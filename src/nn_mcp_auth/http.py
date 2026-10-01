"""Starlette endpoint factory for OAuth 2.0 flows.

Call :func:`build_oauth_endpoints` after building your Starlette app. It
mounts the following routes when ``settings.enabled``:

- ``GET  /authorize``                                  — Authorization Code grant
- ``POST /authorize``                                  — login form submit (password mode only)
- ``GET  /oauth/entra/callback``                       — Microsoft Entra ID return (Entra mode only)

Clients may identify themselves with a Client ID Metadata Document URL
(``client_id=https://chatgpt.com/oauth/client.json``) instead of the
pre-configured ``OAUTH_CLIENT_ID`` when ``settings.cimd_active`` (a person
login is configured and the URL's host is in ``OAUTH_CIMD_ALLOWED_HOSTS``);
see :mod:`nn_mcp_auth.cimd`.
- ``POST /token``                                      — all three grant types
- ``POST /oauth/token``                                — legacy alias for /token
- ``GET  /.well-known/oauth-authorization-server``     — RFC 8414 metadata
- ``GET  /.well-known/openid-configuration``           — alias of the RFC 8414 metadata
- ``GET  /.well-known/oauth-protected-resource``       — RFC 9728 metadata
- ``GET  /.well-known/oauth-protected-resource/{path}``— RFC 9728 path variant

``settings.login_mode`` decides what ``GET /authorize`` does before issuing a
code: ``entra`` (``OAUTH_ENTRA_*`` set) redirects the person to Microsoft
Entra ID and finishes on ``/oauth/entra/callback``; ``password``
(``OAUTH_LOGIN_USERNAME`` + ``OAUTH_LOGIN_PASSWORD``) renders a login page
completed by ``POST /authorize``; ``none`` is byte-for-byte the pre-0.3.0
auto-approve behavior. In both login modes every redirect back to the client
carries ``iss`` (RFC 9207) and the person's identity is bound to the code and
to the access/refresh tokens as ``subject`` (see ``get_subject``).

The RFC 9728 endpoints are required by the MCP authorization spec
(rev 2025-06-18); without them, recent Claude.ai clients loop on 401 →
discovery → 401 and never reach ``/authorize``.

If ``settings.enabled`` is ``False`` the app is returned untouched so an MCP
can be deployed with only the static ``MCP_AUTH_TOKEN`` accepted on /mcp.
"""

from __future__ import annotations

import logging
import secrets
from collections.abc import Awaitable, Callable
from typing import Any
from urllib.parse import urlencode, urlsplit

import jwt
from starlette.applications import Starlette
from starlette.concurrency import run_in_threadpool
from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse, RedirectResponse, Response

from .cimd import (
    CLIENT_ASSERTION_TYPE_JWT_BEARER,
    ClientMetadata,
    ClientMetadataError,
    ClientMetadataResolver,
    is_client_id_url,
)
from .entra import EntraAuthError, EntraVerifier, build_entra_authorize_url
from .jwks import SUPPORTED_JWS_ALGORITHMS
from .login_page import (
    MSG_ENTRA_FAILED,
    MSG_ENTRA_NOT_ALLOWED,
    MSG_INVALID_CREDENTIALS,
    MSG_REQUEST_EXPIRED,
    MSG_TOO_MANY_ATTEMPTS,
    login_page_headers,
    render_login_page,
)
from .oauth import (
    ENTRA_CALLBACK_PATH,
    LOGIN_RATE_LIMIT_MAX_ATTEMPTS,
    OAuthSettings,
    PendingAuthorizationRecord,
    client_id_matches,
    credentials_match,
    parse_basic_auth,
    verify_pkce,
)
from .password import login_credentials_match
from .runtime import log_json
from .storage.base import (
    LoginAttemptLimiter,
    OAuthStores,
    PendingAuthorizationStore,
    ReplayGuardStore,
)
from .storage.memory import (
    MemoryLoginAttemptLimiter,
    MemoryPendingAuthorizationStore,
    MemoryReplayGuard,
)

# Login events are logged here; call ``configure_logging(logger_name="nn_mcp_auth")``
# in the MCP entrypoint to get them as JSON lines.
LOGGER = logging.getLogger("nn_mcp_auth")


def _oauth_error(error_code: str, status_code: int = 400) -> Response:
    return JSONResponse({"error": error_code}, status_code=status_code)


def _issuer(settings: OAuthSettings, request: Request) -> str:
    return settings.issuer_url or f"{request.url.scheme}://{request.url.netloc}"


def _oauth_redirect_error(
    redirect_uri: str, error_code: str, state: str, *, iss: str | None = None
) -> Response:
    params = {"error": error_code}
    if state:
        params["state"] = state
    if iss:
        params["iss"] = iss
    separator = "&" if "?" in redirect_uri else "?"
    return RedirectResponse(f"{redirect_uri}{separator}{urlencode(params)}", status_code=302)


def _code_redirect(redirect_uri: str, code: str, state: str, *, iss: str | None) -> Response:
    query = {"code": code}
    if state:
        query["state"] = state
    if iss:
        query["iss"] = iss
    separator = "&" if "?" in redirect_uri else "?"
    return RedirectResponse(f"{redirect_uri}{separator}{urlencode(query)}", status_code=302)


def _client_host(redirect_uri: str) -> str | None:
    return urlsplit(redirect_uri).hostname or None


def _client_ip(request: Request) -> str:
    # ``request.client`` already honors uvicorn's --proxy-headers /
    # FORWARDED_ALLOW_IPS. Raw X-Forwarded-For is not trusted here because it
    # would let anyone bypass the rate limit by rotating the header.
    return request.client.host if request.client else "unknown"


def _login_response(
    *,
    request: Request,
    status_code: int,
    request_id: str | None,
    redirect_uri: str | None,
    error: str | None = None,
    extra_headers: dict[str, str] | None = None,
) -> Response:
    headers = login_page_headers(redirect_uri)
    if extra_headers:
        headers.update(extra_headers)
    page = render_login_page(
        form_action=request.url.path,
        request_id=request_id,
        client_host=_client_host(redirect_uri) if redirect_uri else None,
        error=error,
    )
    return HTMLResponse(page, status_code=status_code, headers=headers)


def _form_value(form_value: Any) -> str:
    if isinstance(form_value, str):
        return form_value
    return ""


def _issue_token_response(
    stores: OAuthStores,
    *,
    include_refresh: bool,
    subject: str | None = None,
    client_id: str | None = None,
) -> JSONResponse:
    access_token, expires_in = stores.access.issue(subject=subject)
    body: dict[str, Any] = {
        "access_token": access_token,
        "token_type": "Bearer",
        "expires_in": expires_in,
    }
    if include_refresh:
        body["refresh_token"] = stores.refresh.issue(subject=subject, client_id=client_id)
    return JSONResponse(
        body,
        headers={"Cache-Control": "no-store", "Pragma": "no-cache"},
    )


async def _resolve_cimd_client(
    resolver: ClientMetadataResolver | None, client_id: str
) -> ClientMetadata | None:
    """Metadata for a URL ``client_id``, or ``None`` when it must be rejected (logged)."""

    if resolver is None:
        log_json(LOGGER, logging.WARNING, "oauth_cimd_rejected", reason="cimd_inactive")
        return None
    try:
        return await resolver.resolve(client_id)
    except ClientMetadataError as exc:
        log_json(
            LOGGER,
            logging.WARNING,
            "oauth_cimd_rejected",
            client_id=client_id[:200],
            reason=exc.reason,
        )
        return None


def _make_authorize_handler(
    settings: OAuthSettings,
    stores: OAuthStores,
    pending: PendingAuthorizationStore,
    resolver: ClientMetadataResolver | None,
) -> Callable[[Request], Awaitable[Response]]:
    async def handler(request: Request) -> Response:
        if not settings.enabled:
            return _oauth_error("invalid_client", status_code=503)

        params = request.query_params
        response_type = params.get("response_type", "").strip()
        client_id = params.get("client_id", "").strip()
        redirect_uri = params.get("redirect_uri", "").strip()
        code_challenge = params.get("code_challenge", "").strip()
        code_challenge_method = params.get("code_challenge_method", "").strip()
        state = params.get("state", "")

        # Validations whose failure must NOT redirect (RFC 6749 §4.1.2.1):
        # bad client_id / bad redirect_uri are surfaced to the user directly
        # so we never bounce a code/error to an attacker-supplied URI.
        if client_id and is_client_id_url(client_id):
            client_metadata = await _resolve_cimd_client(resolver, client_id)
            if client_metadata is None:
                return _oauth_error("invalid_client", status_code=401)
            if not client_metadata.is_redirect_uri_allowed(redirect_uri):
                return _oauth_error("invalid_request", status_code=400)
        else:
            if not client_id or not client_id_matches(client_id, settings):
                return _oauth_error("invalid_client", status_code=401)
            if not settings.is_redirect_uri_allowed(redirect_uri):
                return _oauth_error("invalid_request", status_code=400)

        # RFC 9207 ``iss`` is only added when the login page is on, so the
        # legacy auto-approve redirects stay exactly as they were.
        iss = _issuer(settings, request) if settings.login_enabled else None

        if response_type != "code":
            return _oauth_redirect_error(
                redirect_uri, "unsupported_response_type", state, iss=iss
            )
        if not code_challenge or code_challenge_method != "S256":
            return _oauth_redirect_error(redirect_uri, "invalid_request", state, iss=iss)

        if settings.entra_enabled:
            # The pending id doubles as the OAuth ``state`` sent to Entra, and
            # the nonce must come back inside the id_token.
            nonce = secrets.token_urlsafe(32)
            request_id = pending.create(
                PendingAuthorizationRecord(
                    client_id=client_id,
                    redirect_uri=redirect_uri,
                    code_challenge=code_challenge,
                    code_challenge_method=code_challenge_method,
                    state=state,
                    nonce=nonce,
                )
            )
            location = build_entra_authorize_url(
                settings,
                redirect_uri=f"{_issuer(settings, request)}{ENTRA_CALLBACK_PATH}",
                state=request_id,
                nonce=nonce,
            )
            response = RedirectResponse(location, status_code=302)
            response.headers["Cache-Control"] = "no-store"
            return response

        if settings.password_login_enabled:
            request_id = pending.create(
                PendingAuthorizationRecord(
                    client_id=client_id,
                    redirect_uri=redirect_uri,
                    code_challenge=code_challenge,
                    code_challenge_method=code_challenge_method,
                    state=state,
                )
            )
            return _login_response(
                request=request,
                status_code=200,
                request_id=request_id,
                redirect_uri=redirect_uri,
            )

        code = stores.code.issue(
            client_id=client_id,
            redirect_uri=redirect_uri,
            code_challenge=code_challenge,
            code_challenge_method=code_challenge_method,
        )
        return _code_redirect(redirect_uri, code, state, iss=None)

    return handler


def _make_login_submit_handler(
    settings: OAuthSettings,
    stores: OAuthStores,
    pending: PendingAuthorizationStore,
    limiter: LoginAttemptLimiter,
) -> Callable[[Request], Awaitable[Response]]:
    """``POST /authorize`` — validate the login form and issue the code."""

    async def handler(request: Request) -> Response:
        client_ip = _client_ip(request)

        try:
            form = await request.form()
        except Exception:
            form = None
        request_id = _form_value(form.get("request_id")).strip() if form else ""
        username = _form_value(form.get("username")) if form else ""
        password = _form_value(form.get("password")) if form else ""

        record = pending.get(request_id) if request_id else None
        redirect_uri = record.redirect_uri if record else None

        # Rate limit before touching the credentials so brute force is capped
        # even when every guess is wrong.
        attempts, retry_after = limiter.hit(client_ip)
        if attempts > LOGIN_RATE_LIMIT_MAX_ATTEMPTS:
            log_json(
                LOGGER,
                logging.WARNING,
                "oauth_login_rate_limited",
                client_ip=client_ip,
                attempts=attempts,
            )
            return _login_response(
                request=request,
                status_code=429,
                request_id=request_id if record else None,
                redirect_uri=redirect_uri,
                error=MSG_TOO_MANY_ATTEMPTS,
                extra_headers={"Retry-After": str(retry_after)},
            )

        if record is None:
            log_json(LOGGER, logging.WARNING, "oauth_login_request_invalid", client_ip=client_ip)
            return _login_response(
                request=request,
                status_code=400,
                request_id=None,
                redirect_uri=None,
                error=MSG_REQUEST_EXPIRED,
            )

        # scrypt is CPU-bound: keep it off the event loop.
        credentials_ok = await run_in_threadpool(
            login_credentials_match,
            username,
            password,
            username=settings.login_username,
            password=settings.login_password,
        )
        if not credentials_ok:
            log_json(LOGGER, logging.WARNING, "oauth_login_failed", client_ip=client_ip)
            return _login_response(
                request=request,
                status_code=401,
                request_id=request_id,
                redirect_uri=redirect_uri,
                error=MSG_INVALID_CREDENTIALS,
            )

        consumed = pending.consume(request_id)
        if consumed is None:
            # Lost a race with a concurrent submission of the same request.
            return _login_response(
                request=request,
                status_code=400,
                request_id=None,
                redirect_uri=None,
                error=MSG_REQUEST_EXPIRED,
            )

        code = stores.code.issue(
            client_id=consumed.client_id,
            redirect_uri=consumed.redirect_uri,
            code_challenge=consumed.code_challenge,
            code_challenge_method=consumed.code_challenge_method,
            subject=settings.login_username,
        )
        log_json(
            LOGGER,
            logging.INFO,
            "oauth_login_succeeded",
            mode="password",
            subject=settings.login_username,
            client_ip=client_ip,
            client_host=_client_host(consumed.redirect_uri),
        )
        response = _code_redirect(
            consumed.redirect_uri,
            code,
            consumed.state,
            iss=_issuer(settings, request),
        )
        response.headers["Cache-Control"] = "no-store"
        return response

    return handler


def _make_entra_callback_handler(
    settings: OAuthSettings,
    stores: OAuthStores,
    pending: PendingAuthorizationStore,
    verifier: EntraVerifier,
) -> Callable[[Request], Awaitable[Response]]:
    """``GET /oauth/entra/callback`` — finish the Microsoft Entra ID login.

    Failures never redirect to the OAuth client: the pending request has
    already been consumed, so the person has to restart from the app, and an
    attacker-supplied ``state`` can never bounce anything anywhere.
    """

    async def handler(request: Request) -> Response:
        client_ip = _client_ip(request)
        params = request.query_params
        state = params.get("state", "").strip()
        code = params.get("code", "").strip()
        entra_error = params.get("error", "").strip()

        record = pending.consume(state) if state else None
        if record is None or not record.nonce:
            log_json(LOGGER, logging.WARNING, "oauth_entra_state_invalid", client_ip=client_ip)
            return _login_response(
                request=request,
                status_code=400,
                request_id=None,
                redirect_uri=None,
                error=MSG_REQUEST_EXPIRED,
            )

        if entra_error or not code:
            log_json(
                LOGGER,
                logging.WARNING,
                "oauth_entra_denied",
                client_ip=client_ip,
                error=entra_error[:64] or "missing_code",
            )
            return _login_response(
                request=request,
                status_code=401,
                request_id=None,
                redirect_uri=None,
                error=MSG_ENTRA_FAILED,
            )

        callback_uri = f"{_issuer(settings, request)}{ENTRA_CALLBACK_PATH}"
        try:
            id_token = await verifier.exchange_code(code, redirect_uri=callback_uri)
            identity = await verifier.verify_id_token(id_token, nonce=record.nonce)
        except EntraAuthError as exc:
            log_json(
                LOGGER,
                logging.WARNING,
                "oauth_entra_failed",
                client_ip=client_ip,
                reason=exc.reason,
            )
            return _login_response(
                request=request,
                status_code=401,
                request_id=None,
                redirect_uri=None,
                error=MSG_ENTRA_FAILED,
            )

        if not settings.is_upn_allowed(identity.upn):
            log_json(
                LOGGER,
                logging.WARNING,
                "oauth_entra_forbidden",
                client_ip=client_ip,
                subject=identity.subject,
            )
            return _login_response(
                request=request,
                status_code=403,
                request_id=None,
                redirect_uri=None,
                error=MSG_ENTRA_NOT_ALLOWED,
            )

        authorization_code = stores.code.issue(
            client_id=record.client_id,
            redirect_uri=record.redirect_uri,
            code_challenge=record.code_challenge,
            code_challenge_method=record.code_challenge_method,
            subject=identity.subject,
        )
        log_json(
            LOGGER,
            logging.INFO,
            "oauth_login_succeeded",
            mode="entra",
            subject=identity.subject,
            client_ip=client_ip,
            client_host=_client_host(record.redirect_uri),
        )
        response = _code_redirect(
            record.redirect_uri,
            authorization_code,
            record.state,
            iss=_issuer(settings, request),
        )
        response.headers["Cache-Control"] = "no-store"
        return response

    return handler


def _unverified_issuer(assertion: str) -> str:
    """``iss`` of a client assertion before verification (RFC 7523 lets ``client_id`` be omitted)."""

    try:
        claims = jwt.decode(assertion, options={"verify_signature": False})
    except jwt.PyJWTError:
        return ""
    iss = claims.get("iss")
    return iss.strip() if isinstance(iss, str) else ""


def _make_token_handler(
    settings: OAuthSettings,
    stores: OAuthStores,
    resolver: ClientMetadataResolver | None,
    replay_guard: ReplayGuardStore,
) -> Callable[[Request], Awaitable[Response]]:
    async def authenticate_cimd_client(
        request: Request, client_id: str, form: Any
    ) -> ClientMetadata | Response:
        """Authenticate a URL client: ``private_key_jwt`` assertion or public ``none``."""

        metadata = await _resolve_cimd_client(resolver, client_id)
        if metadata is None:
            return _oauth_error("invalid_client", status_code=401)
        assertion = _form_value(form.get("client_assertion")).strip()
        assertion_type = _form_value(form.get("client_assertion_type")).strip()
        if assertion:
            if assertion_type != CLIENT_ASSERTION_TYPE_JWT_BEARER or not metadata.allows(
                "private_key_jwt"
            ):
                return _oauth_error("invalid_client", status_code=401)
            issuer = _issuer(settings, request)
            try:
                await resolver.verify_client_assertion(  # type: ignore[union-attr]
                    assertion,
                    metadata,
                    token_endpoint=f"{issuer}/token",
                    issuer=issuer,
                    replay_guard=replay_guard,
                )
            except ClientMetadataError as exc:
                log_json(
                    LOGGER,
                    logging.WARNING,
                    "oauth_cimd_assertion_rejected",
                    client_id=client_id[:200],
                    reason=exc.reason,
                )
                return _oauth_error("invalid_client", status_code=401)
        elif not metadata.allows("none"):
            return _oauth_error("invalid_client", status_code=401)
        return metadata

    async def handler(request: Request) -> Response:
        if not settings.enabled:
            return _oauth_error("invalid_client", status_code=503)

        try:
            form = await request.form()
        except Exception:
            return _oauth_error("invalid_request")

        grant_type = _form_value(form.get("grant_type")).strip()

        basic_credentials = parse_basic_auth(request.headers.get("authorization", ""))
        if basic_credentials is not None:
            provided_id, provided_secret = basic_credentials
        else:
            provided_id = _form_value(form.get("client_id")).strip()
            provided_secret = _form_value(form.get("client_secret"))

        client_assertion = _form_value(form.get("client_assertion")).strip()
        if client_assertion and not provided_id:
            provided_id = _unverified_issuer(client_assertion)
        is_cimd = bool(provided_id) and is_client_id_url(provided_id)

        if grant_type == "authorization_code":
            code = _form_value(form.get("code")).strip()
            redirect_uri = _form_value(form.get("redirect_uri")).strip()
            code_verifier = _form_value(form.get("code_verifier")).strip()

            if is_cimd:
                outcome = await authenticate_cimd_client(request, provided_id, form)
                if isinstance(outcome, Response):
                    return outcome
            elif not client_id_matches(provided_id, settings):
                return _oauth_error("invalid_client", status_code=401)
            if not code or not redirect_uri or not code_verifier:
                return _oauth_error("invalid_request")

            record = stores.code.consume(code)
            if record is None:
                return _oauth_error("invalid_grant")
            if record.client_id != provided_id:
                return _oauth_error("invalid_grant")
            if record.redirect_uri != redirect_uri:
                return _oauth_error("invalid_grant")
            if not verify_pkce(
                code_verifier, record.code_challenge, record.code_challenge_method
            ):
                return _oauth_error("invalid_grant")

            return _issue_token_response(
                stores,
                include_refresh=True,
                subject=record.subject,
                client_id=record.client_id,
            )

        if grant_type == "refresh_token":
            refresh_token = _form_value(form.get("refresh_token")).strip()
            if is_cimd:
                outcome = await authenticate_cimd_client(request, provided_id, form)
                if isinstance(outcome, Response):
                    return outcome
            elif not client_id_matches(provided_id, settings):
                return _oauth_error("invalid_client", status_code=401)
            if not refresh_token:
                return _oauth_error("invalid_request")
            refresh_record = stores.refresh.pop(refresh_token)
            if refresh_record is None:
                return _oauth_error("invalid_grant")
            # Refresh tokens are bound to the client they were issued to. Tokens
            # minted before 0.4.0 carry no client and belong to the static client.
            if refresh_record.client_id is None:
                if is_cimd:
                    return _oauth_error("invalid_grant")
            elif refresh_record.client_id != provided_id:
                return _oauth_error("invalid_grant")
            return _issue_token_response(
                stores,
                include_refresh=True,
                subject=refresh_record.subject,
                client_id=provided_id,
            )

        if grant_type == "client_credentials":
            if is_cimd:
                # Metadata-document clients are user-delegated by construction.
                return _oauth_error("unauthorized_client")
            if not credentials_match(provided_id, provided_secret, settings):
                return _oauth_error("invalid_client", status_code=401)
            return _issue_token_response(stores, include_refresh=False, client_id=provided_id)

        return _oauth_error("unsupported_grant_type")

    return handler


def _make_metadata_handler(
    settings: OAuthSettings,
) -> Callable[[Request], Awaitable[Response]]:
    async def handler(request: Request) -> Response:
        if not settings.enabled:
            return _oauth_error("invalid_client", status_code=503)

        issuer = _issuer(settings, request)
        metadata: dict[str, Any] = {
            "issuer": issuer,
            "authorization_endpoint": f"{issuer}/authorize",
            "token_endpoint": f"{issuer}/token",
            "response_types_supported": ["code"],
            "grant_types_supported": [
                "authorization_code",
                "refresh_token",
                "client_credentials",
            ],
            "token_endpoint_auth_methods_supported": [
                "client_secret_basic",
                "client_secret_post",
            ],
            "code_challenge_methods_supported": ["S256"],
        }
        if settings.login_enabled:
            # RFC 9207 §3: only advertised when every authorization response
            # really carries ``iss`` (true only in login mode).
            metadata["authorization_response_iss_parameter_supported"] = True
        if settings.cimd_active:
            metadata["client_id_metadata_document_supported"] = True
            metadata["token_endpoint_auth_methods_supported"] = [
                "client_secret_basic",
                "client_secret_post",
                "private_key_jwt",
                "none",
            ]
            metadata["token_endpoint_auth_signing_alg_values_supported"] = list(
                SUPPORTED_JWS_ALGORITHMS
            )
        return JSONResponse(metadata)

    return handler


def _make_protected_resource_handler(
    settings: OAuthSettings,
) -> Callable[[Request], Awaitable[Response]]:
    """RFC 9728 — OAuth 2.0 Protected Resource Metadata.

    The MCP authorization spec (rev 2025-06-18) requires resource servers to
    publish this metadata so clients can discover which authorization server
    to use **before** issuing an Authorization Request. Without it, recent
    Claude.ai clients loop on 401 → metadata discovery → 401 and never reach
    ``/authorize``.

    We expose the same payload at both ``/.well-known/oauth-protected-resource``
    and the path-suffixed variant (e.g. ``/.well-known/oauth-protected-resource/mcp``)
    because clients probe both before falling back.
    """

    async def handler(request: Request) -> Response:
        if not settings.enabled:
            return _oauth_error("invalid_client", status_code=503)

        issuer = _issuer(settings, request)
        return JSONResponse(
            {
                "resource": issuer,
                "authorization_servers": [issuer],
                "bearer_methods_supported": ["header"],
                "scopes_supported": [],
            }
        )

    return handler


def build_oauth_endpoints(
    app: Starlette,
    *,
    settings: OAuthSettings,
    stores: OAuthStores,
    client_metadata_resolver: ClientMetadataResolver | None = None,
) -> Starlette:
    """Mount the OAuth routes on ``app``. Returns the same app for chaining.

    ``client_metadata_resolver`` lets callers (and tests) inject the Client ID
    Metadata Document resolver; by default one is built from
    ``settings.cimd_allowed_hosts`` when ``settings.cimd_active``.
    """

    if not settings.enabled:
        return app

    resolver: ClientMetadataResolver | None = None
    if settings.cimd_active:
        resolver = client_metadata_resolver or ClientMetadataResolver(
            allowed_hosts=settings.cimd_allowed_hosts
        )
    replay_guard = stores.replay_guard if stores.replay_guard is not None else MemoryReplayGuard()

    # Hand-built ``OAuthStores`` may predate the login stores; fall back to
    # in-process versions (fine for a single replica, Redis is preferred).
    pending = stores.pending if stores.pending is not None else MemoryPendingAuthorizationStore()
    limiter = (
        stores.login_limiter
        if stores.login_limiter is not None
        else MemoryLoginAttemptLimiter()
    )

    authorize_handler = _make_authorize_handler(settings, stores, pending, resolver)
    token_handler = _make_token_handler(settings, stores, resolver, replay_guard)
    metadata_handler = _make_metadata_handler(settings)
    protected_resource_handler = _make_protected_resource_handler(settings)

    app.add_route("/authorize", authorize_handler, methods=["GET"])
    if settings.entra_enabled:
        app.add_route(
            ENTRA_CALLBACK_PATH,
            _make_entra_callback_handler(settings, stores, pending, EntraVerifier(settings)),
            methods=["GET"],
        )
    elif settings.password_login_enabled:
        app.add_route(
            "/authorize",
            _make_login_submit_handler(settings, stores, pending, limiter),
            methods=["POST"],
        )
    app.add_route("/token", token_handler, methods=["POST"])
    # Legacy alias kept for callers configured against the original PR.
    app.add_route("/oauth/token", token_handler, methods=["POST"])
    app.add_route(
        "/.well-known/oauth-authorization-server",
        metadata_handler,
        methods=["GET"],
    )
    # Some clients (ChatGPT connectors among them) probe the OIDC discovery
    # path before RFC 8414; serve the same document there.
    app.add_route(
        "/.well-known/openid-configuration",
        metadata_handler,
        methods=["GET"],
    )
    # RFC 9728 — exposed at the well-known root AND at the path-suffixed
    # variant the MCP authorization spec asks clients to probe.
    app.add_route(
        "/.well-known/oauth-protected-resource",
        protected_resource_handler,
        methods=["GET"],
    )
    app.add_route(
        "/.well-known/oauth-protected-resource/{path:path}",
        protected_resource_handler,
        methods=["GET"],
    )

    return app
