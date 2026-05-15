"""Starlette endpoint factory for OAuth 2.0 flows.

Call :func:`build_oauth_endpoints` after building your Starlette app. It
mounts the following routes when ``settings.enabled``:

- ``GET  /authorize``                                  — Authorization Code grant
- ``POST /token``                                      — all three grant types
- ``POST /oauth/token``                                — legacy alias for /token
- ``GET  /.well-known/oauth-authorization-server``     — RFC 8414 metadata
- ``GET  /.well-known/oauth-protected-resource``       — RFC 9728 metadata
- ``GET  /.well-known/oauth-protected-resource/{path}``— RFC 9728 path variant

The RFC 9728 endpoints are required by the MCP authorization spec
(rev 2025-06-18); without them, recent Claude.ai clients loop on 401 →
discovery → 401 and never reach ``/authorize``.

If ``settings.enabled`` is ``False`` the app is returned untouched so an MCP
can be deployed with only the static ``MCP_AUTH_TOKEN`` accepted on /mcp.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import Any
from urllib.parse import urlencode

from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse, RedirectResponse, Response

from .oauth import (
    OAuthSettings,
    client_id_matches,
    credentials_match,
    parse_basic_auth,
    verify_pkce,
)
from .storage.base import OAuthStores


def _oauth_error(error_code: str, status_code: int = 400) -> Response:
    return JSONResponse({"error": error_code}, status_code=status_code)


def _oauth_redirect_error(redirect_uri: str, error_code: str, state: str) -> Response:
    params = {"error": error_code}
    if state:
        params["state"] = state
    separator = "&" if "?" in redirect_uri else "?"
    return RedirectResponse(f"{redirect_uri}{separator}{urlencode(params)}", status_code=302)


def _form_value(form_value: Any) -> str:
    if isinstance(form_value, str):
        return form_value
    return ""


def _issue_token_response(
    stores: OAuthStores,
    *,
    include_refresh: bool,
) -> JSONResponse:
    access_token, expires_in = stores.access.issue()
    body: dict[str, Any] = {
        "access_token": access_token,
        "token_type": "Bearer",
        "expires_in": expires_in,
    }
    if include_refresh:
        body["refresh_token"] = stores.refresh.issue()
    return JSONResponse(
        body,
        headers={"Cache-Control": "no-store", "Pragma": "no-cache"},
    )


def _make_authorize_handler(
    settings: OAuthSettings, stores: OAuthStores
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
        if not client_id or not client_id_matches(client_id, settings):
            return _oauth_error("invalid_client", status_code=401)
        if not settings.is_redirect_uri_allowed(redirect_uri):
            return _oauth_error("invalid_request", status_code=400)

        if response_type != "code":
            return _oauth_redirect_error(redirect_uri, "unsupported_response_type", state)
        if not code_challenge or code_challenge_method != "S256":
            return _oauth_redirect_error(redirect_uri, "invalid_request", state)

        code = stores.code.issue(
            client_id=client_id,
            redirect_uri=redirect_uri,
            code_challenge=code_challenge,
            code_challenge_method=code_challenge_method,
        )

        query = {"code": code}
        if state:
            query["state"] = state
        separator = "&" if "?" in redirect_uri else "?"
        return RedirectResponse(
            f"{redirect_uri}{separator}{urlencode(query)}",
            status_code=302,
        )

    return handler


def _make_token_handler(
    settings: OAuthSettings, stores: OAuthStores
) -> Callable[[Request], Awaitable[Response]]:
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

        if grant_type == "authorization_code":
            code = _form_value(form.get("code")).strip()
            redirect_uri = _form_value(form.get("redirect_uri")).strip()
            code_verifier = _form_value(form.get("code_verifier")).strip()

            if not client_id_matches(provided_id, settings):
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

            return _issue_token_response(stores, include_refresh=True)

        if grant_type == "refresh_token":
            refresh_token = _form_value(form.get("refresh_token")).strip()
            if not client_id_matches(provided_id, settings):
                return _oauth_error("invalid_client", status_code=401)
            if not refresh_token:
                return _oauth_error("invalid_request")
            if not stores.refresh.consume(refresh_token):
                return _oauth_error("invalid_grant")
            return _issue_token_response(stores, include_refresh=True)

        if grant_type == "client_credentials":
            if not credentials_match(provided_id, provided_secret, settings):
                return _oauth_error("invalid_client", status_code=401)
            return _issue_token_response(stores, include_refresh=False)

        return _oauth_error("unsupported_grant_type")

    return handler


def _make_metadata_handler(
    settings: OAuthSettings,
) -> Callable[[Request], Awaitable[Response]]:
    async def handler(request: Request) -> Response:
        if not settings.enabled:
            return _oauth_error("invalid_client", status_code=503)

        issuer = settings.issuer_url or f"{request.url.scheme}://{request.url.netloc}"
        return JSONResponse(
            {
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
        )

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

        issuer = settings.issuer_url or f"{request.url.scheme}://{request.url.netloc}"
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
) -> Starlette:
    """Mount the OAuth routes on ``app``. Returns the same app for chaining."""

    if not settings.enabled:
        return app

    authorize_handler = _make_authorize_handler(settings, stores)
    token_handler = _make_token_handler(settings, stores)
    metadata_handler = _make_metadata_handler(settings)
    protected_resource_handler = _make_protected_resource_handler(settings)

    app.add_route("/authorize", authorize_handler, methods=["GET"])
    app.add_route("/token", token_handler, methods=["POST"])
    # Legacy alias kept for callers configured against the original PR.
    app.add_route("/oauth/token", token_handler, methods=["POST"])
    app.add_route(
        "/.well-known/oauth-authorization-server",
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
