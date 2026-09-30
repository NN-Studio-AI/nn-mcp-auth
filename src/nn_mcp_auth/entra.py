"""Microsoft Entra ID federation for the ``/authorize`` login.

The library stays the OAuth authorization server of the MCP clients
(claude.ai, ChatGPT, ...): it keeps issuing its own codes and tokens. Entra
only authenticates the *person*. Flow:

1. ``GET /authorize`` stores the pending request (with a fresh ``nonce``) and
   redirects the browser to the tenant's ``/oauth2/v2.0/authorize``.
2. Entra redirects back to ``{issuer}/oauth/entra/callback?code&state``.
3. The callback exchanges the code server-side (client secret never leaves
   the server), validates the ``id_token`` (RS256 signature against the
   tenant JWKS, ``iss``, ``aud``, ``exp``, ``nonce``, ``tid``) and, if the
   account passes the allowlist, issues the MCP authorization code bound to
   the person's UPN as ``subject``.

Browser SSO applies: no ``prompt`` parameter is sent, so a person already
signed in to Microsoft in that browser is redirected straight back.
"""

from __future__ import annotations

import logging
import secrets
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, Final
from urllib.parse import urlencode

import httpx
import jwt
from jwt import PyJWK

from .errors import NnMcpAuthError
from .oauth import OAuthSettings
from .runtime import log_json

LOGGER = logging.getLogger("nn_mcp_auth")

ENTRA_AUTHORITY: Final[str] = "https://login.microsoftonline.com"
ENTRA_SCOPES: Final[str] = "openid profile email"
ENTRA_HTTP_TIMEOUT_SECONDS: Final[float] = 10.0
ENTRA_ID_TOKEN_ALGORITHMS: Final[tuple[str, ...]] = ("RS256",)
ENTRA_CLOCK_SKEW_SECONDS: Final[int] = 60
JWKS_CACHE_TTL_SECONDS: Final[int] = 3600
# A key id we do not know may mean Entra rotated its keys; refetch, but never
# more often than this so a flood of bogus ``kid`` values cannot hammer Entra.
JWKS_REFETCH_MIN_INTERVAL_SECONDS: Final[int] = 30


class EntraAuthError(NnMcpAuthError):
    """The Entra round-trip or the id_token validation failed.

    ``reason`` is a short machine-readable tag safe for logs; it never
    contains tokens, codes or claims.
    """

    def __init__(self, reason: str) -> None:
        super().__init__(f"Microsoft Entra ID login failed: {reason}")
        self.reason = reason


@dataclass(frozen=True, slots=True)
class EntraIdentity:
    """Claims we keep from a validated id_token."""

    oid: str
    tenant_id: str
    upn: str | None
    name: str | None

    @property
    def subject(self) -> str:
        """Stable, human-readable identity: the UPN, falling back to the object id."""

        return (self.upn or self.oid).lower()


def entra_authorize_endpoint(tenant_id: str) -> str:
    return f"{ENTRA_AUTHORITY}/{tenant_id}/oauth2/v2.0/authorize"


def entra_token_endpoint(tenant_id: str) -> str:
    return f"{ENTRA_AUTHORITY}/{tenant_id}/oauth2/v2.0/token"


def entra_jwks_uri(tenant_id: str) -> str:
    return f"{ENTRA_AUTHORITY}/{tenant_id}/discovery/v2.0/keys"


def entra_issuer(tenant_id: str) -> str:
    return f"{ENTRA_AUTHORITY}/{tenant_id}/v2.0"


def build_entra_authorize_url(
    settings: OAuthSettings,
    *,
    redirect_uri: str,
    state: str,
    nonce: str,
) -> str:
    """Authorization Code request to Entra (no ``prompt``, so browser SSO can apply)."""

    params = {
        "client_id": settings.entra_client_id,
        "response_type": "code",
        "response_mode": "query",
        "redirect_uri": redirect_uri,
        "scope": ENTRA_SCOPES,
        "state": state,
        "nonce": nonce,
    }
    return f"{entra_authorize_endpoint(settings.entra_tenant_id)}?{urlencode(params)}"


class EntraVerifier:
    """Exchanges the Entra code and validates the id_token for one tenant/app."""

    def __init__(
        self,
        settings: OAuthSettings,
        *,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._tenant_id = settings.entra_tenant_id
        self._client_id = settings.entra_client_id
        self._client_secret = settings.entra_client_secret
        self._issuer = entra_issuer(self._tenant_id)
        self._token_endpoint = entra_token_endpoint(self._tenant_id)
        self._jwks_uri = entra_jwks_uri(self._tenant_id)
        self._clock = clock
        self._keys: dict[str, Any] = {}
        self._fetched_at: float | None = None

    async def exchange_code(self, code: str, *, redirect_uri: str) -> str:
        """Redeem the Entra authorization code; returns the raw ``id_token``."""

        data = {
            "client_id": self._client_id,
            "client_secret": self._client_secret,
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": redirect_uri,
            "scope": ENTRA_SCOPES,
        }
        try:
            async with httpx.AsyncClient(timeout=ENTRA_HTTP_TIMEOUT_SECONDS) as client:
                response = await client.post(
                    self._token_endpoint, data=data, headers={"Accept": "application/json"}
                )
        except httpx.HTTPError as exc:
            raise EntraAuthError("token_endpoint_unreachable") from exc

        if response.status_code != 200:
            error_code = _error_code(response)
            log_json(
                LOGGER,
                logging.WARNING,
                "oauth_entra_token_rejected",
                status_code=response.status_code,
                error=error_code,
            )
            raise EntraAuthError("token_exchange_rejected")

        try:
            payload = response.json()
        except ValueError as exc:
            raise EntraAuthError("token_response_invalid") from exc
        id_token = payload.get("id_token") if isinstance(payload, dict) else None
        if not isinstance(id_token, str) or not id_token:
            raise EntraAuthError("id_token_missing")
        return id_token

    async def verify_id_token(self, id_token: str, *, nonce: str) -> EntraIdentity:
        """Validate signature, issuer, audience, lifetime, nonce and tenant."""

        try:
            header = jwt.get_unverified_header(id_token)
        except jwt.PyJWTError as exc:
            raise EntraAuthError("id_token_malformed") from exc
        kid = header.get("kid")
        if not isinstance(kid, str) or not kid:
            raise EntraAuthError("id_token_kid_missing")

        key = await self._signing_key(kid)
        try:
            claims = jwt.decode(
                id_token,
                key=key,
                algorithms=list(ENTRA_ID_TOKEN_ALGORITHMS),
                audience=self._client_id,
                issuer=self._issuer,
                leeway=ENTRA_CLOCK_SKEW_SECONDS,
                options={"require": ["exp", "iat", "aud", "iss", "sub"]},
            )
        except jwt.PyJWTError as exc:
            raise EntraAuthError(f"id_token_invalid:{type(exc).__name__}") from exc

        token_nonce = claims.get("nonce")
        if (
            not nonce
            or not isinstance(token_nonce, str)
            or not secrets.compare_digest(token_nonce, nonce)
        ):
            raise EntraAuthError("nonce_mismatch")

        tid = claims.get("tid")
        if not isinstance(tid, str) or tid.lower() != self._tenant_id:
            raise EntraAuthError("tenant_mismatch")

        oid = claims.get("oid") or claims.get("sub")
        if not isinstance(oid, str) or not oid:
            raise EntraAuthError("subject_missing")
        upn = claims.get("preferred_username") or claims.get("email") or claims.get("upn")
        name = claims.get("name")
        return EntraIdentity(
            oid=oid,
            tenant_id=tid.lower(),
            upn=upn.strip().lower() if isinstance(upn, str) and upn.strip() else None,
            name=name if isinstance(name, str) and name else None,
        )

    async def _signing_key(self, kid: str) -> Any:
        now = self._clock()
        never_fetched = self._fetched_at is None
        stale = never_fetched or now - float(self._fetched_at or 0.0) > JWKS_CACHE_TTL_SECONDS
        can_refetch = (
            never_fetched
            or now - float(self._fetched_at or 0.0) >= JWKS_REFETCH_MIN_INTERVAL_SECONDS
        )
        if (stale or kid not in self._keys) and can_refetch:
            await self._fetch_jwks()
        key = self._keys.get(kid)
        if key is None:
            raise EntraAuthError("signing_key_unknown")
        return key

    async def _fetch_jwks(self) -> None:
        try:
            async with httpx.AsyncClient(timeout=ENTRA_HTTP_TIMEOUT_SECONDS) as client:
                response = await client.get(self._jwks_uri)
            if response.status_code != 200:
                raise EntraAuthError("jwks_unavailable")
            data = response.json()
        except (httpx.HTTPError, ValueError) as exc:
            if self._keys:
                # Keep serving the cached keys: Entra rotates rarely and a
                # transient outage must not lock every login out.
                log_json(LOGGER, logging.WARNING, "oauth_entra_jwks_refresh_failed")
                self._fetched_at = self._clock()
                return
            raise EntraAuthError("jwks_unreachable") from exc
        except EntraAuthError:
            if self._keys:
                log_json(LOGGER, logging.WARNING, "oauth_entra_jwks_refresh_failed")
                self._fetched_at = self._clock()
                return
            raise

        keys: dict[str, Any] = {}
        raw_keys = data.get("keys") if isinstance(data, dict) else None
        for jwk_data in raw_keys if isinstance(raw_keys, list) else []:
            if not isinstance(jwk_data, dict) or jwk_data.get("kty") != "RSA":
                continue
            key_id = jwk_data.get("kid")
            if not isinstance(key_id, str) or not key_id:
                continue
            try:
                keys[key_id] = PyJWK.from_dict(jwk_data, algorithm="RS256").key
            except jwt.PyJWTError:
                continue
        if not keys:
            if self._keys:
                log_json(LOGGER, logging.WARNING, "oauth_entra_jwks_refresh_failed")
                self._fetched_at = self._clock()
                return
            raise EntraAuthError("jwks_empty")
        self._keys = keys
        self._fetched_at = self._clock()


def _error_code(response: httpx.Response) -> str | None:
    """Entra's short ``error`` code (e.g. ``invalid_grant``), never the description."""

    try:
        body = response.json()
    except ValueError:
        return None
    code = body.get("error") if isinstance(body, dict) else None
    return code[:64] if isinstance(code, str) else None
