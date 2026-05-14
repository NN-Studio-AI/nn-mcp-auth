"""OAuth 2.0 helpers — settings, dataclasses, PKCE, credential comparison.

Token persistence lives in :mod:`nn_mcp_auth.storage`; this module only owns
the cryptographic + parsing primitives and the configuration object that the
endpoint factory consumes.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import os
import secrets
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Final

from .errors import ConfigurationError

OAUTH_CLIENT_ID_ENV_VAR: Final[str] = "OAUTH_CLIENT_ID"
OAUTH_CLIENT_SECRET_ENV_VAR: Final[str] = "OAUTH_CLIENT_SECRET"
OAUTH_TOKEN_TTL_ENV_VAR: Final[str] = "OAUTH_TOKEN_TTL_SECONDS"
OAUTH_ALLOWED_REDIRECT_URIS_ENV_VAR: Final[str] = "OAUTH_ALLOWED_REDIRECT_URIS"
OAUTH_ISSUER_URL_ENV_VAR: Final[str] = "OAUTH_ISSUER_URL"

DEFAULT_OAUTH_TOKEN_TTL_SECONDS: Final[int] = 3600
MIN_OAUTH_TOKEN_TTL_SECONDS: Final[int] = 60
MAX_OAUTH_TOKEN_TTL_SECONDS: Final[int] = 86_400

AUTHORIZATION_CODE_TTL_SECONDS: Final[int] = 600
REFRESH_TOKEN_TTL_SECONDS: Final[int] = 60 * 60 * 24 * 90  # 90 days

DEFAULT_ALLOWED_REDIRECT_URIS: Final[tuple[str, ...]] = (
    "https://claude.ai/api/mcp/auth_callback",
    "https://claude.com/api/mcp/auth_callback",
)


@dataclass(frozen=True, slots=True)
class OAuthSettings:
    client_id: str
    client_secret: str
    token_ttl_seconds: int = DEFAULT_OAUTH_TOKEN_TTL_SECONDS
    allowed_redirect_uris: tuple[str, ...] = DEFAULT_ALLOWED_REDIRECT_URIS
    issuer_url: str = ""

    @property
    def enabled(self) -> bool:
        return bool(self.client_id) and bool(self.client_secret)

    def is_redirect_uri_allowed(self, redirect_uri: str) -> bool:
        if not redirect_uri:
            return False
        return redirect_uri in self.allowed_redirect_uris


@dataclass(frozen=True, slots=True)
class AuthorizationCodeRecord:
    """Code metadata carried between /authorize and /token.

    Expiration is enforced at the storage layer (in-memory clock or Redis
    TTL), so the record itself does not carry an expiry field.
    """

    client_id: str
    redirect_uri: str
    code_challenge: str
    code_challenge_method: str


def verify_pkce(code_verifier: str, code_challenge: str, method: str) -> bool:
    """RFC 7636 §4.6 — only ``S256`` is supported (``plain`` is rejected)."""

    if method != "S256":
        return False
    if not code_verifier or not code_challenge:
        return False
    if len(code_verifier) < 43 or len(code_verifier) > 128:
        return False
    digest = hashlib.sha256(code_verifier.encode("ascii")).digest()
    computed = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
    return secrets.compare_digest(computed, code_challenge)


def load_oauth_settings(env: Mapping[str, str] | None = None) -> OAuthSettings:
    """Build :class:`OAuthSettings` from environment variables.

    When both ``OAUTH_CLIENT_ID`` and ``OAUTH_CLIENT_SECRET`` are empty,
    the returned settings have ``enabled == False`` and the endpoint
    factory mounts no routes.
    """

    if env is None:
        env = os.environ

    client_id = env.get(OAUTH_CLIENT_ID_ENV_VAR, "").strip()
    client_secret = env.get(OAUTH_CLIENT_SECRET_ENV_VAR, "").strip()

    if bool(client_id) != bool(client_secret):
        missing = (
            OAUTH_CLIENT_ID_ENV_VAR if not client_id else OAUTH_CLIENT_SECRET_ENV_VAR
        )
        raise ConfigurationError(
            "OAuth client credentials are partially configured. Both "
            "OAUTH_CLIENT_ID and OAUTH_CLIENT_SECRET must be set together, "
            "or both left empty to disable OAuth.",
            details={"missing_env_var": missing},
        )

    ttl_raw = env.get(OAUTH_TOKEN_TTL_ENV_VAR, "").strip()
    if not ttl_raw:
        ttl_seconds = DEFAULT_OAUTH_TOKEN_TTL_SECONDS
    else:
        try:
            ttl_seconds = int(ttl_raw)
        except ValueError as exc:
            raise ConfigurationError(
                f"{OAUTH_TOKEN_TTL_ENV_VAR} must be an integer number of seconds",
                details={OAUTH_TOKEN_TTL_ENV_VAR: ttl_raw},
            ) from exc

    if not MIN_OAUTH_TOKEN_TTL_SECONDS <= ttl_seconds <= MAX_OAUTH_TOKEN_TTL_SECONDS:
        raise ConfigurationError(
            f"{OAUTH_TOKEN_TTL_ENV_VAR} must be between "
            f"{MIN_OAUTH_TOKEN_TTL_SECONDS} and {MAX_OAUTH_TOKEN_TTL_SECONDS} seconds",
            details={OAUTH_TOKEN_TTL_ENV_VAR: str(ttl_seconds)},
        )

    redirect_raw = env.get(OAUTH_ALLOWED_REDIRECT_URIS_ENV_VAR, "").strip()
    if not redirect_raw:
        allowed_redirect_uris = DEFAULT_ALLOWED_REDIRECT_URIS
    else:
        parsed = tuple(
            uri.strip() for uri in redirect_raw.split(",") if uri.strip()
        )
        if not parsed:
            raise ConfigurationError(
                f"{OAUTH_ALLOWED_REDIRECT_URIS_ENV_VAR} must be a non-empty "
                "comma-separated list of absolute URIs, or unset to use defaults.",
                details={OAUTH_ALLOWED_REDIRECT_URIS_ENV_VAR: redirect_raw},
            )
        allowed_redirect_uris = parsed

    issuer_url = env.get(OAUTH_ISSUER_URL_ENV_VAR, "").strip().rstrip("/")

    return OAuthSettings(
        client_id=client_id,
        client_secret=client_secret,
        token_ttl_seconds=ttl_seconds,
        allowed_redirect_uris=allowed_redirect_uris,
        issuer_url=issuer_url,
    )


def parse_basic_auth(authorization_header: str) -> tuple[str, str] | None:
    if not authorization_header.lower().startswith("basic "):
        return None
    encoded = authorization_header[6:].strip()
    if not encoded:
        return None
    try:
        decoded = base64.b64decode(encoded, validate=True).decode("utf-8")
    except (binascii.Error, UnicodeDecodeError):
        return None
    user, separator, password = decoded.partition(":")
    if not separator:
        return None
    return user, password


def credentials_match(
    provided_id: str,
    provided_secret: str,
    settings: OAuthSettings,
) -> bool:
    if not settings.enabled:
        return False
    return secrets.compare_digest(
        provided_id, settings.client_id
    ) and secrets.compare_digest(provided_secret, settings.client_secret)


def client_id_matches(provided_id: str, settings: OAuthSettings) -> bool:
    if not settings.enabled:
        return False
    return secrets.compare_digest(provided_id, settings.client_id)
