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
import re
import secrets
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Final, Literal

from .errors import ConfigurationError
from .password import is_scrypt_hash, parse_scrypt_hash

OAUTH_CLIENT_ID_ENV_VAR: Final[str] = "OAUTH_CLIENT_ID"
OAUTH_CLIENT_SECRET_ENV_VAR: Final[str] = "OAUTH_CLIENT_SECRET"
OAUTH_TOKEN_TTL_ENV_VAR: Final[str] = "OAUTH_TOKEN_TTL_SECONDS"
OAUTH_ALLOWED_REDIRECT_URIS_ENV_VAR: Final[str] = "OAUTH_ALLOWED_REDIRECT_URIS"
OAUTH_ISSUER_URL_ENV_VAR: Final[str] = "OAUTH_ISSUER_URL"
OAUTH_LOGIN_USERNAME_ENV_VAR: Final[str] = "OAUTH_LOGIN_USERNAME"
OAUTH_LOGIN_PASSWORD_ENV_VAR: Final[str] = "OAUTH_LOGIN_PASSWORD"
OAUTH_ENTRA_TENANT_ID_ENV_VAR: Final[str] = "OAUTH_ENTRA_TENANT_ID"
OAUTH_ENTRA_CLIENT_ID_ENV_VAR: Final[str] = "OAUTH_ENTRA_CLIENT_ID"
OAUTH_ENTRA_CLIENT_SECRET_ENV_VAR: Final[str] = "OAUTH_ENTRA_CLIENT_SECRET"
OAUTH_ENTRA_ALLOWED_UPNS_ENV_VAR: Final[str] = "OAUTH_ENTRA_ALLOWED_UPNS"

# Path (relative to the issuer) that Microsoft Entra ID redirects back to.
# Register ``{OAUTH_ISSUER_URL}/oauth/entra/callback`` on the app registration.
ENTRA_CALLBACK_PATH: Final[str] = "/oauth/entra/callback"

LoginMode = Literal["entra", "password", "none"]

_GUID_RE: Final[re.Pattern[str]] = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
)

DEFAULT_OAUTH_TOKEN_TTL_SECONDS: Final[int] = 3600
MIN_OAUTH_TOKEN_TTL_SECONDS: Final[int] = 60
MAX_OAUTH_TOKEN_TTL_SECONDS: Final[int] = 86_400

AUTHORIZATION_CODE_TTL_SECONDS: Final[int] = 600
REFRESH_TOKEN_TTL_SECONDS: Final[int] = 60 * 60 * 24 * 90  # 90 days
PENDING_AUTHORIZATION_TTL_SECONDS: Final[int] = 600
LOGIN_RATE_LIMIT_MAX_ATTEMPTS: Final[int] = 10
LOGIN_RATE_LIMIT_WINDOW_SECONDS: Final[int] = 600

DEFAULT_ALLOWED_REDIRECT_URIS: Final[tuple[str, ...]] = (
    "https://claude.ai/api/mcp/auth_callback",
    "https://claude.com/api/mcp/auth_callback",
    "https://chatgpt.com/connector_platform_oauth_redirect",
    "https://chat.openai.com/connector_platform_oauth_redirect",
)


@dataclass(frozen=True, slots=True)
class OAuthSettings:
    client_id: str
    client_secret: str
    token_ttl_seconds: int = DEFAULT_OAUTH_TOKEN_TTL_SECONDS
    allowed_redirect_uris: tuple[str, ...] = DEFAULT_ALLOWED_REDIRECT_URIS
    issuer_url: str = ""
    login_username: str = ""
    # Plain text or ``scrypt$<salt_b64>$<hash_b64>``; never shown in repr.
    login_password: str = field(default="", repr=False)
    # Microsoft Entra ID federation (takes precedence over the password login).
    entra_tenant_id: str = ""
    entra_client_id: str = ""
    entra_client_secret: str = field(default="", repr=False)
    # Lower-cased UPNs/e-mails allowed to log in; empty = any user of the tenant.
    entra_allowed_upns: tuple[str, ...] = ()

    @property
    def enabled(self) -> bool:
        return bool(self.client_id) and bool(self.client_secret)

    @property
    def entra_enabled(self) -> bool:
        """``True`` when ``/authorize`` sends the person to Microsoft Entra ID."""

        return (
            bool(self.entra_tenant_id)
            and bool(self.entra_client_id)
            and bool(self.entra_client_secret)
        )

    @property
    def password_login_enabled(self) -> bool:
        """``True`` when the fixed username/password credentials are configured."""

        return bool(self.login_username) and bool(self.login_password)

    @property
    def login_enabled(self) -> bool:
        """``True`` when ``/authorize`` must authenticate a person before issuing a code."""

        return self.entra_enabled or self.password_login_enabled

    @property
    def login_mode(self) -> LoginMode:
        """Which authentication ``/authorize`` performs: ``entra`` > ``password`` > ``none``."""

        if self.entra_enabled:
            return "entra"
        if self.password_login_enabled:
            return "password"
        return "none"

    def is_redirect_uri_allowed(self, redirect_uri: str) -> bool:
        if not redirect_uri:
            return False
        return redirect_uri in self.allowed_redirect_uris

    def is_upn_allowed(self, *candidates: str | None) -> bool:
        """Check the Entra allowlist; with no allowlist every tenant user passes."""

        if not self.entra_allowed_upns:
            return True
        allowed = set(self.entra_allowed_upns)
        return any(
            candidate.strip().lower() in allowed
            for candidate in candidates
            if isinstance(candidate, str) and candidate.strip()
        )


@dataclass(frozen=True, slots=True)
class PendingAuthorizationRecord:
    """A validated ``GET /authorize`` request waiting for the person to log in.

    Persisted between the redirect to the login (form or Entra) and its
    completion; single-use and short-lived (``PENDING_AUTHORIZATION_TTL_SECONDS``).
    ``nonce`` is only set in Entra mode and must echo back inside the id_token.
    """

    client_id: str
    redirect_uri: str
    code_challenge: str
    code_challenge_method: str
    state: str = ""
    nonce: str = ""


@dataclass(frozen=True, slots=True)
class AuthorizationCodeRecord:
    """Code metadata carried between /authorize and /token.

    Expiration is enforced at the storage layer (in-memory clock or Redis
    TTL), so the record itself does not carry an expiry field. ``subject`` is
    the identity of the person who logged in (UPN in Entra mode, the username
    in password mode) and travels to the access/refresh tokens.
    """

    client_id: str
    redirect_uri: str
    code_challenge: str
    code_challenge_method: str
    subject: str | None = None


@dataclass(frozen=True, slots=True)
class RefreshTokenRecord:
    """What a consumed refresh token carried: the subject to re-attach to the new tokens."""

    subject: str | None = None


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

    login_username, login_password = _load_login_credentials(env)
    entra_tenant_id, entra_client_id, entra_client_secret, entra_allowed_upns = (
        _load_entra_settings(env)
    )

    return OAuthSettings(
        client_id=client_id,
        client_secret=client_secret,
        token_ttl_seconds=ttl_seconds,
        allowed_redirect_uris=allowed_redirect_uris,
        issuer_url=issuer_url,
        login_username=login_username,
        login_password=login_password,
        entra_tenant_id=entra_tenant_id,
        entra_client_id=entra_client_id,
        entra_client_secret=entra_client_secret,
        entra_allowed_upns=entra_allowed_upns,
    )


def _load_entra_settings(env: Mapping[str, str]) -> tuple[str, str, str, tuple[str, ...]]:
    """Read the optional Microsoft Entra ID login configuration.

    All three of ``OAUTH_ENTRA_TENANT_ID``, ``OAUTH_ENTRA_CLIENT_ID`` and
    ``OAUTH_ENTRA_CLIENT_SECRET`` empty → Entra mode off. Only some set →
    :class:`ConfigurationError`. The tenant must be the directory GUID because
    the ``iss``/``tid`` claims of the id_token are compared against it.
    """

    tenant_id = env.get(OAUTH_ENTRA_TENANT_ID_ENV_VAR, "").strip().lower()
    client_id = env.get(OAUTH_ENTRA_CLIENT_ID_ENV_VAR, "").strip()
    client_secret = env.get(OAUTH_ENTRA_CLIENT_SECRET_ENV_VAR, "").strip()

    required = (
        (OAUTH_ENTRA_TENANT_ID_ENV_VAR, tenant_id),
        (OAUTH_ENTRA_CLIENT_ID_ENV_VAR, client_id),
        (OAUTH_ENTRA_CLIENT_SECRET_ENV_VAR, client_secret),
    )
    missing = [name for name, value in required if not value]
    if missing and len(missing) != len(required):
        raise ConfigurationError(
            "Microsoft Entra ID login is partially configured. "
            "OAUTH_ENTRA_TENANT_ID, OAUTH_ENTRA_CLIENT_ID and OAUTH_ENTRA_CLIENT_SECRET "
            "must be set together, or all left empty to disable the Entra login.",
            details={"missing_env_vars": missing},
        )

    if tenant_id and not _GUID_RE.match(tenant_id):
        raise ConfigurationError(
            f"{OAUTH_ENTRA_TENANT_ID_ENV_VAR} must be the tenant GUID (Directory ID), "
            "not a domain name.",
            details={OAUTH_ENTRA_TENANT_ID_ENV_VAR: tenant_id},
        )

    allowed_raw = env.get(OAUTH_ENTRA_ALLOWED_UPNS_ENV_VAR, "").strip()
    allowed_upns = tuple(
        dict.fromkeys(item.strip().lower() for item in allowed_raw.split(",") if item.strip())
    )
    if allowed_raw and not allowed_upns:
        raise ConfigurationError(
            f"{OAUTH_ENTRA_ALLOWED_UPNS_ENV_VAR} must be a comma-separated list of "
            "e-mails/UPNs, or unset to allow every user of the tenant.",
            details={OAUTH_ENTRA_ALLOWED_UPNS_ENV_VAR: allowed_raw},
        )
    if allowed_upns and not tenant_id:
        raise ConfigurationError(
            f"{OAUTH_ENTRA_ALLOWED_UPNS_ENV_VAR} only applies when the Microsoft Entra ID "
            "login is configured.",
            details={"missing_env_vars": [name for name, _ in required]},
        )

    return tenant_id, client_id, client_secret, allowed_upns


def _load_login_credentials(env: Mapping[str, str]) -> tuple[str, str]:
    """Read the optional /authorize login credentials.

    Both empty → login page disabled (auto-approve, the pre-0.3.0 behavior).
    Only one set → :class:`ConfigurationError`, mirroring the client id/secret
    rule. A value starting with ``scrypt$`` must be a well-formed hash.
    """

    username = env.get(OAUTH_LOGIN_USERNAME_ENV_VAR, "").strip()
    # Stripped like every other var: stray whitespace pasted into the deploy
    # panel is far more common than an intentional leading/trailing space.
    password = env.get(OAUTH_LOGIN_PASSWORD_ENV_VAR, "").strip()

    if bool(username) != bool(password):
        missing = OAUTH_LOGIN_USERNAME_ENV_VAR if not username else OAUTH_LOGIN_PASSWORD_ENV_VAR
        raise ConfigurationError(
            "OAuth login credentials are partially configured. Both "
            "OAUTH_LOGIN_USERNAME and OAUTH_LOGIN_PASSWORD must be set together, "
            "or both left empty to keep /authorize auto-approving.",
            details={"missing_env_var": missing},
        )

    if is_scrypt_hash(password) and parse_scrypt_hash(password) is None:
        # Never echo the value itself: it is a credential.
        raise ConfigurationError(
            f"{OAUTH_LOGIN_PASSWORD_ENV_VAR} starts with 'scrypt$' but is not a valid "
            "'scrypt$<salt_b64>$<hash_b64>' hash. Generate one with "
            "'python -m nn_mcp_auth.hash_password'.",
            details={"env_var": OAUTH_LOGIN_PASSWORD_ENV_VAR},
        )

    return username, password


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
