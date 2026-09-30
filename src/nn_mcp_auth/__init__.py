"""Shared OAuth + bearer middleware for NN Studio MCP servers."""

from __future__ import annotations

from .auth import BearerAuthMiddleware, get_subject
from .entra import EntraAuthError, EntraIdentity, EntraVerifier, build_entra_authorize_url
from .errors import ConfigurationError, NnMcpAuthError, ValidationError
from .http import build_oauth_endpoints
from .oauth import (
    ENTRA_CALLBACK_PATH,
    AuthorizationCodeRecord,
    OAuthSettings,
    PendingAuthorizationRecord,
    RefreshTokenRecord,
    client_id_matches,
    credentials_match,
    load_oauth_settings,
    parse_basic_auth,
    verify_pkce,
)
from .password import hash_login_password, login_credentials_match, verify_login_password
from .runtime import JsonFormatter, configure_logging, log_json, sanitize_log_fields
from .storage import (
    AccessTokenStore,
    AuthCodeStore,
    LoginAttemptLimiter,
    MemoryAccessTokenStore,
    MemoryAuthCodeStore,
    MemoryLoginAttemptLimiter,
    MemoryOAuthStores,
    MemoryPendingAuthorizationStore,
    MemoryRefreshTokenStore,
    OAuthStores,
    PendingAuthorizationStore,
    RedisAccessTokenStore,
    RedisAuthCodeStore,
    RedisLoginAttemptLimiter,
    RedisOAuthStores,
    RedisPendingAuthorizationStore,
    RedisRefreshTokenStore,
    RefreshTokenStore,
)

__version__ = "0.3.0"

__all__ = [
    "__version__",
    # auth
    "BearerAuthMiddleware",
    "get_subject",
    # entra
    "EntraAuthError",
    "EntraIdentity",
    "EntraVerifier",
    "build_entra_authorize_url",
    # errors
    "ConfigurationError",
    "NnMcpAuthError",
    "ValidationError",
    # http
    "build_oauth_endpoints",
    # oauth
    "ENTRA_CALLBACK_PATH",
    "AuthorizationCodeRecord",
    "OAuthSettings",
    "PendingAuthorizationRecord",
    "RefreshTokenRecord",
    "client_id_matches",
    "credentials_match",
    "load_oauth_settings",
    "parse_basic_auth",
    "verify_pkce",
    # password (login page)
    "hash_login_password",
    "login_credentials_match",
    "verify_login_password",
    # runtime
    "JsonFormatter",
    "configure_logging",
    "log_json",
    "sanitize_log_fields",
    # storage
    "AccessTokenStore",
    "AuthCodeStore",
    "LoginAttemptLimiter",
    "MemoryAccessTokenStore",
    "MemoryAuthCodeStore",
    "MemoryLoginAttemptLimiter",
    "MemoryOAuthStores",
    "MemoryPendingAuthorizationStore",
    "MemoryRefreshTokenStore",
    "OAuthStores",
    "PendingAuthorizationStore",
    "RedisAccessTokenStore",
    "RedisAuthCodeStore",
    "RedisLoginAttemptLimiter",
    "RedisOAuthStores",
    "RedisPendingAuthorizationStore",
    "RedisRefreshTokenStore",
    "RefreshTokenStore",
]
