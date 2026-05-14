"""Shared OAuth + bearer middleware for NN Studio MCP servers."""

from __future__ import annotations

from .auth import BearerAuthMiddleware, get_subject
from .errors import ConfigurationError, NnMcpAuthError, ValidationError
from .http import build_oauth_endpoints
from .oauth import (
    AuthorizationCodeRecord,
    OAuthSettings,
    client_id_matches,
    credentials_match,
    load_oauth_settings,
    parse_basic_auth,
    verify_pkce,
)
from .runtime import JsonFormatter, configure_logging, log_json, sanitize_log_fields
from .storage import (
    AccessTokenStore,
    AuthCodeStore,
    MemoryAccessTokenStore,
    MemoryAuthCodeStore,
    MemoryOAuthStores,
    MemoryRefreshTokenStore,
    OAuthStores,
    RedisAccessTokenStore,
    RedisAuthCodeStore,
    RedisOAuthStores,
    RedisRefreshTokenStore,
    RefreshTokenStore,
)

__version__ = "0.2.0"

__all__ = [
    "__version__",
    # auth
    "BearerAuthMiddleware",
    "get_subject",
    # errors
    "ConfigurationError",
    "NnMcpAuthError",
    "ValidationError",
    # http
    "build_oauth_endpoints",
    # oauth
    "AuthorizationCodeRecord",
    "OAuthSettings",
    "client_id_matches",
    "credentials_match",
    "load_oauth_settings",
    "parse_basic_auth",
    "verify_pkce",
    # runtime
    "JsonFormatter",
    "configure_logging",
    "log_json",
    "sanitize_log_fields",
    # storage
    "AccessTokenStore",
    "AuthCodeStore",
    "MemoryAccessTokenStore",
    "MemoryAuthCodeStore",
    "MemoryOAuthStores",
    "MemoryRefreshTokenStore",
    "OAuthStores",
    "RedisAccessTokenStore",
    "RedisAuthCodeStore",
    "RedisOAuthStores",
    "RedisRefreshTokenStore",
    "RefreshTokenStore",
]
