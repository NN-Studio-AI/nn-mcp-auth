"""Redis backends for OAuth state.

Uses native Redis TTL for expiration — no need to track ``expires_at`` per
record. ``GETDEL`` (Redis 6.2+) gives us atomic one-time-use semantics for
authorization codes and refresh tokens, which is what RFC 6749 expects.

Keys are namespaced by a caller-supplied prefix so multiple MCPs can share
one Redis instance without collisions:

- ``{prefix}:access:{token}``  → ``"1"``  (TTL = access lifetime)
- ``{prefix}:refresh:{token}`` → ``"1"``  (TTL = refresh lifetime)
- ``{prefix}:code:{code}``     → JSON     (TTL = code lifetime)
"""

from __future__ import annotations

import json
import os
import secrets
from dataclasses import dataclass

import redis

from ..errors import ConfigurationError
from ..oauth import (
    AUTHORIZATION_CODE_TTL_SECONDS,
    DEFAULT_OAUTH_TOKEN_TTL_SECONDS,
    REFRESH_TOKEN_TTL_SECONDS,
    AuthorizationCodeRecord,
)
from .base import OAuthStores

REDIS_URL_ENV_VAR = "REDIS_URL"
REDIS_KEY_PREFIX_ENV_VAR = "REDIS_KEY_PREFIX"


class RedisAccessTokenStore:
    def __init__(
        self,
        client: redis.Redis,
        *,
        prefix: str,
        ttl_seconds: int = DEFAULT_OAUTH_TOKEN_TTL_SECONDS,
    ) -> None:
        self._r = client
        self._prefix = f"{prefix}:access"
        self._ttl = ttl_seconds

    def issue(self) -> tuple[str, int]:
        token = secrets.token_urlsafe(48)
        self._r.set(f"{self._prefix}:{token}", "1", ex=self._ttl)
        return token, self._ttl

    def is_valid(self, token: str) -> bool:
        if not token:
            return False
        return bool(self._r.exists(f"{self._prefix}:{token}"))

    def revoke(self, token: str) -> None:
        if token:
            self._r.delete(f"{self._prefix}:{token}")


class RedisRefreshTokenStore:
    def __init__(
        self,
        client: redis.Redis,
        *,
        prefix: str,
        ttl_seconds: int = REFRESH_TOKEN_TTL_SECONDS,
    ) -> None:
        self._r = client
        self._prefix = f"{prefix}:refresh"
        self._ttl = ttl_seconds

    def issue(self) -> str:
        token = secrets.token_urlsafe(64)
        self._r.set(f"{self._prefix}:{token}", "1", ex=self._ttl)
        return token

    def consume(self, token: str) -> bool:
        if not token:
            return False
        # GETDEL is atomic in Redis ≥ 6.2 — pop + check existence in one round-trip.
        return self._r.getdel(f"{self._prefix}:{token}") is not None


class RedisAuthCodeStore:
    def __init__(
        self,
        client: redis.Redis,
        *,
        prefix: str,
        ttl_seconds: int = AUTHORIZATION_CODE_TTL_SECONDS,
    ) -> None:
        self._r = client
        self._prefix = f"{prefix}:code"
        self._ttl = ttl_seconds

    def issue(
        self,
        *,
        client_id: str,
        redirect_uri: str,
        code_challenge: str,
        code_challenge_method: str,
    ) -> str:
        code = secrets.token_urlsafe(48)
        payload = json.dumps(
            {
                "client_id": client_id,
                "redirect_uri": redirect_uri,
                "code_challenge": code_challenge,
                "code_challenge_method": code_challenge_method,
            },
            separators=(",", ":"),
        )
        self._r.set(f"{self._prefix}:{code}", payload, ex=self._ttl)
        return code

    def consume(self, code: str) -> AuthorizationCodeRecord | None:
        if not code:
            return None
        raw = self._r.getdel(f"{self._prefix}:{code}")
        if not raw:
            return None
        data = json.loads(raw)
        return AuthorizationCodeRecord(
            client_id=data["client_id"],
            redirect_uri=data["redirect_uri"],
            code_challenge=data["code_challenge"],
            code_challenge_method=data["code_challenge_method"],
        )


@dataclass(frozen=True, slots=True)
class RedisOAuthStores(OAuthStores):
    @classmethod
    def from_env(
        cls,
        env: dict[str, str] | None = None,
        *,
        access_ttl: int = DEFAULT_OAUTH_TOKEN_TTL_SECONDS,
        refresh_ttl: int = REFRESH_TOKEN_TTL_SECONDS,
        code_ttl: int = AUTHORIZATION_CODE_TTL_SECONDS,
    ) -> RedisOAuthStores:
        e = env if env is not None else os.environ
        url = e.get(REDIS_URL_ENV_VAR, "").strip()
        prefix = e.get(REDIS_KEY_PREFIX_ENV_VAR, "").strip()
        if not url:
            raise ConfigurationError(
                f"{REDIS_URL_ENV_VAR} is required for RedisOAuthStores.",
                details={"env_var": REDIS_URL_ENV_VAR},
            )
        if not prefix:
            raise ConfigurationError(
                f"{REDIS_KEY_PREFIX_ENV_VAR} is required (per-MCP namespace).",
                details={"env_var": REDIS_KEY_PREFIX_ENV_VAR},
            )
        client = redis.Redis.from_url(url, decode_responses=True)
        return cls.from_client(
            client,
            prefix=prefix,
            access_ttl=access_ttl,
            refresh_ttl=refresh_ttl,
            code_ttl=code_ttl,
        )

    @classmethod
    def from_client(
        cls,
        client: redis.Redis,
        *,
        prefix: str,
        access_ttl: int = DEFAULT_OAUTH_TOKEN_TTL_SECONDS,
        refresh_ttl: int = REFRESH_TOKEN_TTL_SECONDS,
        code_ttl: int = AUTHORIZATION_CODE_TTL_SECONDS,
    ) -> RedisOAuthStores:
        return cls(
            access=RedisAccessTokenStore(client, prefix=prefix, ttl_seconds=access_ttl),
            refresh=RedisRefreshTokenStore(client, prefix=prefix, ttl_seconds=refresh_ttl),
            code=RedisAuthCodeStore(client, prefix=prefix, ttl_seconds=code_ttl),
        )
