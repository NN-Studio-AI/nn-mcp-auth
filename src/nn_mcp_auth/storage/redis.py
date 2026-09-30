"""Redis backends for OAuth state.

Uses native Redis TTL for expiration — no need to track ``expires_at`` per
record. ``GETDEL`` (Redis 6.2+) gives us atomic one-time-use semantics for
authorization codes and refresh tokens, which is what RFC 6749 expects.

Keys are namespaced by a caller-supplied prefix so multiple MCPs can share
one Redis instance without collisions:

- ``{prefix}:access:{token}``  → ``"1"`` or ``{"subject": ...}`` (TTL = access lifetime)
- ``{prefix}:refresh:{token}`` → ``"1"`` or ``{"subject": ...}`` (TTL = refresh lifetime)
- ``{prefix}:code:{code}``     → JSON     (TTL = code lifetime)
- ``{prefix}:pending_authz:{id}`` → JSON  (TTL = pending /authorize lifetime)
- ``{prefix}:login_attempts:{ip}`` → int  (TTL = rate-limit window)
"""

from __future__ import annotations

import json
import os
import secrets
from dataclasses import dataclass
from typing import Any, cast

import redis

from ..errors import ConfigurationError
from ..oauth import (
    AUTHORIZATION_CODE_TTL_SECONDS,
    DEFAULT_OAUTH_TOKEN_TTL_SECONDS,
    LOGIN_RATE_LIMIT_WINDOW_SECONDS,
    PENDING_AUTHORIZATION_TTL_SECONDS,
    REFRESH_TOKEN_TTL_SECONDS,
    AuthorizationCodeRecord,
    PendingAuthorizationRecord,
    RefreshTokenRecord,
)
from .base import OAuthStores

REDIS_URL_ENV_VAR = "REDIS_URL"
REDIS_KEY_PREFIX_ENV_VAR = "REDIS_KEY_PREFIX"

# Anonymous tokens keep the historical ``"1"`` value so entries written by
# older versions of this library stay valid after an upgrade.
_ANONYMOUS_VALUE = "1"


def _encode_subject(subject: str | None) -> str:
    if not subject:
        return _ANONYMOUS_VALUE
    return json.dumps({"subject": subject}, separators=(",", ":"))


def _decode_subject(raw: str | None) -> str | None:
    if not raw or not raw.startswith("{"):
        return None
    try:
        data = json.loads(raw)
    except ValueError:
        return None
    subject = data.get("subject") if isinstance(data, dict) else None
    return subject if isinstance(subject, str) and subject else None


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

    def issue(self, *, subject: str | None = None) -> tuple[str, int]:
        token = secrets.token_urlsafe(48)
        self._r.set(f"{self._prefix}:{token}", _encode_subject(subject), ex=self._ttl)
        return token, self._ttl

    def is_valid(self, token: str) -> bool:
        if not token:
            return False
        return bool(self._r.exists(f"{self._prefix}:{token}"))

    def subject_of(self, token: str) -> str | None:
        if not token:
            return None
        return _decode_subject(cast(str | None, self._r.get(f"{self._prefix}:{token}")))

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

    def issue(self, *, subject: str | None = None) -> str:
        token = secrets.token_urlsafe(64)
        self._r.set(f"{self._prefix}:{token}", _encode_subject(subject), ex=self._ttl)
        return token

    def consume(self, token: str) -> bool:
        return self.pop(token) is not None

    def pop(self, token: str) -> RefreshTokenRecord | None:
        if not token:
            return None
        # GETDEL is atomic in Redis ≥ 6.2 — pop + check existence in one round-trip.
        raw = cast(str | None, self._r.getdel(f"{self._prefix}:{token}"))
        if raw is None:
            return None
        return RefreshTokenRecord(subject=_decode_subject(raw))


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
        subject: str | None = None,
    ) -> str:
        code = secrets.token_urlsafe(48)
        payload = json.dumps(
            {
                "client_id": client_id,
                "redirect_uri": redirect_uri,
                "code_challenge": code_challenge,
                "code_challenge_method": code_challenge_method,
                "subject": subject or None,
            },
            separators=(",", ":"),
        )
        self._r.set(f"{self._prefix}:{code}", payload, ex=self._ttl)
        return code

    def consume(self, code: str) -> AuthorizationCodeRecord | None:
        if not code:
            return None
        raw = cast(str | None, self._r.getdel(f"{self._prefix}:{code}"))
        if not raw:
            return None
        data = json.loads(raw)
        return AuthorizationCodeRecord(
            client_id=data["client_id"],
            redirect_uri=data["redirect_uri"],
            code_challenge=data["code_challenge"],
            code_challenge_method=data["code_challenge_method"],
            subject=data.get("subject") or None,
        )


class RedisPendingAuthorizationStore:
    def __init__(
        self,
        client: redis.Redis,
        *,
        prefix: str,
        ttl_seconds: int = PENDING_AUTHORIZATION_TTL_SECONDS,
    ) -> None:
        self._r = client
        self._prefix = f"{prefix}:pending_authz"
        self._ttl = ttl_seconds

    def create(self, record: PendingAuthorizationRecord) -> str:
        request_id = secrets.token_urlsafe(32)
        payload = json.dumps(
            {
                "client_id": record.client_id,
                "redirect_uri": record.redirect_uri,
                "code_challenge": record.code_challenge,
                "code_challenge_method": record.code_challenge_method,
                "state": record.state,
                "nonce": record.nonce,
            },
            separators=(",", ":"),
        )
        self._r.set(f"{self._prefix}:{request_id}", payload, ex=self._ttl)
        return request_id

    def get(self, request_id: str) -> PendingAuthorizationRecord | None:
        if not request_id:
            return None
        return self._decode(cast(str | None, self._r.get(f"{self._prefix}:{request_id}")))

    def consume(self, request_id: str) -> PendingAuthorizationRecord | None:
        if not request_id:
            return None
        # GETDEL keeps the request single-use even with concurrent submissions.
        return self._decode(cast(str | None, self._r.getdel(f"{self._prefix}:{request_id}")))

    @staticmethod
    def _decode(raw: str | None) -> PendingAuthorizationRecord | None:
        if not raw:
            return None
        data: dict[str, Any] = json.loads(raw)
        return PendingAuthorizationRecord(
            client_id=data["client_id"],
            redirect_uri=data["redirect_uri"],
            code_challenge=data["code_challenge"],
            code_challenge_method=data["code_challenge_method"],
            state=data.get("state", ""),
            nonce=data.get("nonce", ""),
        )


class RedisLoginAttemptLimiter:
    """Fixed-window counter: ``SET key 0 NX EX window`` then ``INCR``, in one MULTI.

    Creating the key with its TTL before incrementing means a crash between
    the two commands can never leave an immortal counter (permanent lockout).
    """

    def __init__(
        self,
        client: redis.Redis,
        *,
        prefix: str,
        window_seconds: int = LOGIN_RATE_LIMIT_WINDOW_SECONDS,
    ) -> None:
        self._r = client
        self._prefix = f"{prefix}:login_attempts"
        self._window = window_seconds

    def hit(self, key: str) -> tuple[int, int]:
        redis_key = f"{self._prefix}:{key}"
        pipe = self._r.pipeline(transaction=True)
        pipe.set(redis_key, 0, nx=True, ex=self._window)
        pipe.incr(redis_key)
        pipe.ttl(redis_key)
        _, count, ttl = pipe.execute()
        remaining = int(ttl) if isinstance(ttl, int) and ttl > 0 else self._window
        return int(count), remaining


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
            pending=RedisPendingAuthorizationStore(client, prefix=prefix),
            login_limiter=RedisLoginAttemptLimiter(client, prefix=prefix),
        )
