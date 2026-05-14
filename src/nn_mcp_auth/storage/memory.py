"""In-memory backends — dev/testing only; tokens vanish on process restart."""

from __future__ import annotations

import secrets
import time
from collections.abc import Callable
from dataclasses import dataclass, field

from ..oauth import (
    AUTHORIZATION_CODE_TTL_SECONDS,
    DEFAULT_OAUTH_TOKEN_TTL_SECONDS,
    REFRESH_TOKEN_TTL_SECONDS,
    AuthorizationCodeRecord,
)
from .base import OAuthStores


@dataclass(slots=True)
class MemoryAccessTokenStore:
    ttl_seconds: int = DEFAULT_OAUTH_TOKEN_TTL_SECONDS
    _tokens: dict[str, float] = field(default_factory=dict)
    _clock: Callable[[], float] = field(default=time.monotonic)

    def issue(self) -> tuple[str, int]:
        token = secrets.token_urlsafe(48)
        self._tokens[token] = self._clock() + self.ttl_seconds
        self._purge_expired()
        return token, self.ttl_seconds

    def is_valid(self, token: str) -> bool:
        if not token:
            return False
        self._purge_expired()
        return token in self._tokens

    def revoke(self, token: str) -> None:
        self._tokens.pop(token, None)

    def _purge_expired(self) -> None:
        now = self._clock()
        expired = [t for t, exp in self._tokens.items() if exp <= now]
        for t in expired:
            del self._tokens[t]


@dataclass(slots=True)
class MemoryRefreshTokenStore:
    ttl_seconds: int = REFRESH_TOKEN_TTL_SECONDS
    _tokens: dict[str, float] = field(default_factory=dict)
    _clock: Callable[[], float] = field(default=time.monotonic)

    def issue(self) -> str:
        token = secrets.token_urlsafe(64)
        self._tokens[token] = self._clock() + self.ttl_seconds
        self._purge_expired()
        return token

    def consume(self, token: str) -> bool:
        self._purge_expired()
        expires_at = self._tokens.pop(token, None)
        if expires_at is None:
            return False
        return expires_at > self._clock()

    def _purge_expired(self) -> None:
        now = self._clock()
        expired = [t for t, exp in self._tokens.items() if exp <= now]
        for t in expired:
            del self._tokens[t]


@dataclass(slots=True)
class _StoredCode:
    record: AuthorizationCodeRecord
    expires_at: float


@dataclass(slots=True)
class MemoryAuthCodeStore:
    ttl_seconds: int = AUTHORIZATION_CODE_TTL_SECONDS
    _codes: dict[str, _StoredCode] = field(default_factory=dict)
    _clock: Callable[[], float] = field(default=time.monotonic)

    def issue(
        self,
        *,
        client_id: str,
        redirect_uri: str,
        code_challenge: str,
        code_challenge_method: str,
    ) -> str:
        code = secrets.token_urlsafe(48)
        self._codes[code] = _StoredCode(
            record=AuthorizationCodeRecord(
                client_id=client_id,
                redirect_uri=redirect_uri,
                code_challenge=code_challenge,
                code_challenge_method=code_challenge_method,
            ),
            expires_at=self._clock() + self.ttl_seconds,
        )
        self._purge_expired()
        return code

    def consume(self, code: str) -> AuthorizationCodeRecord | None:
        self._purge_expired()
        stored = self._codes.pop(code, None)
        if stored is None:
            return None
        if stored.expires_at <= self._clock():
            return None
        return stored.record

    def _purge_expired(self) -> None:
        now = self._clock()
        expired = [c for c, s in self._codes.items() if s.expires_at <= now]
        for c in expired:
            del self._codes[c]


@dataclass(frozen=True, slots=True)
class MemoryOAuthStores(OAuthStores):
    @classmethod
    def create(
        cls,
        *,
        access_ttl: int = DEFAULT_OAUTH_TOKEN_TTL_SECONDS,
        refresh_ttl: int = REFRESH_TOKEN_TTL_SECONDS,
        code_ttl: int = AUTHORIZATION_CODE_TTL_SECONDS,
    ) -> MemoryOAuthStores:
        return cls(
            access=MemoryAccessTokenStore(ttl_seconds=access_ttl),
            refresh=MemoryRefreshTokenStore(ttl_seconds=refresh_ttl),
            code=MemoryAuthCodeStore(ttl_seconds=code_ttl),
        )
