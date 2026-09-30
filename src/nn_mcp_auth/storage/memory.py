"""In-memory backends — dev/testing only; tokens vanish on process restart."""

from __future__ import annotations

import secrets
import time
from collections.abc import Callable
from dataclasses import dataclass, field

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


@dataclass(slots=True)
class MemoryAccessTokenStore:
    ttl_seconds: int = DEFAULT_OAUTH_TOKEN_TTL_SECONDS
    # token -> (expires_at, subject)
    _tokens: dict[str, tuple[float, str | None]] = field(default_factory=dict)
    _clock: Callable[[], float] = field(default=time.monotonic)

    def issue(self, *, subject: str | None = None) -> tuple[str, int]:
        token = secrets.token_urlsafe(48)
        self._tokens[token] = (self._clock() + self.ttl_seconds, subject or None)
        self._purge_expired()
        return token, self.ttl_seconds

    def is_valid(self, token: str) -> bool:
        if not token:
            return False
        self._purge_expired()
        return token in self._tokens

    def subject_of(self, token: str) -> str | None:
        if not token:
            return None
        self._purge_expired()
        stored = self._tokens.get(token)
        return stored[1] if stored is not None else None

    def revoke(self, token: str) -> None:
        self._tokens.pop(token, None)

    def _purge_expired(self) -> None:
        now = self._clock()
        expired = [t for t, (exp, _) in self._tokens.items() if exp <= now]
        for t in expired:
            del self._tokens[t]


@dataclass(slots=True)
class MemoryRefreshTokenStore:
    ttl_seconds: int = REFRESH_TOKEN_TTL_SECONDS
    # token -> (expires_at, subject)
    _tokens: dict[str, tuple[float, str | None]] = field(default_factory=dict)
    _clock: Callable[[], float] = field(default=time.monotonic)

    def issue(self, *, subject: str | None = None) -> str:
        token = secrets.token_urlsafe(64)
        self._tokens[token] = (self._clock() + self.ttl_seconds, subject or None)
        self._purge_expired()
        return token

    def consume(self, token: str) -> bool:
        return self.pop(token) is not None

    def pop(self, token: str) -> RefreshTokenRecord | None:
        self._purge_expired()
        stored = self._tokens.pop(token, None)
        if stored is None:
            return None
        expires_at, subject = stored
        if expires_at <= self._clock():
            return None
        return RefreshTokenRecord(subject=subject)

    def _purge_expired(self) -> None:
        now = self._clock()
        expired = [t for t, (exp, _) in self._tokens.items() if exp <= now]
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
        subject: str | None = None,
    ) -> str:
        code = secrets.token_urlsafe(48)
        self._codes[code] = _StoredCode(
            record=AuthorizationCodeRecord(
                client_id=client_id,
                redirect_uri=redirect_uri,
                code_challenge=code_challenge,
                code_challenge_method=code_challenge_method,
                subject=subject or None,
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


@dataclass(slots=True)
class _StoredPending:
    record: PendingAuthorizationRecord
    expires_at: float


@dataclass(slots=True)
class MemoryPendingAuthorizationStore:
    ttl_seconds: int = PENDING_AUTHORIZATION_TTL_SECONDS
    _requests: dict[str, _StoredPending] = field(default_factory=dict)
    _clock: Callable[[], float] = field(default=time.monotonic)

    def create(self, record: PendingAuthorizationRecord) -> str:
        request_id = secrets.token_urlsafe(32)
        self._requests[request_id] = _StoredPending(
            record=record, expires_at=self._clock() + self.ttl_seconds
        )
        self._purge_expired()
        return request_id

    def get(self, request_id: str) -> PendingAuthorizationRecord | None:
        self._purge_expired()
        stored = self._requests.get(request_id)
        return stored.record if stored is not None else None

    def consume(self, request_id: str) -> PendingAuthorizationRecord | None:
        self._purge_expired()
        stored = self._requests.pop(request_id, None)
        return stored.record if stored is not None else None

    def _purge_expired(self) -> None:
        now = self._clock()
        expired = [k for k, v in self._requests.items() if v.expires_at <= now]
        for k in expired:
            del self._requests[k]


@dataclass(slots=True)
class MemoryLoginAttemptLimiter:
    window_seconds: int = LOGIN_RATE_LIMIT_WINDOW_SECONDS
    _windows: dict[str, tuple[int, float]] = field(default_factory=dict)
    _clock: Callable[[], float] = field(default=time.monotonic)

    def hit(self, key: str) -> tuple[int, int]:
        now = self._clock()
        expired = [k for k, (_, reset_at) in self._windows.items() if reset_at <= now]
        for k in expired:
            del self._windows[k]
        count, reset_at = self._windows.get(key, (0, now + self.window_seconds))
        count += 1
        self._windows[key] = (count, reset_at)
        return count, max(1, int(round(reset_at - now)))


@dataclass(frozen=True, slots=True)
class MemoryOAuthStores(OAuthStores):
    @classmethod
    def create(
        cls,
        *,
        access_ttl: int = DEFAULT_OAUTH_TOKEN_TTL_SECONDS,
        refresh_ttl: int = REFRESH_TOKEN_TTL_SECONDS,
        code_ttl: int = AUTHORIZATION_CODE_TTL_SECONDS,
        pending_ttl: int = PENDING_AUTHORIZATION_TTL_SECONDS,
        login_window: int = LOGIN_RATE_LIMIT_WINDOW_SECONDS,
    ) -> MemoryOAuthStores:
        return cls(
            access=MemoryAccessTokenStore(ttl_seconds=access_ttl),
            refresh=MemoryRefreshTokenStore(ttl_seconds=refresh_ttl),
            code=MemoryAuthCodeStore(ttl_seconds=code_ttl),
            pending=MemoryPendingAuthorizationStore(ttl_seconds=pending_ttl),
            login_limiter=MemoryLoginAttemptLimiter(window_seconds=login_window),
        )
