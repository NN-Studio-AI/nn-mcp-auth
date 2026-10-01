"""Storage protocols for OAuth state.

Each store has a small, opinionated interface so any backend (in-memory,
Redis, future SQL) implements the same shape. The :class:`OAuthStores`
dataclass bundles the stores so the HTTP endpoint factory can take a single
argument.

``pending`` and ``login_limiter`` only matter when the /authorize login page
is enabled (``OAUTH_LOGIN_USERNAME`` + ``OAUTH_LOGIN_PASSWORD``). They are
optional so hand-built ``OAuthStores(access=..., refresh=..., code=...)``
keeps working; the endpoint factory falls back to in-memory versions.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol, runtime_checkable

from ..oauth import AuthorizationCodeRecord, PendingAuthorizationRecord, RefreshTokenRecord


@runtime_checkable
class AccessTokenStore(Protocol):
    def issue(self, *, subject: str | None = None) -> tuple[str, int]:
        """Mint an access token, returning ``(token, ttl_seconds)``.

        ``subject`` is the identity of the person who logged in (``None`` for
        service tokens such as ``client_credentials``).
        """

    def is_valid(self, token: str) -> bool:
        """Return ``True`` if the token is currently valid."""

    def subject_of(self, token: str) -> str | None:
        """Return the subject bound to a valid token; ``None`` when anonymous or unknown."""

    def revoke(self, token: str) -> None:
        """Invalidate a token if present. No-op when unknown."""


@runtime_checkable
class RefreshTokenStore(Protocol):
    def issue(self, *, subject: str | None = None, client_id: str | None = None) -> str:
        """Mint a refresh token carrying ``subject`` and the ``client_id`` it belongs to."""

    def consume(self, token: str) -> bool:
        """Return ``True`` if the token is valid; invalidates it on success."""

    def pop(self, token: str) -> RefreshTokenRecord | None:
        """Like :meth:`consume` but returns the stored record (``None`` if invalid)."""


@runtime_checkable
class AuthCodeStore(Protocol):
    def issue(
        self,
        *,
        client_id: str,
        redirect_uri: str,
        code_challenge: str,
        code_challenge_method: str,
        subject: str | None = None,
    ) -> str:
        """Mint a one-time authorization code bound to PKCE + redirect URI (+ subject)."""

    def consume(self, code: str) -> AuthorizationCodeRecord | None:
        """Pop the code if valid; returns ``None`` if absent or expired."""


@runtime_checkable
class PendingAuthorizationStore(Protocol):
    def create(self, record: PendingAuthorizationRecord) -> str:
        """Persist a validated /authorize request; returns a random single-use id."""

    def get(self, request_id: str) -> PendingAuthorizationRecord | None:
        """Read without consuming (used to re-render the form after a bad login)."""

    def consume(self, request_id: str) -> PendingAuthorizationRecord | None:
        """Atomically pop the request; ``None`` if absent, expired or already used."""


@runtime_checkable
class ReplayGuardStore(Protocol):
    def claim(self, key: str, ttl_seconds: int) -> bool:
        """Record ``key`` for ``ttl_seconds``; ``False`` when it was already recorded."""


@runtime_checkable
class LoginAttemptLimiter(Protocol):
    def hit(self, key: str) -> tuple[int, int]:
        """Count one attempt for ``key`` in a fixed window.

        Returns ``(attempts_in_window, seconds_until_window_resets)``.
        """


@dataclass(frozen=True, slots=True)
class OAuthStores:
    access: AccessTokenStore
    refresh: RefreshTokenStore
    code: AuthCodeStore
    pending: PendingAuthorizationStore | None = None
    login_limiter: LoginAttemptLimiter | None = None
    replay_guard: ReplayGuardStore | None = None
