"""Storage protocols for OAuth state.

Each store has a small, opinionated interface so any backend (in-memory,
Redis, future SQL) implements the same shape. The :class:`OAuthStores`
dataclass bundles the three stores so the HTTP endpoint factory can take
a single argument.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol, runtime_checkable

from ..oauth import AuthorizationCodeRecord


@runtime_checkable
class AccessTokenStore(Protocol):
    def issue(self) -> tuple[str, int]:
        """Mint an access token, returning ``(token, ttl_seconds)``."""

    def is_valid(self, token: str) -> bool:
        """Return ``True`` if the token is currently valid."""

    def revoke(self, token: str) -> None:
        """Invalidate a token if present. No-op when unknown."""


@runtime_checkable
class RefreshTokenStore(Protocol):
    def issue(self) -> str:
        """Mint a refresh token."""

    def consume(self, token: str) -> bool:
        """Return ``True`` if the token is valid; invalidates it on success."""


@runtime_checkable
class AuthCodeStore(Protocol):
    def issue(
        self,
        *,
        client_id: str,
        redirect_uri: str,
        code_challenge: str,
        code_challenge_method: str,
    ) -> str:
        """Mint a one-time authorization code bound to PKCE + redirect URI."""

    def consume(self, code: str) -> AuthorizationCodeRecord | None:
        """Pop the code if valid; returns ``None`` if absent or expired."""


@dataclass(frozen=True, slots=True)
class OAuthStores:
    access: AccessTokenStore
    refresh: RefreshTokenStore
    code: AuthCodeStore
