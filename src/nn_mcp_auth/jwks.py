"""Cached JWKS fetching shared by the Entra and Client ID Metadata verifiers."""

from __future__ import annotations

import logging
import time
from collections.abc import Callable
from typing import Any, Final

import httpx
import jwt
from jwt import PyJWK

from .runtime import log_json

LOGGER = logging.getLogger("nn_mcp_auth")

JWKS_HTTP_TIMEOUT_SECONDS: Final[float] = 10.0
JWKS_CACHE_TTL_SECONDS: Final[int] = 3600
# A key id we do not know may mean the issuer rotated its keys; refetch, but
# never more often than this so a flood of bogus ``kid`` values cannot hammer it.
JWKS_REFETCH_MIN_INTERVAL_SECONDS: Final[int] = 30
JWKS_MAX_BYTES: Final[int] = 64 * 1024
SUPPORTED_JWS_ALGORITHMS: Final[tuple[str, ...]] = ("RS256", "PS256", "ES256")


class JwksError(Exception):
    """A signing key could not be obtained. ``reason`` is a short log-safe tag."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


def parse_jwks(data: Any) -> dict[str, Any]:
    """Return ``{kid: public_key}`` for the usable signature keys of a JWKS document."""

    keys: dict[str, Any] = {}
    raw_keys = data.get("keys") if isinstance(data, dict) else None
    for jwk_data in raw_keys if isinstance(raw_keys, list) else []:
        if not isinstance(jwk_data, dict):
            continue
        kid = jwk_data.get("kid")
        if not isinstance(kid, str) or not kid:
            continue
        if jwk_data.get("use") not in (None, "sig"):
            continue
        try:
            keys[kid] = PyJWK.from_dict(jwk_data).key
        except jwt.PyJWTError:
            continue
    return keys


class StaticJwks:
    """Keys embedded in a document (the ``jwks`` member of a client metadata document)."""

    def __init__(self, data: Any) -> None:
        self._keys = parse_jwks(data)

    async def signing_key(self, kid: str) -> Any:
        key = self._keys.get(kid)
        if key is None:
            raise JwksError("signing_key_unknown")
        return key


class JwksCache:
    """Fetches a ``jwks_uri`` lazily and keeps the keys for an hour.

    On refresh failure the cached keys keep serving (issuers rotate rarely and
    a transient outage must not lock every login out); only a cold cache
    surfaces the failure.
    """

    def __init__(
        self,
        uri: str,
        *,
        clock: Callable[[], float] = time.monotonic,
        failure_event: str = "jwks_refresh_failed",
    ) -> None:
        self._uri = uri
        self._clock = clock
        self._failure_event = failure_event
        self._keys: dict[str, Any] = {}
        self._fetched_at: float | None = None

    async def signing_key(self, kid: str) -> Any:
        now = self._clock()
        never_fetched = self._fetched_at is None
        age = now - float(self._fetched_at or 0.0)
        stale = never_fetched or age > JWKS_CACHE_TTL_SECONDS
        can_refetch = never_fetched or age >= JWKS_REFETCH_MIN_INTERVAL_SECONDS
        if (stale or kid not in self._keys) and can_refetch:
            await self._fetch()
        key = self._keys.get(kid)
        if key is None:
            raise JwksError("signing_key_unknown")
        return key

    async def _fetch(self) -> None:
        try:
            async with httpx.AsyncClient(
                timeout=JWKS_HTTP_TIMEOUT_SECONDS, follow_redirects=False
            ) as client:
                response = await client.get(self._uri, headers={"Accept": "application/json"})
            if response.status_code != 200:
                raise JwksError("jwks_unavailable")
            if len(response.content) > JWKS_MAX_BYTES:
                raise JwksError("jwks_too_large")
            keys = parse_jwks(response.json())
            if not keys:
                raise JwksError("jwks_empty")
        except (httpx.HTTPError, ValueError, JwksError) as exc:
            if self._keys:
                log_json(LOGGER, logging.WARNING, self._failure_event, uri=self._uri)
                self._fetched_at = self._clock()
                return
            if isinstance(exc, JwksError):
                raise
            raise JwksError("jwks_unreachable") from exc
        self._keys = keys
        self._fetched_at = self._clock()
