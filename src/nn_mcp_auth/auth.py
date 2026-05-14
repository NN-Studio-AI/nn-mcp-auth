"""ASGI middleware that gates protected paths behind bearer-token auth."""

from __future__ import annotations

import json
import secrets
from collections.abc import Iterable

from starlette.datastructures import Headers
from starlette.types import ASGIApp, Receive, Scope, Send

from .storage.base import AccessTokenStore


class BearerAuthMiddleware:
    """Validate the ``Authorization`` header for a set of protected paths.

    Accepts:

    - The static ``token`` (typically the MCP's ``MCP_AUTH_TOKEN``), compared
      in constant time.
    - Any token that ``oauth_store.is_valid()`` reports as still valid (the
      OAuth-issued bearer flow). Optional — pass ``None`` to reject all
      non-static tokens.

    All other requests pass through untouched, so callers can layer this
    middleware on a Starlette app that has additional unauthenticated
    routes (e.g. ``/health`` or a webhook receiver).
    """

    def __init__(
        self,
        app: ASGIApp,
        token: str,
        *,
        protected_paths: Iterable[str],
        oauth_store: AccessTokenStore | None = None,
    ) -> None:
        self.app = app
        self.token = token
        self.protected_paths = frozenset(protected_paths)
        self.oauth_store = oauth_store

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http" or scope.get("path") not in self.protected_paths:
            await self.app(scope, receive, send)
            return

        auth_header = Headers(scope=scope).get("authorization", "")
        if not auth_header.lower().startswith("bearer "):
            await self._send_auth_error(send)
            return

        provided_token = auth_header[7:]
        if secrets.compare_digest(provided_token, self.token):
            await self.app(scope, receive, send)
            return

        if self.oauth_store is not None and self.oauth_store.is_valid(provided_token):
            await self.app(scope, receive, send)
            return

        await self._send_auth_error(send)

    async def _send_auth_error(self, send: Send) -> None:
        body = {
            "error": "invalid_token",
            "error_description": "Authentication required",
        }
        body_bytes = json.dumps(body).encode()

        await send(
            {
                "type": "http.response.start",
                "status": 401,
                "headers": [
                    (b"content-type", b"application/json"),
                    (b"content-length", str(len(body_bytes)).encode()),
                    (
                        b"www-authenticate",
                        b'Bearer error="invalid_token", error_description="Authentication required"',
                    ),
                ],
            }
        )
        await send(
            {
                "type": "http.response.body",
                "body": body_bytes,
            }
        )
