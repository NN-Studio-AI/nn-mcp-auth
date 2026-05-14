"""ASGI middleware that gates protected paths behind bearer-token auth."""

from __future__ import annotations

import json
import secrets
from collections.abc import Iterable, Mapping

from starlette.datastructures import Headers
from starlette.types import ASGIApp, Receive, Scope, Send

from .storage.base import AccessTokenStore

SCOPE_STATE_SUBJECT_KEY = "nn_mcp_auth.subject"


def get_subject(scope_or_request: object) -> str | None:
    """Return the subject (caller identity) attached by :class:`BearerAuthMiddleware`.

    Accepts either a raw ASGI ``scope`` mapping or a Starlette ``Request``
    object. Returns ``None`` when the request did not carry an identified
    token (e.g. a single static ``MCP_AUTH_TOKEN`` without per-caller mapping).
    """

    state = getattr(scope_or_request, "scope", scope_or_request)
    if not isinstance(state, Mapping):
        return None
    value = state.get(SCOPE_STATE_SUBJECT_KEY)
    return value if isinstance(value, str) else None


class BearerAuthMiddleware:
    """Validate the ``Authorization`` header for a set of protected paths.

    Accepts ``token`` in two shapes:

    - **str** — a single static token (typically the MCP's ``MCP_AUTH_TOKEN``);
      compared in constant time. No caller identity is exposed.
    - **Mapping[str, str]** — ``{token: subject}``. The first token that
      matches in constant time wins; its ``subject`` is attached to the ASGI
      scope so downstream handlers can identify the caller via
      :func:`get_subject`.

    Optionally also accepts any token that ``oauth_store.is_valid()`` reports
    as valid (the OAuth-issued bearer flow). Tokens minted via OAuth do not
    carry identity in this minor version — that is the next milestone.

    All other requests pass through untouched, so callers can layer this
    middleware on a Starlette app that has additional unauthenticated
    routes (e.g. ``/health`` or a webhook receiver).
    """

    def __init__(
        self,
        app: ASGIApp,
        token: str | Mapping[str, str],
        *,
        protected_paths: Iterable[str],
        oauth_store: AccessTokenStore | None = None,
    ) -> None:
        self.app = app
        if isinstance(token, str):
            self._static_tokens: tuple[tuple[str, str | None], ...] = ((token, None),)
        else:
            self._static_tokens = tuple(
                (tok, subject)
                for tok, subject in token.items()
                if isinstance(tok, str) and tok
            )
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
        for valid_token, subject in self._static_tokens:
            if valid_token and secrets.compare_digest(provided_token, valid_token):
                if subject is not None:
                    scope[SCOPE_STATE_SUBJECT_KEY] = subject  # type: ignore[index]
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
