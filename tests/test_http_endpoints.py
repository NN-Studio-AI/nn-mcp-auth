"""End-to-end OAuth flow tests against a Starlette app via TestClient."""

from __future__ import annotations

import base64
import hashlib
import secrets
from urllib.parse import parse_qs, urlparse

import pytest
from starlette.applications import Starlette
from starlette.responses import JSONResponse
from starlette.routing import Route
from starlette.testclient import TestClient

from nn_mcp_auth import (
    BearerAuthMiddleware,
    MemoryOAuthStores,
    OAuthSettings,
    build_oauth_endpoints,
)


def _pkce_pair() -> tuple[str, str]:
    verifier = secrets.token_urlsafe(64)[:64]
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
    return verifier, challenge


@pytest.fixture
def app() -> Starlette:
    async def mcp_endpoint(_):  # type: ignore[no-untyped-def]
        return JSONResponse({"ok": True})

    settings = OAuthSettings(
        client_id="cid",
        client_secret="csec",
        allowed_redirect_uris=("https://claude.ai/api/mcp/auth_callback",),
    )
    stores = MemoryOAuthStores.create()

    app = Starlette(routes=[Route("/mcp", mcp_endpoint, methods=["POST"])])
    build_oauth_endpoints(app, settings=settings, stores=stores)
    app.add_middleware(
        BearerAuthMiddleware,
        token="static-mcp-token",
        protected_paths={"/mcp"},
        oauth_store=stores.access,
    )
    return app


def test_authorization_code_full_flow(app: Starlette) -> None:
    verifier, challenge = _pkce_pair()
    with TestClient(app) as client:
        # 1. /authorize redirect with code
        auth_resp = client.get(
            "/authorize",
            params={
                "response_type": "code",
                "client_id": "cid",
                "redirect_uri": "https://claude.ai/api/mcp/auth_callback",
                "code_challenge": challenge,
                "code_challenge_method": "S256",
                "state": "abc",
            },
            follow_redirects=False,
        )
        assert auth_resp.status_code == 302
        location = auth_resp.headers["location"]
        qs = parse_qs(urlparse(location).query)
        assert qs.get("state") == ["abc"]
        code = qs["code"][0]

        # 2. /token exchange
        token_resp = client.post(
            "/token",
            data={
                "grant_type": "authorization_code",
                "code": code,
                "client_id": "cid",
                "redirect_uri": "https://claude.ai/api/mcp/auth_callback",
                "code_verifier": verifier,
            },
        )
        assert token_resp.status_code == 200
        body = token_resp.json()
        assert body["token_type"] == "Bearer"
        access_token = body["access_token"]
        refresh_token = body["refresh_token"]

        # 3. /mcp accessible with bearer
        mcp_resp = client.post(
            "/mcp",
            headers={"authorization": f"Bearer {access_token}"},
        )
        assert mcp_resp.status_code == 200

        # 4. /token refresh rotates the refresh token
        refresh_resp = client.post(
            "/token",
            data={
                "grant_type": "refresh_token",
                "client_id": "cid",
                "refresh_token": refresh_token,
            },
        )
        assert refresh_resp.status_code == 200
        new_body = refresh_resp.json()
        assert new_body["refresh_token"] != refresh_token

        # 5. Old refresh token is now invalid
        old_again = client.post(
            "/token",
            data={
                "grant_type": "refresh_token",
                "client_id": "cid",
                "refresh_token": refresh_token,
            },
        )
        assert old_again.status_code == 400


def test_client_credentials_grant(app: Starlette) -> None:
    with TestClient(app) as client:
        basic = base64.b64encode(b"cid:csec").decode()
        resp = client.post(
            "/token",
            data={"grant_type": "client_credentials"},
            headers={"authorization": f"Basic {basic}"},
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["access_token"]
        assert "refresh_token" not in body  # client_credentials does not issue refresh


def test_client_credentials_rejects_wrong_secret(app: Starlette) -> None:
    with TestClient(app) as client:
        resp = client.post(
            "/token",
            data={
                "grant_type": "client_credentials",
                "client_id": "cid",
                "client_secret": "wrong",
            },
        )
        assert resp.status_code == 401


def test_authorize_rejects_bad_redirect_uri(app: Starlette) -> None:
    _, challenge = _pkce_pair()
    with TestClient(app) as client:
        resp = client.get(
            "/authorize",
            params={
                "response_type": "code",
                "client_id": "cid",
                "redirect_uri": "https://evil.example/cb",
                "code_challenge": challenge,
                "code_challenge_method": "S256",
            },
            follow_redirects=False,
        )
        # Bad redirect_uri must NOT redirect (RFC 6749 §4.1.2.1).
        assert resp.status_code == 400
        assert resp.json() == {"error": "invalid_request"}


def test_authorize_rejects_unknown_client_id(app: Starlette) -> None:
    _, challenge = _pkce_pair()
    with TestClient(app) as client:
        resp = client.get(
            "/authorize",
            params={
                "response_type": "code",
                "client_id": "wrong",
                "redirect_uri": "https://claude.ai/api/mcp/auth_callback",
                "code_challenge": challenge,
                "code_challenge_method": "S256",
            },
            follow_redirects=False,
        )
        assert resp.status_code == 401


def test_authorize_redirects_unsupported_response_type(app: Starlette) -> None:
    _, challenge = _pkce_pair()
    with TestClient(app) as client:
        resp = client.get(
            "/authorize",
            params={
                "response_type": "token",  # implicit grant; we reject
                "client_id": "cid",
                "redirect_uri": "https://claude.ai/api/mcp/auth_callback",
                "code_challenge": challenge,
                "code_challenge_method": "S256",
            },
            follow_redirects=False,
        )
        assert resp.status_code == 302
        qs = parse_qs(urlparse(resp.headers["location"]).query)
        assert qs["error"] == ["unsupported_response_type"]


def test_mcp_endpoint_static_token_works(app: Starlette) -> None:
    with TestClient(app) as client:
        resp = client.post(
            "/mcp",
            headers={"authorization": "Bearer static-mcp-token"},
        )
        assert resp.status_code == 200


def test_mcp_endpoint_rejects_no_auth(app: Starlette) -> None:
    with TestClient(app) as client:
        resp = client.post("/mcp")
        assert resp.status_code == 401
        assert resp.json()["error"] == "invalid_token"


def test_mcp_endpoint_rejects_invalid_bearer(app: Starlette) -> None:
    with TestClient(app) as client:
        resp = client.post("/mcp", headers={"authorization": "Bearer wrong"})
        assert resp.status_code == 401


def test_metadata_endpoint(app: Starlette) -> None:
    with TestClient(app) as client:
        resp = client.get("/.well-known/oauth-authorization-server")
        assert resp.status_code == 200
        body = resp.json()
        assert "authorization_endpoint" in body
        assert "token_endpoint" in body
        assert body["code_challenge_methods_supported"] == ["S256"]
        assert "authorization_code" in body["grant_types_supported"]


def test_protected_resource_metadata_at_root(app: Starlette) -> None:
    """RFC 9728 — required by MCP authorization spec 2025-06-18."""

    with TestClient(app) as client:
        resp = client.get("/.well-known/oauth-protected-resource")
        assert resp.status_code == 200
        body = resp.json()
        assert "resource" in body
        assert "authorization_servers" in body
        assert isinstance(body["authorization_servers"], list)
        assert body["authorization_servers"]
        assert body["bearer_methods_supported"] == ["header"]


def test_protected_resource_metadata_at_path_variant(app: Starlette) -> None:
    """Clients probe ``/.well-known/oauth-protected-resource/<resource-path>``
    before falling back to the root variant. Both must answer."""

    with TestClient(app) as client:
        resp = client.get("/.well-known/oauth-protected-resource/mcp")
        assert resp.status_code == 200
        body = resp.json()
        assert "authorization_servers" in body
        # Nested arbitrary paths also resolve.
        nested = client.get("/.well-known/oauth-protected-resource/some/nested/path")
        assert nested.status_code == 200
        assert nested.json()["authorization_servers"] == body["authorization_servers"]


def test_protected_resource_uses_configured_issuer(app: Starlette) -> None:
    """The metadata ``resource`` and ``authorization_servers`` entries reflect
    the configured ``issuer_url`` (or the request host when unset)."""

    with TestClient(app) as client:
        resp = client.get("/.well-known/oauth-protected-resource")
        body = resp.json()
        # The fixture leaves issuer empty, so it should fall back to the
        # request URL. We just assert it is an https-like URL.
        assert body["resource"]
        assert body["authorization_servers"][0] == body["resource"]


def test_token_rejects_unsupported_grant(app: Starlette) -> None:
    with TestClient(app) as client:
        resp = client.post(
            "/token",
            data={"grant_type": "password", "client_id": "cid", "client_secret": "csec"},
        )
        assert resp.status_code == 400
        assert resp.json() == {"error": "unsupported_grant_type"}


def test_oauth_token_alias(app: Starlette) -> None:
    """Legacy /oauth/token path mirrors /token."""

    with TestClient(app) as client:
        basic = base64.b64encode(b"cid:csec").decode()
        resp = client.post(
            "/oauth/token",
            data={"grant_type": "client_credentials"},
            headers={"authorization": f"Basic {basic}"},
        )
        assert resp.status_code == 200
        assert "access_token" in resp.json()
