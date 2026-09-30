"""/authorize login page (OAUTH_LOGIN_USERNAME + OAUTH_LOGIN_PASSWORD)."""

from __future__ import annotations

import base64
import hashlib
import re
import secrets
from collections.abc import Iterator
from urllib.parse import parse_qs, urlparse

import fakeredis
import httpx
import pytest
from starlette.applications import Starlette
from starlette.responses import JSONResponse
from starlette.routing import Route
from starlette.testclient import TestClient

from nn_mcp_auth import (
    BearerAuthMiddleware,
    MemoryOAuthStores,
    OAuthSettings,
    OAuthStores,
    RedisOAuthStores,
    build_oauth_endpoints,
    hash_login_password,
)
from nn_mcp_auth.oauth import DEFAULT_ALLOWED_REDIRECT_URIS
from nn_mcp_auth.storage.memory import (
    MemoryAccessTokenStore,
    MemoryAuthCodeStore,
    MemoryRefreshTokenStore,
)

CHATGPT_REDIRECT = "https://chatgpt.com/connector_platform_oauth_redirect"
CLAUDE_REDIRECT = "https://claude.ai/api/mcp/auth_callback"
ISSUER = "https://mcp.example.com"


def _pkce_pair() -> tuple[str, str]:
    verifier = secrets.token_urlsafe(64)[:64]
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
    return verifier, challenge


def _build_app(settings: OAuthSettings, stores: OAuthStores) -> Starlette:
    async def mcp_endpoint(_):  # type: ignore[no-untyped-def]
        return JSONResponse({"ok": True})

    app = Starlette(routes=[Route("/mcp", mcp_endpoint, methods=["POST"])])
    build_oauth_endpoints(app, settings=settings, stores=stores)
    app.add_middleware(
        BearerAuthMiddleware,
        token="static-mcp-token",
        protected_paths={"/mcp"},
        oauth_store=stores.access,
    )
    return app


def _login_settings(password: str = "s3nha") -> OAuthSettings:
    return OAuthSettings(
        client_id="cid",
        client_secret="csec",
        issuer_url=ISSUER,
        login_username="caio",
        login_password=password,
    )


@pytest.fixture(params=["memory", "redis"])
def stores(request: pytest.FixtureRequest) -> OAuthStores:
    if request.param == "memory":
        return MemoryOAuthStores.create()
    client = fakeredis.FakeRedis(decode_responses=True, version=(6, 2, 0))
    return RedisOAuthStores.from_client(client, prefix="mcp:test")


@pytest.fixture
def client(stores: OAuthStores) -> Iterator[TestClient]:
    app = _build_app(_login_settings(hash_login_password("s3nha")), stores)
    with TestClient(app) as c:
        yield c


def _authorize(
    client: TestClient, challenge: str, *, redirect_uri: str = CHATGPT_REDIRECT, state: str = "st-1"
) -> httpx.Response:
    return client.get(
        "/authorize",
        params={
            "response_type": "code",
            "client_id": "cid",
            "redirect_uri": redirect_uri,
            "code_challenge": challenge,
            "code_challenge_method": "S256",
            "state": state,
        },
        follow_redirects=False,
    )


def _request_id(html: str) -> str:
    match = re.search(r'name="request_id" value="([^"]+)"', html)
    assert match, "login form must carry request_id"
    return match.group(1)


def _submit(client: TestClient, request_id: str, username: str, password: str) -> httpx.Response:
    return client.post(
        "/authorize",
        data={"request_id": request_id, "username": username, "password": password},
        follow_redirects=False,
    )


def test_get_authorize_renders_login_page(client: TestClient) -> None:
    _, challenge = _pkce_pair()
    resp = _authorize(client, challenge)
    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("text/html")
    html = resp.text
    assert '<html lang="pt-BR">' in html
    assert "Usuário" in html and "Senha" in html
    assert 'method="post"' in html and 'action="/authorize"' in html
    assert 'name="username"' in html and 'name="password"' in html
    assert "chatgpt.com" in html
    # No JavaScript and no external assets.
    assert "<script" not in html.lower()
    assert "http://" not in html and "src=" not in html and "<link" not in html
    _request_id(html)


def test_login_page_security_headers(client: TestClient) -> None:
    _, challenge = _pkce_pair()
    resp = _authorize(client, challenge)
    csp = resp.headers["content-security-policy"]
    assert "default-src 'none'" in csp
    assert "style-src 'unsafe-inline'" in csp
    # 'self' for the form POST + the client's origin for the redirect that follows it.
    assert "form-action 'self' https://chatgpt.com" in csp
    assert "frame-ancestors 'none'" in csp
    assert "script-src" not in csp
    assert resp.headers["x-frame-options"] == "DENY"
    assert resp.headers["cache-control"] == "no-store"


def test_login_success_redirects_with_code_state_and_iss(client: TestClient) -> None:
    verifier, challenge = _pkce_pair()
    page = _authorize(client, challenge, state="xyz")
    resp = _submit(client, _request_id(page.text), "caio", "s3nha")
    assert resp.status_code == 302
    location = urlparse(resp.headers["location"])
    assert f"{location.scheme}://{location.netloc}{location.path}" == CHATGPT_REDIRECT
    qs = parse_qs(location.query)
    assert qs["state"] == ["xyz"]
    assert qs["iss"] == [ISSUER]
    code = qs["code"][0]

    token = client.post(
        "/token",
        data={
            "grant_type": "authorization_code",
            "code": code,
            "client_id": "cid",
            "redirect_uri": CHATGPT_REDIRECT,
            "code_verifier": verifier,
        },
    )
    assert token.status_code == 200
    access = token.json()["access_token"]
    assert client.post("/mcp", headers={"authorization": f"Bearer {access}"}).status_code == 200


def test_login_wrong_password_returns_401_generic_message(client: TestClient) -> None:
    _, challenge = _pkce_pair()
    page = _authorize(client, challenge)
    request_id = _request_id(page.text)
    for username, password in (("caio", "errada"), ("outro", "s3nha"), ("", "")):
        resp = _submit(client, request_id, username, password)
        assert resp.status_code == 401
        assert "Usuário ou senha inválidos" in resp.text
        assert "location" not in resp.headers
        assert resp.headers["x-frame-options"] == "DENY"
        # The form is re-rendered with the same (still valid) request.
        assert _request_id(resp.text) == request_id

    # The request survives failed attempts: the right password still works.
    ok = _submit(client, request_id, "caio", "s3nha")
    assert ok.status_code == 302


def test_request_id_is_single_use(client: TestClient) -> None:
    _, challenge = _pkce_pair()
    request_id = _request_id(_authorize(client, challenge).text)
    assert _submit(client, request_id, "caio", "s3nha").status_code == 302
    again = _submit(client, request_id, "caio", "s3nha")
    assert again.status_code == 400
    assert "expirou ou já foi usada" in again.text
    assert 'name="request_id"' not in again.text


def test_unknown_request_id_is_rejected(client: TestClient) -> None:
    resp = _submit(client, "nao-existe", "caio", "s3nha")
    assert resp.status_code == 400
    assert "location" not in resp.headers


def test_rate_limit_blocks_after_ten_attempts(client: TestClient) -> None:
    _, challenge = _pkce_pair()
    request_id = _request_id(_authorize(client, challenge).text)
    for _ in range(10):
        assert _submit(client, request_id, "caio", "errada").status_code == 401
    blocked = _submit(client, request_id, "caio", "s3nha")
    assert blocked.status_code == 429
    assert "Muitas tentativas" in blocked.text
    assert int(blocked.headers["retry-after"]) > 0
    assert blocked.headers["content-security-policy"].startswith("default-src 'none'")
    assert "location" not in blocked.headers


def test_rate_limit_window_resets() -> None:
    stores = MemoryOAuthStores.create()
    now = [1000.0]
    assert stores.login_limiter is not None
    stores.login_limiter._clock = lambda: now[0]  # type: ignore[attr-defined]
    app = _build_app(_login_settings(), stores)
    with TestClient(app) as client:
        _, challenge = _pkce_pair()
        request_id = _request_id(_authorize(client, challenge).text)
        for _ in range(10):
            _submit(client, request_id, "caio", "errada")
        assert _submit(client, request_id, "caio", "s3nha").status_code == 429
        now[0] += 601
        assert _submit(client, request_id, "caio", "s3nha").status_code == 302


def test_plain_text_password_config_works() -> None:
    app = _build_app(_login_settings("texto-puro"), MemoryOAuthStores.create())
    with TestClient(app) as client:
        _, challenge = _pkce_pair()
        request_id = _request_id(_authorize(client, challenge).text)
        assert _submit(client, request_id, "caio", "texto-errado").status_code == 401
        assert _submit(client, request_id, "caio", "texto-puro").status_code == 302


def test_pending_request_expires() -> None:
    stores = MemoryOAuthStores.create()
    now = [50.0]
    assert stores.pending is not None
    stores.pending._clock = lambda: now[0]  # type: ignore[attr-defined]
    app = _build_app(_login_settings(), stores)
    with TestClient(app) as client:
        _, challenge = _pkce_pair()
        request_id = _request_id(_authorize(client, challenge).text)
        now[0] += 601
        resp = _submit(client, request_id, "caio", "s3nha")
        assert resp.status_code == 400


def test_login_mode_still_validates_client_and_redirect(client: TestClient) -> None:
    _, challenge = _pkce_pair()
    bad_redirect = _authorize(client, challenge, redirect_uri="https://evil.example/cb")
    assert bad_redirect.status_code == 400
    assert bad_redirect.json() == {"error": "invalid_request"}

    no_pkce = client.get(
        "/authorize",
        params={"response_type": "code", "client_id": "cid", "redirect_uri": CHATGPT_REDIRECT},
        follow_redirects=False,
    )
    assert no_pkce.status_code == 302
    qs = parse_qs(urlparse(no_pkce.headers["location"]).query)
    assert qs["error"] == ["invalid_request"]
    assert qs["iss"] == [ISSUER]


def test_client_credentials_never_needs_login(client: TestClient) -> None:
    basic = base64.b64encode(b"cid:csec").decode()
    resp = client.post(
        "/token",
        data={"grant_type": "client_credentials"},
        headers={"authorization": f"Basic {basic}"},
    )
    assert resp.status_code == 200
    assert "access_token" in resp.json()


def test_metadata_advertises_iss_only_in_login_mode(client: TestClient) -> None:
    body = client.get("/.well-known/oauth-authorization-server").json()
    assert body["authorization_response_iss_parameter_supported"] is True

    legacy = _build_app(
        OAuthSettings(client_id="cid", client_secret="csec"), MemoryOAuthStores.create()
    )
    with TestClient(legacy) as legacy_client:
        legacy_body = legacy_client.get("/.well-known/oauth-authorization-server").json()
    assert "authorization_response_iss_parameter_supported" not in legacy_body


def test_login_works_with_hand_built_stores_without_login_stores() -> None:
    """``OAuthStores(access, refresh, code)`` built by hand keeps working (memory fallback)."""

    stores = OAuthStores(
        access=MemoryAccessTokenStore(),
        refresh=MemoryRefreshTokenStore(),
        code=MemoryAuthCodeStore(),
    )
    app = _build_app(_login_settings(), stores)
    with TestClient(app) as client:
        _, challenge = _pkce_pair()
        request_id = _request_id(_authorize(client, challenge).text)
        assert _submit(client, request_id, "caio", "s3nha").status_code == 302


# --- login disabled: legacy behavior must be intact -------------------------


@pytest.fixture
def legacy_client() -> Iterator[TestClient]:
    settings = OAuthSettings(client_id="cid", client_secret="csec")
    app = _build_app(settings, MemoryOAuthStores.create())
    with TestClient(app) as c:
        yield c


def test_login_disabled_get_authorize_auto_approves_without_iss(legacy_client: TestClient) -> None:
    _, challenge = _pkce_pair()
    resp = _authorize(legacy_client, challenge, redirect_uri=CLAUDE_REDIRECT, state="abc")
    assert resp.status_code == 302
    qs = parse_qs(urlparse(resp.headers["location"]).query)
    assert set(qs) == {"code", "state"}
    assert qs["state"] == ["abc"]


def test_login_disabled_post_authorize_is_not_mounted(legacy_client: TestClient) -> None:
    resp = legacy_client.post(
        "/authorize",
        data={"request_id": "x", "username": "caio", "password": "s3nha"},
        follow_redirects=False,
    )
    assert resp.status_code == 405


def test_new_chatgpt_redirect_uris_are_allowed_by_default(legacy_client: TestClient) -> None:
    assert "https://chatgpt.com/connector_platform_oauth_redirect" in DEFAULT_ALLOWED_REDIRECT_URIS
    assert (
        "https://chat.openai.com/connector_platform_oauth_redirect" in DEFAULT_ALLOWED_REDIRECT_URIS
    )
    assert CLAUDE_REDIRECT in DEFAULT_ALLOWED_REDIRECT_URIS
    assert "https://claude.com/api/mcp/auth_callback" in DEFAULT_ALLOWED_REDIRECT_URIS
    for redirect in (
        "https://chatgpt.com/connector_platform_oauth_redirect",
        "https://chat.openai.com/connector_platform_oauth_redirect",
    ):
        _, challenge = _pkce_pair()
        resp = _authorize(legacy_client, challenge, redirect_uri=redirect)
        assert resp.status_code == 302
        assert resp.headers["location"].startswith(redirect + "?")


def test_openid_configuration_alias_matches_rfc8414(legacy_client: TestClient) -> None:
    rfc8414 = legacy_client.get("/.well-known/oauth-authorization-server")
    oidc = legacy_client.get("/.well-known/openid-configuration")
    assert oidc.status_code == 200
    assert oidc.json() == rfc8414.json()
    body = oidc.json()
    assert body["code_challenge_methods_supported"] == ["S256"]
    assert body["token_endpoint_auth_methods_supported"] == [
        "client_secret_basic",
        "client_secret_post",
    ]
