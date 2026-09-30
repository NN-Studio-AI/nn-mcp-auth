"""Microsoft Entra ID login mode (OAUTH_ENTRA_TENANT_ID + CLIENT_ID + CLIENT_SECRET)."""

from __future__ import annotations

import asyncio
import base64
import hashlib
import secrets
import time
from collections.abc import Iterator
from typing import Any
from urllib.parse import parse_qs, urlparse

import fakeredis
import httpx
import jwt
import pytest
import respx
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route
from starlette.testclient import TestClient

from nn_mcp_auth import (
    BearerAuthMiddleware,
    ConfigurationError,
    EntraAuthError,
    EntraVerifier,
    MemoryOAuthStores,
    OAuthSettings,
    OAuthStores,
    RedisOAuthStores,
    build_oauth_endpoints,
    get_subject,
    load_oauth_settings,
)
from nn_mcp_auth.login_page import (
    MSG_ENTRA_FAILED,
    MSG_ENTRA_NOT_ALLOWED,
    MSG_REQUEST_EXPIRED,
)
from nn_mcp_auth.storage.redis import RedisAccessTokenStore

TENANT = "11111111-2222-4333-8444-555555555555"
ENTRA_CLIENT_ID = "entra-app-id"
ISSUER = "https://mcp.example.com"
CALLBACK = f"{ISSUER}/oauth/entra/callback"
CHATGPT_REDIRECT = "https://chatgpt.com/connector_platform_oauth_redirect"
AUTHORITY = f"https://login.microsoftonline.com/{TENANT}"
AUTHORIZE_URL = f"{AUTHORITY}/oauth2/v2.0/authorize"
TOKEN_URL = f"{AUTHORITY}/oauth2/v2.0/token"
JWKS_URL = f"{AUTHORITY}/discovery/v2.0/keys"
ENTRA_ISSUER = f"{AUTHORITY}/v2.0"
KID = "kid-2026"


@pytest.fixture(scope="module")
def rsa_key() -> RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _jwks(key: RSAPrivateKey, *kids: str) -> dict[str, Any]:
    numbers = key.public_key().public_numbers()
    n = numbers.n.to_bytes((numbers.n.bit_length() + 7) // 8, "big")
    e = numbers.e.to_bytes((numbers.e.bit_length() + 7) // 8, "big")
    return {
        "keys": [
            {"kty": "RSA", "use": "sig", "kid": kid, "n": _b64url(n), "e": _b64url(e)}
            for kid in (kids or (KID,))
        ]
    }


def _id_token(key: RSAPrivateKey, *, nonce: str, kid: str = KID, **overrides: Any) -> str:
    now = int(time.time())
    claims: dict[str, Any] = {
        "iss": ENTRA_ISSUER,
        "aud": ENTRA_CLIENT_ID,
        "sub": "sub-1",
        "oid": "oid-1",
        "tid": TENANT,
        "nonce": nonce,
        "preferred_username": "Caio@NNStudio.ai",
        "name": "Caio",
        "iat": now,
        "nbf": now,
        "exp": now + 600,
    }
    claims.update(overrides)
    claims = {k: v for k, v in claims.items() if v is not None}
    return jwt.encode(claims, key, algorithm="RS256", headers={"kid": kid})


def _pkce_pair() -> tuple[str, str]:
    verifier = secrets.token_urlsafe(64)[:64]
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    return verifier, base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def _settings(**overrides: Any) -> OAuthSettings:
    base: dict[str, Any] = {
        "client_id": "cid",
        "client_secret": "csec",
        "issuer_url": ISSUER,
        "entra_tenant_id": TENANT,
        "entra_client_id": ENTRA_CLIENT_ID,
        "entra_client_secret": "entra-secret",
        "entra_allowed_upns": ("caio@nnstudio.ai",),
    }
    base.update(overrides)
    return OAuthSettings(**base)


def _build_app(settings: OAuthSettings, stores: OAuthStores) -> Starlette:
    async def whoami(request: Request) -> JSONResponse:
        return JSONResponse({"subject": get_subject(request)})

    app = Starlette(routes=[Route("/mcp", whoami, methods=["POST"])])
    build_oauth_endpoints(app, settings=settings, stores=stores)
    app.add_middleware(
        BearerAuthMiddleware,
        token="static-mcp-token",
        protected_paths={"/mcp"},
        oauth_store=stores.access,
    )
    return app


@pytest.fixture(params=["memory", "redis"])
def stores(request: pytest.FixtureRequest) -> OAuthStores:
    if request.param == "memory":
        return MemoryOAuthStores.create()
    client = fakeredis.FakeRedis(decode_responses=True, version=(6, 2, 0))
    return RedisOAuthStores.from_client(client, prefix="mcp:test")


@pytest.fixture
def client(stores: OAuthStores) -> Iterator[TestClient]:
    with TestClient(_build_app(_settings(), stores)) as c:
        yield c


def _start(client: TestClient, *, challenge: str | None = None) -> tuple[str, str, httpx.Response]:
    """GET /authorize → (state sent to Entra, nonce, response)."""

    if challenge is None:
        _, challenge = _pkce_pair()
    resp = client.get(
        "/authorize",
        params={
            "response_type": "code",
            "client_id": "cid",
            "redirect_uri": CHATGPT_REDIRECT,
            "code_challenge": challenge,
            "code_challenge_method": "S256",
            "state": "st-1",
        },
        follow_redirects=False,
    )
    assert resp.status_code == 302
    query = parse_qs(urlparse(resp.headers["location"]).query)
    return query["state"][0], query["nonce"][0], resp


def _mock_entra(key: RSAPrivateKey, *, id_token: str | None, token_status: int = 200) -> None:
    respx.get(JWKS_URL).mock(return_value=httpx.Response(200, json=_jwks(key)))
    body: dict[str, Any] = {"token_type": "Bearer", "scope": "openid profile email"}
    if id_token is not None:
        body["id_token"] = id_token
    if token_status != 200:
        body = {"error": "invalid_grant", "error_description": "AADSTS70000: nope"}
    respx.post(TOKEN_URL).mock(return_value=httpx.Response(token_status, json=body))


def _callback(client: TestClient, state: str, code: str = "entra-code") -> httpx.Response:
    return client.get(
        "/oauth/entra/callback", params={"code": code, "state": state}, follow_redirects=False
    )


# --------------------------------------------------------------------------- #
# GET /authorize
# --------------------------------------------------------------------------- #


def test_authorize_redirects_to_entra(client: TestClient) -> None:
    _, challenge = _pkce_pair()
    state, nonce, resp = _start(client, challenge=challenge)
    location = resp.headers["location"]
    assert location.startswith(AUTHORIZE_URL + "?")
    query = parse_qs(urlparse(location).query)
    assert query["client_id"] == [ENTRA_CLIENT_ID]
    assert query["response_type"] == ["code"]
    assert query["redirect_uri"] == [CALLBACK]
    assert "openid" in query["scope"][0]
    assert len(state) >= 32 and len(nonce) >= 32
    # Browser SSO must be able to kick in: never force a fresh login prompt.
    assert "prompt" not in query
    assert resp.headers["cache-control"] == "no-store"


def test_password_form_is_not_mounted_in_entra_mode(client: TestClient) -> None:
    resp = client.post("/authorize", data={"request_id": "x", "username": "a", "password": "b"})
    assert resp.status_code == 405


def test_metadata_advertises_iss_in_entra_mode(client: TestClient) -> None:
    metadata = client.get("/.well-known/oauth-authorization-server").json()
    assert metadata["authorization_response_iss_parameter_supported"] is True
    assert metadata["code_challenge_methods_supported"] == ["S256"]


# --------------------------------------------------------------------------- #
# Full flow
# --------------------------------------------------------------------------- #


@respx.mock
def test_full_login_binds_identity_to_tokens(client: TestClient, rsa_key: RSAPrivateKey) -> None:
    verifier, challenge = _pkce_pair()
    state, nonce, _ = _start(client, challenge=challenge)
    _mock_entra(rsa_key, id_token=_id_token(rsa_key, nonce=nonce))

    resp = _callback(client, state, code="entra-code-123")
    assert resp.status_code == 302, resp.text
    assert resp.headers["cache-control"] == "no-store"
    redirect = urlparse(resp.headers["location"])
    assert f"{redirect.scheme}://{redirect.netloc}{redirect.path}" == CHATGPT_REDIRECT
    query = parse_qs(redirect.query)
    assert query["state"] == ["st-1"]
    assert query["iss"] == [ISSUER]
    code = query["code"][0]

    # The exchange happened server-side with the client secret, never in the browser.
    token_call = respx.post(TOKEN_URL).calls.last
    form = parse_qs(token_call.request.content.decode())
    assert form["grant_type"] == ["authorization_code"]
    assert form["code"] == ["entra-code-123"]
    assert form["redirect_uri"] == [CALLBACK]
    assert form["client_id"] == [ENTRA_CLIENT_ID]
    assert form["client_secret"] == ["entra-secret"]

    token = client.post(
        "/token",
        data={
            "grant_type": "authorization_code",
            "client_id": "cid",
            "code": code,
            "redirect_uri": CHATGPT_REDIRECT,
            "code_verifier": verifier,
        },
    )
    assert token.status_code == 200, token.text
    body = token.json()
    access_token = body["access_token"]
    refresh_token = body["refresh_token"]

    who = client.post("/mcp", headers={"Authorization": f"Bearer {access_token}"})
    assert who.status_code == 200
    assert who.json() == {"subject": "caio@nnstudio.ai"}

    refreshed = client.post(
        "/token",
        data={"grant_type": "refresh_token", "client_id": "cid", "refresh_token": refresh_token},
    )
    assert refreshed.status_code == 200, refreshed.text
    new_access = refreshed.json()["access_token"]
    who_again = client.post("/mcp", headers={"Authorization": f"Bearer {new_access}"})
    assert who_again.json() == {"subject": "caio@nnstudio.ai"}

    # The refresh token rotated: the old one is dead.
    replay = client.post(
        "/token",
        data={"grant_type": "refresh_token", "client_id": "cid", "refresh_token": refresh_token},
    )
    assert replay.status_code == 400

    # The Entra state is single-use.
    again = _callback(client, state)
    assert again.status_code == 400
    assert MSG_REQUEST_EXPIRED in again.text


def test_client_credentials_stay_anonymous(client: TestClient) -> None:
    token = client.post(
        "/token",
        data={"grant_type": "client_credentials", "client_id": "cid", "client_secret": "csec"},
    )
    assert token.status_code == 200
    who = client.post("/mcp", headers={"Authorization": f"Bearer {token.json()['access_token']}"})
    assert who.json() == {"subject": None}


@respx.mock
def test_without_allowlist_any_tenant_user_passes(
    stores: OAuthStores, rsa_key: RSAPrivateKey
) -> None:
    with TestClient(_build_app(_settings(entra_allowed_upns=()), stores)) as client:
        state, nonce, _ = _start(client)
        _mock_entra(
            rsa_key,
            id_token=_id_token(rsa_key, nonce=nonce, preferred_username="alguem@nnstudio.ai"),
        )
        resp = _callback(client, state)
        assert resp.status_code == 302, resp.text


@respx.mock
def test_identity_falls_back_to_oid_without_upn(
    stores: OAuthStores, rsa_key: RSAPrivateKey
) -> None:
    with TestClient(_build_app(_settings(entra_allowed_upns=()), stores)) as client:
        verifier, challenge = _pkce_pair()
        state, nonce, _ = _start(client, challenge=challenge)
        _mock_entra(
            rsa_key,
            id_token=_id_token(rsa_key, nonce=nonce, preferred_username=None, oid="OID-9"),
        )
        resp = _callback(client, state)
        assert resp.status_code == 302, resp.text
        code = parse_qs(urlparse(resp.headers["location"]).query)["code"][0]
        token = client.post(
            "/token",
            data={
                "grant_type": "authorization_code",
                "client_id": "cid",
                "code": code,
                "redirect_uri": CHATGPT_REDIRECT,
                "code_verifier": verifier,
            },
        ).json()
        who = client.post("/mcp", headers={"Authorization": f"Bearer {token['access_token']}"})
        assert who.json() == {"subject": "oid-9"}


# --------------------------------------------------------------------------- #
# Failures never redirect to the client
# --------------------------------------------------------------------------- #


def _assert_failed_page(resp: httpx.Response, status: int, message: str) -> None:
    assert resp.status_code == status, resp.text
    assert "location" not in resp.headers
    assert resp.headers["content-type"].startswith("text/html")
    assert message in resp.text
    assert "<form" not in resp.text
    assert "default-src 'none'" in resp.headers["content-security-policy"]


@respx.mock
@pytest.mark.parametrize(
    "overrides",
    [
        pytest.param({"nonce": "other-nonce"}, id="nonce-mismatch"),
        pytest.param({"nonce": None}, id="nonce-missing"),
        pytest.param({"aud": "another-app"}, id="wrong-audience"),
        pytest.param({"iss": "https://login.microsoftonline.com/common/v2.0"}, id="wrong-issuer"),
        pytest.param({"tid": "99999999-2222-4333-8444-555555555555"}, id="wrong-tenant"),
        pytest.param({"exp": int(time.time()) - 3600}, id="expired"),
        pytest.param({"kid": "unknown-kid"}, id="unknown-signing-key"),
    ],
)
def test_invalid_id_token_is_rejected(
    client: TestClient, rsa_key: RSAPrivateKey, overrides: dict[str, Any]
) -> None:
    state, nonce, _ = _start(client)
    token_kwargs: dict[str, Any] = {"nonce": nonce}
    token_kwargs.update(overrides)
    _mock_entra(rsa_key, id_token=_id_token(rsa_key, **token_kwargs))
    _assert_failed_page(_callback(client, state), 401, MSG_ENTRA_FAILED)
    # The pending request was consumed: a retry with the same state is refused.
    _assert_failed_page(_callback(client, state), 400, MSG_REQUEST_EXPIRED)


@respx.mock
def test_token_signed_by_another_key_is_rejected(
    client: TestClient, rsa_key: RSAPrivateKey
) -> None:
    state, nonce, _ = _start(client)
    other_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    _mock_entra(rsa_key, id_token=_id_token(other_key, nonce=nonce))
    _assert_failed_page(_callback(client, state), 401, MSG_ENTRA_FAILED)


@respx.mock
def test_user_outside_allowlist_is_forbidden(client: TestClient, rsa_key: RSAPrivateKey) -> None:
    state, nonce, _ = _start(client)
    _mock_entra(
        rsa_key,
        id_token=_id_token(rsa_key, nonce=nonce, preferred_username="intruso@nnstudio.ai"),
    )
    _assert_failed_page(_callback(client, state), 403, MSG_ENTRA_NOT_ALLOWED)


@respx.mock
def test_token_exchange_rejected_by_entra(client: TestClient, rsa_key: RSAPrivateKey) -> None:
    state, _, _ = _start(client)
    _mock_entra(rsa_key, id_token=None, token_status=400)
    _assert_failed_page(_callback(client, state), 401, MSG_ENTRA_FAILED)


@respx.mock
def test_token_response_without_id_token(client: TestClient, rsa_key: RSAPrivateKey) -> None:
    state, _, _ = _start(client)
    _mock_entra(rsa_key, id_token=None)
    _assert_failed_page(_callback(client, state), 401, MSG_ENTRA_FAILED)


@respx.mock
def test_token_endpoint_unreachable(client: TestClient, rsa_key: RSAPrivateKey) -> None:
    state, _, _ = _start(client)
    respx.post(TOKEN_URL).mock(side_effect=httpx.ConnectError("boom"))
    _assert_failed_page(_callback(client, state), 401, MSG_ENTRA_FAILED)


def test_entra_error_parameter(client: TestClient) -> None:
    state, _, _ = _start(client)
    resp = client.get(
        "/oauth/entra/callback",
        params={"error": "access_denied", "error_description": "user cancelled", "state": state},
        follow_redirects=False,
    )
    _assert_failed_page(resp, 401, MSG_ENTRA_FAILED)


def test_unknown_or_missing_state(client: TestClient) -> None:
    _assert_failed_page(_callback(client, "does-not-exist"), 400, MSG_REQUEST_EXPIRED)
    resp = client.get("/oauth/entra/callback", params={"code": "x"}, follow_redirects=False)
    _assert_failed_page(resp, 400, MSG_REQUEST_EXPIRED)


# --------------------------------------------------------------------------- #
# EntraVerifier — JWKS cache
# --------------------------------------------------------------------------- #


def test_jwks_refetch_on_key_rotation_is_rate_limited(rsa_key: RSAPrivateKey) -> None:
    now = [1000.0]
    verifier = EntraVerifier(_settings(), clock=lambda: now[0])

    with respx.mock:
        jwks_route = respx.get(JWKS_URL).mock(
            return_value=httpx.Response(200, json=_jwks(rsa_key, "kid-old"))
        )
        old = _id_token(rsa_key, nonce="n1", kid="kid-old")
        identity = asyncio.run(verifier.verify_id_token(old, nonce="n1"))
        assert identity.subject == "caio@nnstudio.ai"
        assert identity.name == "Caio" and identity.tenant_id == TENANT
        assert jwks_route.call_count == 1

        # Entra rotated: the new kid is unknown and the last fetch was 1 s ago → no refetch.
        jwks_route.mock(return_value=httpx.Response(200, json=_jwks(rsa_key, "kid-new")))
        new = _id_token(rsa_key, nonce="n2", kid="kid-new")
        now[0] += 1
        with pytest.raises(EntraAuthError) as excinfo:
            asyncio.run(verifier.verify_id_token(new, nonce="n2"))
        assert excinfo.value.reason == "signing_key_unknown"
        assert jwks_route.call_count == 1

        # After the minimum interval the keys are refetched and the token validates.
        now[0] += 30
        assert asyncio.run(verifier.verify_id_token(new, nonce="n2")).oid == "oid-1"
        assert jwks_route.call_count == 2


def test_jwks_outage_keeps_cached_keys(rsa_key: RSAPrivateKey) -> None:
    now = [1000.0]
    verifier = EntraVerifier(_settings(), clock=lambda: now[0])
    with respx.mock:
        jwks_route = respx.get(JWKS_URL).mock(return_value=httpx.Response(200, json=_jwks(rsa_key)))
        asyncio.run(verifier.verify_id_token(_id_token(rsa_key, nonce="n"), nonce="n"))
        # Cache is stale and Entra is down: keep validating with the cached key.
        jwks_route.mock(return_value=httpx.Response(503, text="down"))
        now[0] += 3601
        asyncio.run(verifier.verify_id_token(_id_token(rsa_key, nonce="n"), nonce="n"))
        assert jwks_route.call_count == 2


def test_jwks_unreachable_without_cache_fails(rsa_key: RSAPrivateKey) -> None:
    verifier = EntraVerifier(_settings())
    with respx.mock:
        respx.get(JWKS_URL).mock(side_effect=httpx.ConnectError("down"))
        with pytest.raises(EntraAuthError) as excinfo:
            asyncio.run(verifier.verify_id_token(_id_token(rsa_key, nonce="n"), nonce="n"))
        assert excinfo.value.reason == "jwks_unreachable"


def test_malformed_id_token(rsa_key: RSAPrivateKey) -> None:
    verifier = EntraVerifier(_settings())
    with pytest.raises(EntraAuthError) as excinfo:
        asyncio.run(verifier.verify_id_token("not-a-jwt", nonce="n"))
    assert excinfo.value.reason == "id_token_malformed"


# --------------------------------------------------------------------------- #
# Settings
# --------------------------------------------------------------------------- #


def _env(**extra: str) -> dict[str, str]:
    env = {"OAUTH_CLIENT_ID": "cid", "OAUTH_CLIENT_SECRET": "csec"}
    env.update(extra)
    return env


def test_load_settings_enables_entra_mode() -> None:
    settings = load_oauth_settings(
        _env(
            OAUTH_ENTRA_TENANT_ID=TENANT.upper(),
            OAUTH_ENTRA_CLIENT_ID=ENTRA_CLIENT_ID,
            OAUTH_ENTRA_CLIENT_SECRET="sup3r-secret-value",
            OAUTH_ENTRA_ALLOWED_UPNS=" Caio@NNStudio.ai, outro@nnstudio.ai ,caio@nnstudio.ai,",
        )
    )
    assert settings.entra_enabled and settings.login_enabled
    assert settings.login_mode == "entra"
    assert settings.entra_tenant_id == TENANT
    assert settings.entra_allowed_upns == ("caio@nnstudio.ai", "outro@nnstudio.ai")
    assert settings.is_upn_allowed("CAIO@nnstudio.ai")
    assert not settings.is_upn_allowed("x@nnstudio.ai", None)
    assert "sup3r-secret-value" not in repr(settings)
    assert "entra_client_secret" not in repr(settings)


def test_entra_takes_precedence_over_password() -> None:
    settings = load_oauth_settings(
        _env(
            OAUTH_ENTRA_TENANT_ID=TENANT,
            OAUTH_ENTRA_CLIENT_ID=ENTRA_CLIENT_ID,
            OAUTH_ENTRA_CLIENT_SECRET="s",
            OAUTH_LOGIN_USERNAME="u",
            OAUTH_LOGIN_PASSWORD="p",
        )
    )
    assert settings.login_mode == "entra"
    assert settings.password_login_enabled  # still configured, just not used by /authorize


def test_password_mode_and_none_mode() -> None:
    assert load_oauth_settings(_env()).login_mode == "none"
    password = load_oauth_settings(_env(OAUTH_LOGIN_USERNAME="u", OAUTH_LOGIN_PASSWORD="p"))
    assert password.login_mode == "password" and not password.entra_enabled


@pytest.mark.parametrize(
    "extra",
    [
        {"OAUTH_ENTRA_TENANT_ID": TENANT},
        {"OAUTH_ENTRA_TENANT_ID": TENANT, "OAUTH_ENTRA_CLIENT_ID": "x"},
        {"OAUTH_ENTRA_CLIENT_SECRET": "x"},
    ],
)
def test_partial_entra_config_is_rejected(extra: dict[str, str]) -> None:
    with pytest.raises(ConfigurationError, match="partially configured"):
        load_oauth_settings(_env(**extra))


def test_tenant_must_be_a_guid() -> None:
    with pytest.raises(ConfigurationError, match="GUID"):
        load_oauth_settings(
            _env(
                OAUTH_ENTRA_TENANT_ID="nnstudio.ai",
                OAUTH_ENTRA_CLIENT_ID="x",
                OAUTH_ENTRA_CLIENT_SECRET="y",
            )
        )


def test_allowlist_without_entra_is_rejected() -> None:
    with pytest.raises(ConfigurationError, match="only applies"):
        load_oauth_settings(_env(OAUTH_ENTRA_ALLOWED_UPNS="a@b.c"))


def test_allowlist_only_separators_is_rejected() -> None:
    with pytest.raises(ConfigurationError, match="comma-separated"):
        load_oauth_settings(
            _env(
                OAUTH_ENTRA_TENANT_ID=TENANT,
                OAUTH_ENTRA_CLIENT_ID="x",
                OAUTH_ENTRA_CLIENT_SECRET="y",
                OAUTH_ENTRA_ALLOWED_UPNS=" , ,",
            )
        )


# --------------------------------------------------------------------------- #
# Storage compatibility
# --------------------------------------------------------------------------- #


def test_redis_legacy_anonymous_tokens_stay_valid() -> None:
    client = fakeredis.FakeRedis(decode_responses=True, version=(6, 2, 0))
    store = RedisAccessTokenStore(client, prefix="mcp:test")
    client.set("mcp:test:access:legacy", "1", ex=60)
    assert store.is_valid("legacy")
    assert store.subject_of("legacy") is None
    token, _ = store.issue(subject="caio@nnstudio.ai")
    assert store.subject_of(token) == "caio@nnstudio.ai"
    assert store.subject_of("missing") is None
