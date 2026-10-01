"""Client ID Metadata Documents: clients identified by an HTTPS URL (e.g. ChatGPT)."""

from __future__ import annotations

import asyncio
import base64
import hashlib
import re
import secrets
import time
import uuid
from collections.abc import Iterator
from typing import Any
from urllib.parse import parse_qs, urlparse

import fakeredis
import httpx
import jwt
import pytest
import respx
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route
from starlette.testclient import TestClient

from nn_mcp_auth import (
    BearerAuthMiddleware,
    ClientMetadataError,
    ClientMetadataResolver,
    ConfigurationError,
    MemoryOAuthStores,
    OAuthSettings,
    OAuthStores,
    RedisOAuthStores,
    build_oauth_endpoints,
    get_subject,
    hash_login_password,
    load_oauth_settings,
    validate_client_id_url,
)
from nn_mcp_auth.cimd import (
    CIMD_MAX_DOCUMENT_BYTES,
    CLIENT_ASSERTION_TYPE_JWT_BEARER,
    parse_client_metadata,
)
from nn_mcp_auth.storage.memory import MemoryReplayGuard

ISSUER = "https://mcp.example.com"
TOKEN_ENDPOINT = f"{ISSUER}/token"
CHATGPT_CLIENT = "https://chatgpt.com/oauth/client.json"
CHATGPT_JWKS = "https://chatgpt.com/oauth/jwks.json"
CHATGPT_REDIRECT = "https://chatgpt.com/connector_platform_oauth_redirect"
KID = "cimd-2026"
PUBLIC_ADDRESSES = ["104.18.32.47", "2606:4700::6812:202f"]


def _public_resolver(_host: str) -> list[str]:
    return list(PUBLIC_ADDRESSES)


@pytest.fixture(scope="module")
def rsa_key() -> RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _jwks(key: RSAPrivateKey, kid: str = KID) -> dict[str, Any]:
    numbers = key.public_key().public_numbers()
    n = numbers.n.to_bytes((numbers.n.bit_length() + 7) // 8, "big")
    e = numbers.e.to_bytes((numbers.e.bit_length() + 7) // 8, "big")
    return {
        "keys": [
            {
                "kty": "RSA",
                "use": "sig",
                "alg": "RS256",
                "kid": kid,
                "n": _b64url(n),
                "e": _b64url(e),
            }
        ]
    }


def _chatgpt_document(**overrides: Any) -> dict[str, Any]:
    """The document ChatGPT really serves (fetched 2026-10-01), with overrides; ``None`` removes a key."""

    document: dict[str, Any] = {
        "client_id": CHATGPT_CLIENT,
        "client_uri": "https://chatgpt.com/",
        "redirect_uris": [CHATGPT_REDIRECT],
        "token_endpoint_auth_method": "private_key_jwt",
        "token_endpoint_auth_methods_supported": ["none", "private_key_jwt"],
        "grant_types": ["authorization_code", "refresh_token"],
        "response_types": ["code"],
        "client_name": "ChatGPT",
        "logo_uri": "https://persistent.oaistatic.com/sonic/misc/openai-logo.png",
        "token_endpoint_auth_signing_alg": "RS256",
        "jwks_uri": CHATGPT_JWKS,
    }
    for key, value in overrides.items():
        if value is None:
            document.pop(key, None)
        else:
            document[key] = value
    return document


def _assertion(key: Any, *, kid: str = KID, alg: str = "RS256", **overrides: Any) -> str:
    now = int(time.time())
    claims: dict[str, Any] = {
        "iss": CHATGPT_CLIENT,
        "sub": CHATGPT_CLIENT,
        "aud": TOKEN_ENDPOINT,
        "iat": now,
        "exp": now + 300,
        "jti": str(uuid.uuid4()),
    }
    claims.update(overrides)
    claims = {k: v for k, v in claims.items() if v is not None}
    return jwt.encode(claims, key, algorithm=alg, headers={"kid": kid})


def _pkce_pair() -> tuple[str, str]:
    verifier = secrets.token_urlsafe(64)[:64]
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    return verifier, base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def _settings(**overrides: Any) -> OAuthSettings:
    base: dict[str, Any] = {
        "client_id": "cid",
        "client_secret": "csec",
        "issuer_url": ISSUER,
        "login_username": "caio",
        "login_password": hash_login_password("s3nha"),
        "cimd_allowed_hosts": ("chatgpt.com",),
    }
    base.update(overrides)
    return OAuthSettings(**base)


def _build_app(
    settings: OAuthSettings,
    stores: OAuthStores,
    resolver: ClientMetadataResolver | None = None,
) -> Starlette:
    async def whoami(request: Request) -> JSONResponse:
        return JSONResponse({"subject": get_subject(request)})

    app = Starlette(routes=[Route("/mcp", whoami, methods=["POST"])])
    build_oauth_endpoints(app, settings=settings, stores=stores, client_metadata_resolver=resolver)
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
def resolver() -> ClientMetadataResolver:
    return ClientMetadataResolver(allowed_hosts=("chatgpt.com",), host_resolver=_public_resolver)


@pytest.fixture
def client(stores: OAuthStores, resolver: ClientMetadataResolver) -> Iterator[TestClient]:
    with TestClient(_build_app(_settings(), stores, resolver)) as c:
        yield c


def _mock_document(
    document: dict[str, Any] | None = None,
    *,
    status: int = 200,
    headers: dict[str, str] | None = None,
    key: RSAPrivateKey | None = None,
    raw: bytes | None = None,
) -> respx.Route:
    if raw is not None:
        response = httpx.Response(status, content=raw, headers=headers)
    else:
        response = httpx.Response(
            status, json=document if document is not None else _chatgpt_document(), headers=headers
        )
    route = respx.get(CHATGPT_CLIENT).mock(return_value=response)
    if key is not None:
        respx.get(CHATGPT_JWKS).mock(return_value=httpx.Response(200, json=_jwks(key)))
    return route


def _authorize(
    client: TestClient,
    challenge: str,
    *,
    client_id: str = CHATGPT_CLIENT,
    redirect_uri: str = CHATGPT_REDIRECT,
) -> httpx.Response:
    return client.get(
        "/authorize",
        params={
            "response_type": "code",
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "code_challenge": challenge,
            "code_challenge_method": "S256",
            "state": "st-1",
        },
        follow_redirects=False,
    )


def _login(client: TestClient, html: str) -> str:
    """Submit the password form and return the authorization code sent to the client."""

    match = re.search(r'name="request_id" value="([^"]+)"', html)
    assert match, "login form must carry request_id"
    resp = client.post(
        "/authorize",
        data={"request_id": match.group(1), "username": "caio", "password": "s3nha"},
        follow_redirects=False,
    )
    assert resp.status_code == 302, resp.text
    query = parse_qs(urlparse(resp.headers["location"]).query)
    assert query["iss"] == [ISSUER]
    return query["code"][0]


def _obtain_code(client: TestClient) -> tuple[str, str]:
    verifier, challenge = _pkce_pair()
    resp = _authorize(client, challenge)
    assert resp.status_code == 200, resp.text
    return verifier, _login(client, resp.text)


def _exchange(client: TestClient, code: str, verifier: str, **extra: str) -> httpx.Response:
    data = {
        "grant_type": "authorization_code",
        "client_id": CHATGPT_CLIENT,
        "code": code,
        "redirect_uri": CHATGPT_REDIRECT,
        "code_verifier": verifier,
    }
    data.update(extra)
    return client.post("/token", data=data)


def _whoami(client: TestClient, access_token: str) -> Any:
    resp = client.post("/mcp", headers={"Authorization": f"Bearer {access_token}"})
    assert resp.status_code == 200
    return resp.json()["subject"]


# --------------------------------------------------------------------------- #
# Metadata
# --------------------------------------------------------------------------- #


def test_metadata_advertises_cimd(client: TestClient) -> None:
    metadata = client.get("/.well-known/oauth-authorization-server").json()
    assert metadata["client_id_metadata_document_supported"] is True
    assert set(metadata["token_endpoint_auth_methods_supported"]) == {
        "client_secret_basic",
        "client_secret_post",
        "private_key_jwt",
        "none",
    }
    assert "RS256" in metadata["token_endpoint_auth_signing_alg_values_supported"]
    assert metadata["code_challenge_methods_supported"] == ["S256"]
    assert metadata["authorization_response_iss_parameter_supported"] is True


@respx.mock
def test_cimd_is_off_without_a_person_login(stores: OAuthStores) -> None:
    """An auto-approving server must never hand tokens to arbitrary URL clients."""

    settings = _settings(login_username="", login_password="")
    assert not settings.cimd_active
    route = _mock_document()
    with TestClient(_build_app(settings, stores)) as client:
        metadata = client.get("/.well-known/oauth-authorization-server").json()
        assert "client_id_metadata_document_supported" not in metadata
        assert "none" not in metadata["token_endpoint_auth_methods_supported"]
        _, challenge = _pkce_pair()
        resp = _authorize(client, challenge)
        assert resp.status_code == 401
        assert route.call_count == 0


# --------------------------------------------------------------------------- #
# /authorize with a URL client_id
# --------------------------------------------------------------------------- #


@respx.mock
def test_authorize_renders_login_and_caches_the_document(client: TestClient) -> None:
    route = _mock_document(headers={"Cache-Control": "public, max-age=300"})
    _, challenge = _pkce_pair()
    resp = _authorize(client, challenge)
    assert resp.status_code == 200
    assert "chatgpt.com" in resp.text and 'name="request_id"' in resp.text
    assert route.call_count == 1
    assert "nn-mcp-auth" in route.calls.last.request.headers["user-agent"]
    # Second request within max-age: served from cache.
    assert _authorize(client, challenge).status_code == 200
    assert route.call_count == 1


def test_document_cache_honours_max_age(rsa_key: RSAPrivateKey) -> None:
    now = [1000.0]
    resolver = ClientMetadataResolver(
        allowed_hosts=("chatgpt.com",), clock=lambda: now[0], host_resolver=_public_resolver
    )
    with respx.mock:
        route = _mock_document(headers={"Cache-Control": "public, max-age=300"})
        first = asyncio.run(resolver.resolve(CHATGPT_CLIENT))
        assert first.client_name == "ChatGPT" and first.allows("private_key_jwt")
        now[0] += 299
        asyncio.run(resolver.resolve(CHATGPT_CLIENT))
        assert route.call_count == 1
        now[0] += 2
        asyncio.run(resolver.resolve(CHATGPT_CLIENT))
        assert route.call_count == 2


@respx.mock
def test_redirect_uri_must_be_in_the_document(client: TestClient) -> None:
    _mock_document()
    _, challenge = _pkce_pair()
    resp = _authorize(client, challenge, redirect_uri="https://chatgpt.com/connector/oauth/other")
    assert resp.status_code == 400
    assert resp.json() == {"error": "invalid_request"}


@respx.mock
@pytest.mark.parametrize(
    "client_id",
    [
        "http://chatgpt.com/oauth/client.json",
        "https://chatgpt.com",
        "https://chatgpt.com/",
        "https://chatgpt.com/oauth/../client.json",
        "https://user@chatgpt.com/oauth/client.json",
        "https://chatgpt.com/oauth/client.json#frag",
        "https://127.0.0.1/oauth/client.json",
        "https://localhost/oauth/client.json",
        "https://evil.example/oauth/client.json",
        "https://chatgpt.com.evil.example/oauth/client.json",
    ],
)
def test_invalid_or_untrusted_client_ids_are_rejected_without_fetching(
    client: TestClient, client_id: str
) -> None:
    route = respx.get(re.compile(r".*")).mock(return_value=httpx.Response(200, json={}))
    _, challenge = _pkce_pair()
    resp = _authorize(client, challenge, client_id=client_id)
    assert resp.status_code == 401, client_id
    assert resp.json() == {"error": "invalid_client"}
    assert route.call_count == 0


@respx.mock
def test_subdomains_of_allowed_hosts_are_accepted(stores: OAuthStores) -> None:
    resolver = ClientMetadataResolver(
        allowed_hosts=("chatgpt.com",), host_resolver=_public_resolver
    )
    client_id = "https://connectors.chatgpt.com/oauth/client.json"
    respx.get(client_id).mock(
        return_value=httpx.Response(200, json=_chatgpt_document(client_id=client_id))
    )
    with TestClient(_build_app(_settings(), stores, resolver)) as client:
        _, challenge = _pkce_pair()
        assert _authorize(client, challenge, client_id=client_id).status_code == 200


@respx.mock
@pytest.mark.parametrize("addresses", [["127.0.0.1"], ["10.0.0.5"], ["169.254.169.254"], ["::1"]])
def test_hosts_resolving_to_private_addresses_are_rejected(
    stores: OAuthStores, addresses: list[str]
) -> None:
    resolver = ClientMetadataResolver(
        allowed_hosts=("chatgpt.com",), host_resolver=lambda _host: addresses
    )
    route = _mock_document()
    with TestClient(_build_app(_settings(), stores, resolver)) as client:
        _, challenge = _pkce_pair()
        assert _authorize(client, challenge).status_code == 401
        assert route.call_count == 0


@respx.mock
@pytest.mark.parametrize(
    "mock_kwargs",
    [
        pytest.param({"status": 404}, id="not-found"),
        pytest.param(
            {"status": 302, "headers": {"Location": "https://chatgpt.com/x"}}, id="redirect"
        ),
        pytest.param(
            {"document": _chatgpt_document(client_id="https://chatgpt.com/oauth/other.json")},
            id="client-id-mismatch",
        ),
        pytest.param({"document": _chatgpt_document(redirect_uris=None)}, id="no-redirect-uris"),
        pytest.param({"document": _chatgpt_document(client_secret="shh")}, id="has-secret"),
        pytest.param(
            {
                "document": _chatgpt_document(
                    token_endpoint_auth_method="client_secret_basic",
                    token_endpoint_auth_methods_supported=None,
                )
            },
            id="secret-based-auth",
        ),
        pytest.param(
            {"document": _chatgpt_document(jwks_uri=None)}, id="private-key-jwt-without-keys"
        ),
        pytest.param(
            {"document": _chatgpt_document(jwks_uri="https://evil.example/jwks.json")},
            id="jwks-on-untrusted-host",
        ),
        pytest.param({"raw": b"not json"}, id="invalid-json"),
        pytest.param({"raw": b"[" + b"1," * CIMD_MAX_DOCUMENT_BYTES + b"1]"}, id="too-large"),
    ],
)
def test_bad_documents_are_rejected(client: TestClient, mock_kwargs: dict[str, Any]) -> None:
    _mock_document(**mock_kwargs)
    _, challenge = _pkce_pair()
    resp = _authorize(client, challenge)
    assert resp.status_code == 401
    assert resp.json() == {"error": "invalid_client"}


# --------------------------------------------------------------------------- #
# Token endpoint: public client (none)
# --------------------------------------------------------------------------- #


@respx.mock
def test_public_client_flow_binds_tokens_to_the_url_client(client: TestClient) -> None:
    _mock_document(
        _chatgpt_document(
            token_endpoint_auth_method="none",
            token_endpoint_auth_methods_supported=None,
            jwks_uri=None,
        )
    )
    verifier, code = _obtain_code(client)

    token = _exchange(client, code, verifier)
    assert token.status_code == 200, token.text
    body = token.json()
    assert _whoami(client, body["access_token"]) == "caio"

    # Refresh with the same URL client works and rotates.
    refreshed = client.post(
        "/token",
        data={
            "grant_type": "refresh_token",
            "client_id": CHATGPT_CLIENT,
            "refresh_token": body["refresh_token"],
        },
    )
    assert refreshed.status_code == 200, refreshed.text
    assert _whoami(client, refreshed.json()["access_token"]) == "caio"

    # The static client cannot use a refresh token issued to ChatGPT.
    stolen = client.post(
        "/token",
        data={
            "grant_type": "refresh_token",
            "client_id": "cid",
            "refresh_token": refreshed.json()["refresh_token"],
        },
    )
    assert stolen.status_code == 400
    assert stolen.json() == {"error": "invalid_grant"}


@respx.mock
def test_code_issued_to_url_client_cannot_be_redeemed_by_static_client(client: TestClient) -> None:
    _mock_document()
    verifier, code = _obtain_code(client)
    resp = client.post(
        "/token",
        data={
            "grant_type": "authorization_code",
            "client_id": "cid",
            "code": code,
            "redirect_uri": CHATGPT_REDIRECT,
            "code_verifier": verifier,
        },
    )
    assert resp.status_code == 400
    assert resp.json() == {"error": "invalid_grant"}


@respx.mock
def test_none_is_refused_when_document_only_allows_private_key_jwt(
    client: TestClient, rsa_key: RSAPrivateKey
) -> None:
    _mock_document(_chatgpt_document(token_endpoint_auth_methods_supported=None), key=rsa_key)
    verifier, code = _obtain_code(client)
    resp = _exchange(client, code, verifier)
    assert resp.status_code == 401
    assert resp.json() == {"error": "invalid_client"}


@respx.mock
def test_client_credentials_is_not_available_to_url_clients(client: TestClient) -> None:
    _mock_document()
    resp = client.post(
        "/token", data={"grant_type": "client_credentials", "client_id": CHATGPT_CLIENT}
    )
    assert resp.status_code == 400
    assert resp.json() == {"error": "unauthorized_client"}


def test_legacy_refresh_tokens_belong_to_the_static_client(
    client: TestClient, stores: OAuthStores
) -> None:
    legacy = stores.refresh.issue(subject="caio")  # no client binding, as minted before 0.4.0
    with respx.mock:
        _mock_document()
        resp = client.post(
            "/token",
            data={
                "grant_type": "refresh_token",
                "client_id": CHATGPT_CLIENT,
                "refresh_token": legacy,
            },
        )
        assert resp.status_code == 400 and resp.json() == {"error": "invalid_grant"}
    legacy = stores.refresh.issue(subject="caio")
    ok = client.post(
        "/token", data={"grant_type": "refresh_token", "client_id": "cid", "refresh_token": legacy}
    )
    assert ok.status_code == 200


# --------------------------------------------------------------------------- #
# Token endpoint: private_key_jwt (what ChatGPT prefers)
# --------------------------------------------------------------------------- #


@respx.mock
def test_private_key_jwt_flow(client: TestClient, rsa_key: RSAPrivateKey) -> None:
    _mock_document(key=rsa_key)
    verifier, code = _obtain_code(client)

    assertion = _assertion(rsa_key)
    token = _exchange(
        client,
        code,
        verifier,
        client_assertion_type=CLIENT_ASSERTION_TYPE_JWT_BEARER,
        client_assertion=assertion,
    )
    assert token.status_code == 200, token.text
    body = token.json()
    assert _whoami(client, body["access_token"]) == "caio"

    # Replaying the same assertion is refused.
    replay = client.post(
        "/token",
        data={
            "grant_type": "refresh_token",
            "client_id": CHATGPT_CLIENT,
            "refresh_token": body["refresh_token"],
            "client_assertion_type": CLIENT_ASSERTION_TYPE_JWT_BEARER,
            "client_assertion": assertion,
        },
    )
    assert replay.status_code == 401

    # A fresh assertion refreshes fine; the issuer URL is also an acceptable audience.
    refreshed = client.post(
        "/token",
        data={
            "grant_type": "refresh_token",
            "client_id": CHATGPT_CLIENT,
            "refresh_token": body["refresh_token"],
            "client_assertion_type": CLIENT_ASSERTION_TYPE_JWT_BEARER,
            "client_assertion": _assertion(rsa_key, aud=[ISSUER]),
        },
    )
    assert refreshed.status_code == 200, refreshed.text
    assert _whoami(client, refreshed.json()["access_token"]) == "caio"


@respx.mock
def test_assertion_without_client_id_field(client: TestClient, rsa_key: RSAPrivateKey) -> None:
    _mock_document(key=rsa_key)
    verifier, code = _obtain_code(client)
    resp = client.post(
        "/token",
        data={
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": CHATGPT_REDIRECT,
            "code_verifier": verifier,
            "client_assertion_type": CLIENT_ASSERTION_TYPE_JWT_BEARER,
            "client_assertion": _assertion(rsa_key),
        },
    )
    assert resp.status_code == 200, resp.text


@respx.mock
def test_inline_jwks_document(client: TestClient, rsa_key: RSAPrivateKey) -> None:
    _mock_document(_chatgpt_document(jwks_uri=None, jwks=_jwks(rsa_key)))
    verifier, code = _obtain_code(client)
    resp = _exchange(
        client,
        code,
        verifier,
        client_assertion_type=CLIENT_ASSERTION_TYPE_JWT_BEARER,
        client_assertion=_assertion(rsa_key),
    )
    assert resp.status_code == 200, resp.text


def _ec_key() -> Any:
    return ec.generate_private_key(ec.SECP256R1())


@respx.mock
@pytest.mark.parametrize(
    "case",
    [
        pytest.param({"aud": "https://other.example/token"}, id="wrong-audience"),
        pytest.param({"exp": int(time.time()) - 3600}, id="expired"),
        pytest.param({"exp": int(time.time()) + 7200}, id="lifetime-too-long"),
        pytest.param({"iss": "https://chatgpt.com/oauth/other.json"}, id="issuer-mismatch"),
        pytest.param({"sub": "https://chatgpt.com/oauth/other.json"}, id="subject-mismatch"),
        pytest.param({"jti": None}, id="missing-jti"),
        pytest.param({"kid": "unknown"}, id="unknown-key"),
        pytest.param({"_other_key": True}, id="signed-by-another-key"),
        pytest.param({"_ec": True}, id="algorithm-not-the-declared-one"),
        pytest.param(
            {"_type": "urn:ietf:params:oauth:client-assertion-type:saml2-bearer"},
            id="wrong-assertion-type",
        ),
    ],
)
def test_bad_assertions_are_rejected(
    client: TestClient, rsa_key: RSAPrivateKey, case: dict[str, Any]
) -> None:
    case = dict(case)  # parametrize shares the dict across the memory/redis variants
    _mock_document(key=rsa_key)
    verifier, code = _obtain_code(client)
    assertion_type = case.pop("_type", CLIENT_ASSERTION_TYPE_JWT_BEARER)
    if case.pop("_other_key", False):
        assertion = _assertion(rsa.generate_private_key(public_exponent=65537, key_size=2048))
    elif case.pop("_ec", False):
        assertion = _assertion(_ec_key(), alg="ES256")
    else:
        assertion = _assertion(rsa_key, **case)
    resp = _exchange(
        client, code, verifier, client_assertion_type=assertion_type, client_assertion=assertion
    )
    assert resp.status_code == 401, resp.text
    assert resp.json() == {"error": "invalid_client"}


def test_replay_guard_expires_keys() -> None:
    now = [100.0]
    guard = MemoryReplayGuard(_clock=lambda: now[0])
    assert guard.claim("a", 10) and not guard.claim("a", 10)
    now[0] += 11
    assert guard.claim("a", 10)


# --------------------------------------------------------------------------- #
# Settings and parsing
# --------------------------------------------------------------------------- #


def _env(**extra: str) -> dict[str, str]:
    env = {
        "OAUTH_CLIENT_ID": "cid",
        "OAUTH_CLIENT_SECRET": "csec",
        "OAUTH_LOGIN_USERNAME": "u",
        "OAUTH_LOGIN_PASSWORD": "p",
    }
    env.update(extra)
    return env


def test_settings_defaults() -> None:
    settings = load_oauth_settings(_env())
    assert settings.cimd_enabled and settings.cimd_active
    assert settings.cimd_allowed_hosts == ("chatgpt.com", "claude.ai", "claude.com")


def test_settings_requires_login_for_cimd() -> None:
    settings = load_oauth_settings({"OAUTH_CLIENT_ID": "cid", "OAUTH_CLIENT_SECRET": "csec"})
    assert settings.cimd_enabled and not settings.cimd_active


def test_settings_can_disable_and_restrict_hosts() -> None:
    assert not load_oauth_settings(_env(OAUTH_CIMD_ENABLED="false")).cimd_active
    settings = load_oauth_settings(
        _env(OAUTH_CIMD_ALLOWED_HOSTS=" ChatGPT.com, chatgpt.com ,claude.ai")
    )
    assert settings.cimd_allowed_hosts == ("chatgpt.com", "claude.ai")


@pytest.mark.parametrize(
    "extra",
    [
        {"OAUTH_CIMD_ENABLED": "maybe"},
        {"OAUTH_CIMD_ALLOWED_HOSTS": "https://chatgpt.com"},
        {"OAUTH_CIMD_ALLOWED_HOSTS": "chatgpt.com:443"},
        {"OAUTH_CIMD_ALLOWED_HOSTS": ", ,"},
    ],
)
def test_invalid_cimd_settings(extra: dict[str, str]) -> None:
    with pytest.raises(ConfigurationError):
        load_oauth_settings(_env(**extra))


def test_validate_client_id_url_returns_lowercase_host() -> None:
    assert validate_client_id_url("https://ChatGPT.com/oauth/client.json") == "chatgpt.com"
    with pytest.raises(ClientMetadataError) as excinfo:
        validate_client_id_url("https://chatgpt.com/oauth/client.json?x=1#y")
    assert excinfo.value.reason == "client_id_fragment"


def test_parse_document_defaults() -> None:
    minimal = {"client_id": CHATGPT_CLIENT, "redirect_uris": [CHATGPT_REDIRECT]}
    metadata = parse_client_metadata(CHATGPT_CLIENT, minimal)
    assert metadata.auth_methods == frozenset({"none"})
    assert metadata.client_name == "chatgpt.com"
    assert metadata.is_redirect_uri_allowed(CHATGPT_REDIRECT)
    assert not metadata.is_redirect_uri_allowed("")
