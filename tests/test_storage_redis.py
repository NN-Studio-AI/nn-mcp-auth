"""Roundtrip tests for the Redis-backed token stores using fakeredis."""

from __future__ import annotations

import fakeredis
import pytest

from nn_mcp_auth.errors import ConfigurationError
from nn_mcp_auth.storage.redis import (
    RedisAccessTokenStore,
    RedisAuthCodeStore,
    RedisOAuthStores,
    RedisRefreshTokenStore,
)


@pytest.fixture
def client() -> fakeredis.FakeRedis:
    return fakeredis.FakeRedis(decode_responses=True, version=(6, 2, 0))


def test_redis_access_token_issue_and_validate(client: fakeredis.FakeRedis) -> None:
    store = RedisAccessTokenStore(client, prefix="mcp:test", ttl_seconds=10)
    token, ttl = store.issue()
    assert ttl == 10
    assert store.is_valid(token) is True
    assert store.is_valid("nope") is False


def test_redis_access_token_revoke(client: fakeredis.FakeRedis) -> None:
    store = RedisAccessTokenStore(client, prefix="mcp:test", ttl_seconds=10)
    token, _ = store.issue()
    store.revoke(token)
    assert store.is_valid(token) is False


def test_redis_refresh_token_one_time_use(client: fakeredis.FakeRedis) -> None:
    store = RedisRefreshTokenStore(client, prefix="mcp:test", ttl_seconds=100)
    token = store.issue()
    assert store.consume(token) is True
    # Second consume must fail.
    assert store.consume(token) is False


def test_redis_refresh_token_rejects_empty(client: fakeredis.FakeRedis) -> None:
    store = RedisRefreshTokenStore(client, prefix="mcp:test", ttl_seconds=100)
    assert store.consume("") is False
    assert store.consume("never-issued") is False


def test_redis_auth_code_roundtrip(client: fakeredis.FakeRedis) -> None:
    store = RedisAuthCodeStore(client, prefix="mcp:test", ttl_seconds=600)
    code = store.issue(
        client_id="cid",
        redirect_uri="https://x.example/cb",
        code_challenge="abc",
        code_challenge_method="S256",
    )
    record = store.consume(code)
    assert record is not None
    assert record.client_id == "cid"
    assert record.redirect_uri == "https://x.example/cb"
    assert record.code_challenge == "abc"
    # One-time use.
    assert store.consume(code) is None


def test_redis_stores_namespace_isolation(client: fakeredis.FakeRedis) -> None:
    """Two MCPs sharing the same Redis must not see each other's tokens."""

    store_a = RedisAccessTokenStore(client, prefix="mcp:whatsapp", ttl_seconds=10)
    store_b = RedisAccessTokenStore(client, prefix="mcp:github", ttl_seconds=10)

    token_a, _ = store_a.issue()
    token_b, _ = store_b.issue()

    assert store_a.is_valid(token_a) is True
    assert store_a.is_valid(token_b) is False
    assert store_b.is_valid(token_a) is False
    assert store_b.is_valid(token_b) is True


def test_redis_oauth_stores_from_client(client: fakeredis.FakeRedis) -> None:
    stores = RedisOAuthStores.from_client(client, prefix="mcp:test")
    token, _ = stores.access.issue()
    assert stores.access.is_valid(token) is True


def test_redis_oauth_stores_from_env_requires_url() -> None:
    with pytest.raises(ConfigurationError):
        RedisOAuthStores.from_env({"REDIS_KEY_PREFIX": "mcp:x"})


def test_redis_oauth_stores_from_env_requires_prefix() -> None:
    with pytest.raises(ConfigurationError):
        RedisOAuthStores.from_env({"REDIS_URL": "redis://localhost:6379/0"})
