"""Roundtrip tests for the in-memory token stores."""

from __future__ import annotations

from nn_mcp_auth.oauth import PendingAuthorizationRecord
from nn_mcp_auth.storage.memory import (
    MemoryAccessTokenStore,
    MemoryAuthCodeStore,
    MemoryLoginAttemptLimiter,
    MemoryOAuthStores,
    MemoryPendingAuthorizationStore,
    MemoryRefreshTokenStore,
)


class FakeClock:
    def __init__(self, start: float = 0.0) -> None:
        self.value = start

    def __call__(self) -> float:
        return self.value


def test_access_token_issue_and_validate() -> None:
    clock = FakeClock()
    store = MemoryAccessTokenStore(ttl_seconds=10, _clock=clock)

    token, ttl = store.issue()
    assert ttl == 10
    assert store.is_valid(token) is True
    assert store.is_valid("unknown-token") is False


def test_access_token_expires_after_ttl() -> None:
    clock = FakeClock()
    store = MemoryAccessTokenStore(ttl_seconds=10, _clock=clock)
    token, _ = store.issue()

    clock.value = 11
    assert store.is_valid(token) is False


def test_access_token_revoke() -> None:
    store = MemoryAccessTokenStore(ttl_seconds=10)
    token, _ = store.issue()
    store.revoke(token)
    assert store.is_valid(token) is False


def test_refresh_token_one_time_use() -> None:
    store = MemoryRefreshTokenStore(ttl_seconds=100)
    token = store.issue()
    assert store.consume(token) is True
    # Second consume must fail (rotation).
    assert store.consume(token) is False


def test_refresh_token_invalid_returns_false() -> None:
    store = MemoryRefreshTokenStore(ttl_seconds=100)
    assert store.consume("nope") is False
    assert store.consume("") is False


def test_refresh_token_expires_after_ttl() -> None:
    clock = FakeClock()
    store = MemoryRefreshTokenStore(ttl_seconds=10, _clock=clock)
    token = store.issue()

    clock.value = 11
    assert store.consume(token) is False


def test_auth_code_roundtrip() -> None:
    store = MemoryAuthCodeStore(ttl_seconds=600)
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
    assert record.code_challenge_method == "S256"
    # One-time use.
    assert store.consume(code) is None


def test_auth_code_expires() -> None:
    clock = FakeClock()
    store = MemoryAuthCodeStore(ttl_seconds=10, _clock=clock)
    code = store.issue(
        client_id="c", redirect_uri="u", code_challenge="cc", code_challenge_method="S256"
    )

    clock.value = 11
    assert store.consume(code) is None


def test_memory_oauth_stores_factory() -> None:
    stores = MemoryOAuthStores.create(access_ttl=60, refresh_ttl=120, code_ttl=30)
    assert stores.access.ttl_seconds == 60
    assert stores.refresh.ttl_seconds == 120
    assert stores.code.ttl_seconds == 30


def _pending_record() -> PendingAuthorizationRecord:
    return PendingAuthorizationRecord(
        client_id="cid",
        redirect_uri="https://chatgpt.com/connector_platform_oauth_redirect",
        code_challenge="abc",
        code_challenge_method="S256",
        state="st",
    )


def test_pending_authorization_get_then_consume_once() -> None:
    clock = FakeClock()
    store = MemoryPendingAuthorizationStore(ttl_seconds=600, _clock=clock)
    request_id = store.create(_pending_record())
    assert store.get(request_id) == _pending_record()
    assert store.get(request_id) == _pending_record()  # get does not consume
    assert store.consume(request_id) == _pending_record()
    assert store.consume(request_id) is None
    assert store.get(request_id) is None


def test_pending_authorization_expires() -> None:
    clock = FakeClock()
    store = MemoryPendingAuthorizationStore(ttl_seconds=600, _clock=clock)
    request_id = store.create(_pending_record())
    clock.value = 600
    assert store.get(request_id) is None
    assert store.consume(request_id) is None


def test_login_limiter_fixed_window() -> None:
    clock = FakeClock()
    limiter = MemoryLoginAttemptLimiter(window_seconds=600, _clock=clock)
    assert limiter.hit("1.2.3.4") == (1, 600)
    clock.value = 100
    assert limiter.hit("1.2.3.4") == (2, 500)
    assert limiter.hit("5.6.7.8") == (1, 600)
    clock.value = 600
    assert limiter.hit("1.2.3.4") == (1, 600)


def test_memory_stores_create_includes_login_stores() -> None:
    stores = MemoryOAuthStores.create()
    assert isinstance(stores.pending, MemoryPendingAuthorizationStore)
    assert isinstance(stores.login_limiter, MemoryLoginAttemptLimiter)
