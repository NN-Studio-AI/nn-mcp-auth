"""PKCE, Basic auth parsing, credential matching, and settings loader."""

from __future__ import annotations

import base64
import hashlib
import secrets

import pytest

from nn_mcp_auth.errors import ConfigurationError
from nn_mcp_auth.oauth import (
    OAuthSettings,
    client_id_matches,
    credentials_match,
    load_oauth_settings,
    parse_basic_auth,
    verify_pkce,
)


def _pkce_pair() -> tuple[str, str]:
    verifier = secrets.token_urlsafe(64)[:64]  # 43-128 chars, url-safe
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
    return verifier, challenge


def test_verify_pkce_happy_path() -> None:
    verifier, challenge = _pkce_pair()
    assert verify_pkce(verifier, challenge, "S256") is True


def test_verify_pkce_rejects_plain_method() -> None:
    verifier, challenge = _pkce_pair()
    assert verify_pkce(verifier, challenge, "plain") is False


def test_verify_pkce_rejects_wrong_verifier() -> None:
    _, challenge = _pkce_pair()
    other_verifier = secrets.token_urlsafe(64)[:64]
    assert verify_pkce(other_verifier, challenge, "S256") is False


@pytest.mark.parametrize("length", [42, 129])
def test_verify_pkce_rejects_out_of_range_verifier_length(length: int) -> None:
    verifier = "a" * length
    challenge = base64.urlsafe_b64encode(
        hashlib.sha256(verifier.encode("ascii")).digest()
    ).rstrip(b"=").decode("ascii")
    assert verify_pkce(verifier, challenge, "S256") is False


def test_verify_pkce_rejects_empty_inputs() -> None:
    assert verify_pkce("", "anything", "S256") is False
    assert verify_pkce("a" * 43, "", "S256") is False


def test_parse_basic_auth_happy() -> None:
    raw = base64.b64encode(b"user:pass").decode()
    assert parse_basic_auth(f"Basic {raw}") == ("user", "pass")


def test_parse_basic_auth_lowercase_scheme() -> None:
    raw = base64.b64encode(b"a:b").decode()
    assert parse_basic_auth(f"basic {raw}") == ("a", "b")


def test_parse_basic_auth_rejects_non_basic_scheme() -> None:
    assert parse_basic_auth("Bearer x") is None


def test_parse_basic_auth_rejects_empty() -> None:
    assert parse_basic_auth("") is None
    assert parse_basic_auth("Basic ") is None


def test_parse_basic_auth_rejects_invalid_base64() -> None:
    assert parse_basic_auth("Basic not-base64!") is None


def test_parse_basic_auth_rejects_missing_colon() -> None:
    raw = base64.b64encode(b"useronly").decode()
    assert parse_basic_auth(f"Basic {raw}") is None


def test_credentials_match_constant_time() -> None:
    settings = OAuthSettings(client_id="id-1", client_secret="sec-1")
    assert credentials_match("id-1", "sec-1", settings) is True
    assert credentials_match("id-2", "sec-1", settings) is False
    assert credentials_match("id-1", "sec-2", settings) is False


def test_credentials_match_when_disabled() -> None:
    disabled = OAuthSettings(client_id="", client_secret="")
    assert credentials_match("id", "sec", disabled) is False


def test_client_id_matches_only_checks_id() -> None:
    settings = OAuthSettings(client_id="id-1", client_secret="sec-1")
    assert client_id_matches("id-1", settings) is True
    assert client_id_matches("id-2", settings) is False


def test_load_oauth_settings_disabled_when_empty() -> None:
    settings = load_oauth_settings({})
    assert settings.enabled is False


def test_load_oauth_settings_enabled() -> None:
    settings = load_oauth_settings({"OAUTH_CLIENT_ID": "x", "OAUTH_CLIENT_SECRET": "y"})
    assert settings.enabled is True
    assert settings.client_id == "x"
    assert settings.token_ttl_seconds == 3600


def test_load_oauth_settings_partial_credentials_raises() -> None:
    with pytest.raises(ConfigurationError):
        load_oauth_settings({"OAUTH_CLIENT_ID": "x"})
    with pytest.raises(ConfigurationError):
        load_oauth_settings({"OAUTH_CLIENT_SECRET": "y"})


def test_load_oauth_settings_invalid_ttl() -> None:
    with pytest.raises(ConfigurationError):
        load_oauth_settings(
            {"OAUTH_CLIENT_ID": "x", "OAUTH_CLIENT_SECRET": "y", "OAUTH_TOKEN_TTL_SECONDS": "abc"}
        )
    with pytest.raises(ConfigurationError):
        load_oauth_settings(
            {"OAUTH_CLIENT_ID": "x", "OAUTH_CLIENT_SECRET": "y", "OAUTH_TOKEN_TTL_SECONDS": "5"}
        )


def test_load_oauth_settings_custom_redirect_uris() -> None:
    settings = load_oauth_settings(
        {
            "OAUTH_CLIENT_ID": "x",
            "OAUTH_CLIENT_SECRET": "y",
            "OAUTH_ALLOWED_REDIRECT_URIS": "https://a.example/cb,https://b.example/cb",
        }
    )
    assert settings.is_redirect_uri_allowed("https://a.example/cb") is True
    assert settings.is_redirect_uri_allowed("https://b.example/cb") is True
    assert settings.is_redirect_uri_allowed("https://c.example/cb") is False


def test_is_redirect_uri_allowed_rejects_empty() -> None:
    settings = OAuthSettings(client_id="x", client_secret="y")
    assert settings.is_redirect_uri_allowed("") is False
