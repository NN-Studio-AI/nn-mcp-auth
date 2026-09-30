"""Login password hashing, verification and the hash_password CLI."""

from __future__ import annotations

import base64
import hashlib
import io
import subprocess
import sys

import pytest

from nn_mcp_auth import hash_password as cli
from nn_mcp_auth.password import (
    hash_login_password,
    login_credentials_match,
    parse_scrypt_hash,
    verify_login_password,
)


def test_hash_format_is_scrypt_salt_hash() -> None:
    hashed = hash_login_password("s3nha-forte")
    prefix, salt_b64, key_b64 = hashed.split("$")
    assert prefix == "scrypt"
    assert len(base64.b64decode(salt_b64)) == 16
    assert len(base64.b64decode(key_b64)) == 32


def test_hash_is_salted() -> None:
    assert hash_login_password("igual") != hash_login_password("igual")


def test_verify_hash_accepts_right_and_rejects_wrong_password() -> None:
    hashed = hash_login_password("s3nha-forte")
    assert verify_login_password("s3nha-forte", hashed) is True
    assert verify_login_password("s3nha-fraca", hashed) is False
    assert verify_login_password("", hashed) is False


def test_verify_plain_text_password() -> None:
    assert verify_login_password("texto-puro", "texto-puro") is True
    assert verify_login_password("texto-purO", "texto-puro") is False
    # Non-ASCII must not raise (compare_digest on str would TypeError).
    assert verify_login_password("ação", "ação") is True
    assert verify_login_password("acao", "ação") is False


def test_verify_rejects_empty_stored_and_malformed_hash() -> None:
    assert verify_login_password("x", "") is False
    assert verify_login_password("x", "scrypt$não-é-base64$???") is False
    assert verify_login_password("x", "scrypt$only-two") is False


def test_verify_accepts_node_style_64_byte_key() -> None:
    """Hashes produced by Node's scryptSync(code, salt, 64) must verify too."""

    salt = b"0123456789abcdef"
    key = hashlib.scrypt(b"codigo", salt=salt, n=2**14, r=8, p=1, dklen=64)
    stored = f"scrypt${base64.b64encode(salt).decode()}${base64.b64encode(key).decode()}"
    assert verify_login_password("codigo", stored) is True
    assert verify_login_password("outro", stored) is False


@pytest.mark.parametrize(
    "value",
    [
        "scrypt$",
        "scrypt$$",
        "scrypt$YWJj$",  # empty key
        "scrypt$$" + base64.b64encode(b"k" * 32).decode(),  # empty salt
        "scrypt$YWJj$" + base64.b64encode(b"k" * 8).decode(),  # key too short
        "scrypt$YWJj$" + base64.b64encode(b"k" * 32).decode() + "$extra",
    ],
)
def test_parse_scrypt_hash_rejects_malformed(value: str) -> None:
    assert parse_scrypt_hash(value) is None


def test_hash_rejects_empty_password() -> None:
    with pytest.raises(ValueError):
        hash_login_password("")


def test_login_credentials_match_requires_both_fields() -> None:
    hashed = hash_login_password("senha")
    assert login_credentials_match("caio", "senha", username="caio", password=hashed)
    assert not login_credentials_match("caio", "errada", username="caio", password=hashed)
    assert not login_credentials_match("outro", "senha", username="caio", password=hashed)
    assert not login_credentials_match("caio", "senha", username="", password=hashed)
    assert not login_credentials_match("caio", "senha", username="caio", password="")


class _FakeStdin(io.StringIO):
    def __init__(self, value: str, *, tty: bool) -> None:
        super().__init__(value)
        self._tty = tty

    def isatty(self) -> bool:
        return self._tty


def test_cli_reads_stdin_and_prints_verifiable_hash() -> None:
    out = io.StringIO()
    assert cli.main(stdin=_FakeStdin("minha senha\n", tty=False), stdout=out) == 0
    printed = out.getvalue().strip()
    assert printed.startswith("scrypt$")
    assert "minha senha" not in printed
    # Only the line terminator is stripped; inner spaces are kept.
    assert verify_login_password("minha senha", printed) is True


def test_cli_rejects_empty_stdin() -> None:
    out = io.StringIO()
    assert cli.main(stdin=_FakeStdin("\n", tty=False), stdout=out) == 2
    assert out.getvalue() == ""


def test_cli_interactive_prompt_confirms(monkeypatch: pytest.MonkeyPatch) -> None:
    answers = iter(["abc123", "abc123"])
    monkeypatch.setattr(cli.getpass, "getpass", lambda _prompt: next(answers))
    out = io.StringIO()
    assert cli.main(stdin=_FakeStdin("", tty=True), stdout=out) == 0
    assert verify_login_password("abc123", out.getvalue().strip()) is True


def test_cli_interactive_mismatch_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    answers = iter(["abc123", "abc124"])
    monkeypatch.setattr(cli.getpass, "getpass", lambda _prompt: next(answers))
    out = io.StringIO()
    assert cli.main(stdin=_FakeStdin("", tty=True), stdout=out) == 1
    assert out.getvalue() == ""


def test_cli_runs_as_module() -> None:
    result = subprocess.run(
        [sys.executable, "-m", "nn_mcp_auth.hash_password"],
        input="via-subprocess",
        capture_output=True,
        text=True,
        check=True,
    )
    assert verify_login_password("via-subprocess", result.stdout.strip()) is True
