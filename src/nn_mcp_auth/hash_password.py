"""CLI: print a scrypt hash for ``OAUTH_LOGIN_PASSWORD``.

Usage::

    python -m nn_mcp_auth.hash_password            # interactive prompt (asks twice)
    printf '%s' "$SENHA" | python -m nn_mcp_auth.hash_password   # from stdin

The password itself is never echoed; only the ``scrypt$<salt>$<hash>`` string
is written to stdout.
"""

from __future__ import annotations

import getpass
import sys
from typing import TextIO

from .password import hash_login_password


def _read_password(stdin: TextIO) -> str | None:
    if stdin.isatty():
        first = getpass.getpass("Senha: ")
        second = getpass.getpass("Confirme a senha: ")
        if first != second:
            print("As senhas não conferem.", file=sys.stderr)
            return None
        return first
    # Only strip the line terminator: leading/trailing spaces may be intentional.
    return stdin.read().rstrip("\r\n")


def main(stdin: TextIO | None = None, stdout: TextIO | None = None) -> int:
    source = stdin if stdin is not None else sys.stdin
    sink = stdout if stdout is not None else sys.stdout
    password = _read_password(source)
    if password is None:
        return 1
    if not password:
        print("A senha não pode ser vazia.", file=sys.stderr)
        return 2
    print(hash_login_password(password), file=sink)
    return 0


if __name__ == "__main__":  # pragma: no cover - exercised via subprocess in tests
    raise SystemExit(main())
