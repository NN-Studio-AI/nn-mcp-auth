"""HTML for the optional /authorize login page.

Minimal on purpose: Portuguese copy, inline CSS, no JavaScript, no external
assets. Every dynamic value goes through :func:`html.escape`. The response
headers (CSP, X-Frame-Options, Cache-Control) are set by
:func:`login_page_headers` so the page can never be framed or cached.
"""

from __future__ import annotations

import html
import re
from typing import Final
from urllib.parse import urlsplit

LOGIN_TITLE: Final[str] = "Autorizar acesso"
MSG_INVALID_CREDENTIALS: Final[str] = "Usuário ou senha inválidos."
MSG_TOO_MANY_ATTEMPTS: Final[str] = (
    "Muitas tentativas de acesso. Aguarde alguns minutos e tente novamente."
)
MSG_REQUEST_EXPIRED: Final[str] = (
    "Esta solicitação de autorização expirou ou já foi usada. "
    "Volte ao aplicativo e inicie a conexão novamente."
)

_ORIGIN_RE: Final[re.Pattern[str]] = re.compile(r"^https?://[A-Za-z0-9.\-]+(:\d{1,5})?$")

_STYLE: Final[str] = """
:root{color-scheme:light dark;--bg:#f4f5f7;--card:#fff;--ink:#121212;--muted:#5b6170;
--line:#d7dae0;--accent:#1f4fd1;--accent-ink:#fff;--error-bg:#fdecec;--error-ink:#9b1c1c}
@media (prefers-color-scheme:dark){:root{--bg:#0f1115;--card:#181b22;--ink:#eceef2;
--muted:#9aa1ad;--line:#2c313b;--accent:#7aa2ff;--accent-ink:#0f1115;--error-bg:#3a1717;
--error-ink:#ffb4b4}}
*{box-sizing:border-box}
body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;
padding:16px;background:var(--bg);color:var(--ink);
font:16px/1.5 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
main{width:100%;max-width:380px;background:var(--card);border:1px solid var(--line);
border-radius:12px;padding:28px 24px}
h1{margin:0 0 8px;font-size:1.35rem}
p{margin:0 0 20px;color:var(--muted);font-size:.95rem}
strong{color:var(--ink)}
label{display:block;margin:0 0 6px;font-weight:600;font-size:.9rem}
input{width:100%;margin:0 0 16px;padding:10px 12px;border:1px solid var(--line);
border-radius:8px;background:transparent;color:var(--ink);font:inherit}
input:focus{outline:2px solid var(--accent);outline-offset:1px}
button{width:100%;padding:11px 12px;border:0;border-radius:8px;background:var(--accent);
color:var(--accent-ink);font:inherit;font-weight:600;cursor:pointer}
.error{margin:0 0 16px;padding:10px 12px;border-radius:8px;background:var(--error-bg);
color:var(--error-ink);font-size:.9rem}
"""


def redirect_origin(redirect_uri: str) -> str | None:
    """Return ``scheme://host[:port]`` of ``redirect_uri`` if it is safe to put in a CSP."""

    parts = urlsplit(redirect_uri)
    if parts.scheme not in ("http", "https") or not parts.netloc:
        return None
    origin = f"{parts.scheme}://{parts.netloc}"
    return origin if _ORIGIN_RE.match(origin) else None


def login_page_headers(redirect_uri: str | None) -> dict[str, str]:
    """Security headers for every login-page response.

    ``form-action`` must list the client's redirect origin besides ``'self'``:
    browsers apply ``form-action`` to the redirect that follows a form POST,
    so ``'self'`` alone would block the final 302 to the OAuth client. The
    redirect URI comes from the server-side allowlist, never from user input
    alone, and is re-validated by :func:`redirect_origin`.
    """

    form_action = "'self'"
    origin = redirect_origin(redirect_uri) if redirect_uri else None
    if origin:
        form_action = f"'self' {origin}"
    csp = (
        "default-src 'none'; style-src 'unsafe-inline'; "
        f"form-action {form_action}; frame-ancestors 'none'; base-uri 'none'"
    )
    return {
        "Content-Security-Policy": csp,
        "X-Frame-Options": "DENY",
        "Cache-Control": "no-store",
        "Pragma": "no-cache",
        "Referrer-Policy": "no-referrer",
        "X-Content-Type-Options": "nosniff",
        "X-Robots-Tag": "noindex, nofollow",
    }


def render_login_page(
    *,
    form_action: str,
    request_id: str | None,
    client_host: str | None,
    error: str | None = None,
) -> str:
    """Render the page. Without ``request_id`` only the message is shown (no form)."""

    esc = html.escape
    if client_host:
        lead = (
            f"O aplicativo em <strong>{esc(client_host)}</strong> está solicitando acesso "
            "a este servidor. Entre com suas credenciais para autorizar."
        )
    else:
        lead = "Entre com suas credenciais para autorizar o acesso a este servidor."

    error_block = f'<p class="error" role="alert">{esc(error)}</p>' if error else ""

    if request_id:
        form = (
            f'<form method="post" action="{esc(form_action)}">'
            f'<input type="hidden" name="request_id" value="{esc(request_id)}">'
            '<label for="username">Usuário</label>'
            '<input id="username" name="username" type="text" autocomplete="username" '
            'autocapitalize="none" spellcheck="false" required autofocus>'
            '<label for="password">Senha</label>'
            '<input id="password" name="password" type="password" '
            'autocomplete="current-password" required>'
            '<button type="submit">Entrar e autorizar</button>'
            "</form>"
        )
        body = f"<h1>{LOGIN_TITLE}</h1><p>{lead}</p>{error_block}{form}"
    else:
        body = f"<h1>{LOGIN_TITLE}</h1>{error_block}"

    return (
        "<!doctype html>"
        '<html lang="pt-BR"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width, initial-scale=1">'
        '<meta name="robots" content="noindex, nofollow">'
        f"<title>{LOGIN_TITLE}</title><style>{_STYLE}</style></head>"
        f"<body><main>{body}</main></body></html>"
    )
