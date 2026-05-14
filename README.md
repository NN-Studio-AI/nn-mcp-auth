# nn-mcp-auth

Shared library that gives every NN Studio MCP server the same OAuth 2.0 + bearer-token plumbing without copy-pasting 700 LOC per repo.

Implements the three grant types that claude.ai custom connectors and headless service-to-service callers need:

- **Authorization Code with PKCE** (RFC 6749 §4.1 + RFC 7636) — for OAuth UIs like the claude.ai "Vincular" flow
- **Refresh Token rotation** (RFC 6749 §6) — claude.ai rotates on every refresh
- **Client Credentials** (RFC 6749 §4.4) — for headless callers holding `client_id` + `client_secret`

Plus a `BearerAuthMiddleware` that protects MCP routes with either the static `MCP_AUTH_TOKEN` or an OAuth-issued access token, and an RFC 8414 metadata endpoint.

## Why this exists

Before this lib, each NN MCP (googleads, github, whatsapp, …) had its own near-identical `auth.py` + `oauth.py` + parts of `http_app.py` (~700 LOC). Bug fixes meant N PRs. Adding Redis-backed token persistence meant N implementations. Stop.

## Storage backends

- `MemoryOAuthStores` — in-process dicts. Tokens vanish on restart. Fine for tests/dev.
- `RedisOAuthStores` — persists tokens, refresh tokens, and authorization codes in Redis with native TTL. Survives restarts. Use in production. Each MCP namespaces its keys via a prefix so a single Redis instance is shared safely.

## Usage in an MCP server

```python
from starlette.applications import Starlette
from nn_mcp_auth import (
    BearerAuthMiddleware,
    RedisOAuthStores,
    build_oauth_endpoints,
    load_oauth_settings,
)

settings = load_oauth_settings()                   # reads OAUTH_* env vars
stores   = RedisOAuthStores.from_env()             # reads REDIS_URL + REDIS_KEY_PREFIX

build_oauth_endpoints(app, settings=settings, stores=stores)
app.add_middleware(
    BearerAuthMiddleware,
    token=os.environ["MCP_AUTH_TOKEN"],
    protected_paths={"/mcp"},
    oauth_store=stores.access,
)
```

That replaces the entire `auth.py` + `oauth.py` + most of `http_app.py` that used to live in each MCP.

## Env vars consumed

| Var | Purpose | Default |
|---|---|---|
| `OAUTH_CLIENT_ID` | Client id callers must present | — (empty disables OAuth) |
| `OAUTH_CLIENT_SECRET` | Client secret callers must present | — |
| `OAUTH_TOKEN_TTL_SECONDS` | Access token lifetime | 3600 |
| `OAUTH_ALLOWED_REDIRECT_URIS` | CSV of allowed redirect URIs for code grant | claude.ai defaults |
| `OAUTH_ISSUER_URL` | Issuer URL announced in metadata | derived from request scheme/host |
| `REDIS_URL` | `redis://host:port[/db]` | required for `RedisOAuthStores.from_env()` |
| `REDIS_KEY_PREFIX` | Namespace per MCP, e.g. `mcp:whatsapp` | required |
| `LOG_LEVEL` | Stdlib log level for `configure_logging()` | INFO |

## Run tests

```bash
uv sync
uv run pytest
```
