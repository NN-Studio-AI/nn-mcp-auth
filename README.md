# nn-mcp-auth

Shared library that gives every NN Studio MCP server the same OAuth 2.0 + bearer-token plumbing without copy-pasting 700 LOC per repo.

Implements the three grant types that claude.ai custom connectors and headless service-to-service callers need:

- **Authorization Code with PKCE** (RFC 6749 §4.1 + RFC 7636) — for OAuth UIs like the claude.ai "Vincular" flow
- **Refresh Token rotation** (RFC 6749 §6) — claude.ai rotates on every refresh
- **Client Credentials** (RFC 6749 §4.4) — for headless callers holding `client_id` + `client_secret`

Plus a `BearerAuthMiddleware` that protects MCP routes with either the static `MCP_AUTH_TOKEN` or an OAuth-issued access token, an RFC 8414 metadata endpoint (also served at `/.well-known/openid-configuration`), RFC 9728 protected-resource metadata, and an optional login page on `/authorize` (see [Tela de login](#tela-de-login)).

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
| `OAUTH_ALLOWED_REDIRECT_URIS` | CSV of allowed redirect URIs for code grant | claude.ai, claude.com, chatgpt.com and chat.openai.com callbacks |
| `OAUTH_ISSUER_URL` | Issuer URL announced in metadata and sent as `iss` (RFC 9207) | derived from request scheme/host |
| `OAUTH_LOGIN_USERNAME` | Username required by the `/authorize` login page | — (empty keeps auto-approve) |
| `OAUTH_LOGIN_PASSWORD` | Password for the login page: plain text or `scrypt$<salt_b64>$<hash_b64>` | — (empty keeps auto-approve) |
| `OAUTH_ENTRA_TENANT_ID` | Microsoft Entra ID tenant GUID (Directory ID); with the two vars below, `/authorize` logs the person in via Entra (see [Login com Microsoft Entra ID](#login-com-microsoft-entra-id)) | — (empty disables the Entra login) |
| `OAUTH_ENTRA_CLIENT_ID` | Application (client) ID of the app registration | — |
| `OAUTH_ENTRA_CLIENT_SECRET` | Client secret of the app registration | — |
| `OAUTH_ENTRA_ALLOWED_UPNS` | CSV of e-mails/UPNs allowed to log in | — (any user of the tenant) |
| `OAUTH_CIMD_ENABLED` | Accept clients identified by a Client ID Metadata Document URL (see [Clientes por Client ID Metadata Document](#clientes-por-client-id-metadata-document)); only effective when a person login is configured | `true` |
| `OAUTH_CIMD_ALLOWED_HOSTS` | CSV of hosts (plus subdomains) whose metadata documents are trusted | `chatgpt.com,claude.ai,claude.com` |
| `REDIS_URL` | `redis://host:port[/db]` | required for `RedisOAuthStores.from_env()` |
| `REDIS_KEY_PREFIX` | Namespace per MCP, e.g. `mcp:whatsapp` | required |
| `LOG_LEVEL` | Stdlib log level for `configure_logging()` | INFO |

Default `OAUTH_ALLOWED_REDIRECT_URIS` (used when the var is unset):

- `https://claude.ai/api/mcp/auth_callback`
- `https://claude.com/api/mcp/auth_callback`
- `https://chatgpt.com/connector_platform_oauth_redirect`
- `https://chat.openai.com/connector_platform_oauth_redirect`

## Clientes por Client ID Metadata Document

A partir da 0.4.0 um cliente não precisa de `OAUTH_CLIENT_ID`/`OAUTH_CLIENT_SECRET`
pré-combinados: ele pode se identificar com uma URL HTTPS que serve o seu
documento de metadados ([draft-ietf-oauth-client-id-metadata-document](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-client-id-metadata-document),
mecanismo padrão da especificação MCP 2026-07-28). É o que o ChatGPT faz com
`client_id=https://chatgpt.com/oauth/client.json`: na hora de conectar o
conector, a pessoa só faz o login e pronto.

Como funciona:

1. A metadata RFC 8414 anuncia `client_id_metadata_document_supported: true`,
   `token_endpoint_auth_methods_supported` com `private_key_jwt` e `none` e
   `token_endpoint_auth_signing_alg_values_supported`.
2. `GET /authorize` com `client_id` em forma de URL: a URL precisa ser `https`,
   ter caminho, não ter userinfo, fragmento nem segmentos `.`/`..`, não ser IP
   nem `localhost`, e o host precisa estar em `OAUTH_CIMD_ALLOWED_HOSTS` (ou ser
   subdomínio de um deles) e resolver para endereços públicos. Só então o
   documento é buscado (sem seguir redirects, no máximo 16 KiB) e validado:
   `client_id` igual à URL, `redirect_uris` contendo o `redirect_uri` pedido,
   nenhum segredo embutido, método de autenticação `none` ou `private_key_jwt`
   (com `jwks_uri` no mesmo domínio confiável ou `jwks` embutido). O documento
   fica em cache respeitando `Cache-Control: max-age` (entre 60 s e 24 h).
3. A pessoa faz o login (Entra ou senha) como em qualquer cliente.
4. `POST /token`: com `client_assertion` (`private_key_jwt`, o que o ChatGPT
   prefere), a assinatura é verificada pela chave do documento e os claims
   `iss`/`sub` = `client_id`, `aud` = token endpoint ou issuer, `exp` (até 10
   minutos) e `jti` de uso único (guardado no Redis/memória) são conferidos. Sem
   assertion, o cliente precisa permitir `none` no documento (PKCE obrigatório).
5. Os refresh tokens ficam presos ao cliente que os recebeu: um refresh emitido
   ao ChatGPT não serve ao cliente pré-configurado e vice-versa.
   `client_credentials` continua exclusivo do cliente pré-configurado.

Regra de segurança: CIMD só fica ativo quando existe login de pessoa
(`OAUTH_ENTRA_*` ou `OAUTH_LOGIN_*`). Num MCP em aprovação automática ele é
ignorado e não é anunciado, porque qualquer cliente que soubesse a URL do
servidor ganharia tokens. `OAUTH_CIMD_ENABLED=false` desliga de vez.

Logs: `oauth_cimd_document_loaded`, `oauth_cimd_rejected` (com `reason`) e
`oauth_cimd_assertion_rejected`.

## Login com Microsoft Entra ID

Modo principal de login. Com `OAUTH_ENTRA_TENANT_ID`, `OAUTH_ENTRA_CLIENT_ID` e
`OAUTH_ENTRA_CLIENT_SECRET` preenchidas, `GET /authorize` deixa de aprovar
automaticamente (e ignora a tela de usuário/senha) e passa a autenticar a
pessoa na Microsoft:

1. `GET /authorize` valida `client_id`, `redirect_uri` e PKCE como sempre,
   guarda o pedido pendente (10 minutos, single-use, com um `nonce` novo) e
   redireciona o navegador para
   `https://login.microsoftonline.com/{tenant}/oauth2/v2.0/authorize` com
   `scope=openid profile email`, `state` = id do pedido pendente e o `nonce`.
   Nenhum `prompt` é enviado: quem já está logado na Microsoft naquele
   navegador volta sem digitar nada (SSO).
2. A Microsoft devolve para `{OAUTH_ISSUER_URL}/oauth/entra/callback?code&state`.
3. O callback consome o pedido pendente, troca o `code` no endpoint de token
   do tenant **no servidor** (o client secret nunca vai ao navegador) e valida
   o `id_token`: assinatura RS256 contra o JWKS do tenant (cache de 1 hora,
   refetch em rotação de chave no máximo a cada 30 s), `iss`, `aud`, `exp`,
   `nonce` e `tid`.
4. Se `OAUTH_ENTRA_ALLOWED_UPNS` estiver preenchida, o `preferred_username`
   precisa estar na lista (comparação sem maiúsculas). Fora da lista → página
   `403` em português. Sem lista, qualquer usuário do tenant entra.
5. Só então a biblioteca emite o **próprio** authorization code, com o UPN da
   pessoa como `subject`, e redireciona ao cliente com `code`, `state` e `iss`.

A identidade viaja com o code até o access token e o refresh token (a rotação
preserva), e o `BearerAuthMiddleware` a expõe por `get_subject(request)` em
toda chamada ao MCP. `client_credentials` e o bearer fixo continuam anônimos e
sem login.

Falhas (state desconhecido ou reutilizado, code inválido, troca recusada,
`id_token` inválido, usuário fora da lista, erro devolvido pela Microsoft)
nunca redirecionam ao cliente: respondem uma página HTML em português
(`400`/`401`/`403`, mesma CSP da tela de login) e a pessoa reinicia a conexão
pelo aplicativo. Logs: `oauth_login_succeeded` (com `mode=entra` e `subject`),
`oauth_entra_failed` (com `reason` curto, sem tokens), `oauth_entra_forbidden`,
`oauth_entra_denied` e `oauth_entra_state_invalid`.

### App registration (Azure Portal → Microsoft Entra ID → App registrations)

- **Supported account types:** somente o tenant da organização (single-tenant).
- **Redirect URI (plataforma Web):** `{OAUTH_ISSUER_URL}/oauth/entra/callback`,
  um por MCP (ex.: `https://mcp-resend.nnstudio.ai/oauth/entra/callback`).
- **Certificates & secrets:** um client secret → `OAUTH_ENTRA_CLIENT_SECRET`.
- **API permissions:** apenas `openid`, `profile` e `email` (Microsoft Graph,
  delegadas). Nada de `User.Read.All` ou permissões de aplicação.
- **Overview:** `Application (client) ID` → `OAUTH_ENTRA_CLIENT_ID`;
  `Directory (tenant) ID` → `OAUTH_ENTRA_TENANT_ID` (o GUID, não o domínio).
- `OAUTH_ISSUER_URL` precisa ser a origin pública do MCP, porque ela compõe o
  redirect URI enviado à Microsoft.

Precedência dos modos de `/authorize`: Entra (`OAUTH_ENTRA_*`) > usuário/senha
(`OAUTH_LOGIN_*`) > aprovação automática (nenhuma das duas). As três vars do
Entra devem ser definidas juntas ou ficar todas vazias; combinação parcial é
`ConfigurationError` na carga.

## Tela de login

Por padrão (`OAUTH_LOGIN_USERNAME` e `OAUTH_LOGIN_PASSWORD` vazias) o
`GET /authorize` aprova automaticamente: valida `client_id`, `redirect_uri` e
PKCE e já redireciona com o `code`. Esse é o comportamento de todas as versões
até a `v0.2.2` e continua idêntico na `v0.3.0` quando as duas variáveis estão vazias.

Com as duas variáveis preenchidas, o fluxo passa a exigir login:

1. `GET /authorize` valida os parâmetros como antes, grava um *pending
   authorization request* no store (Redis ou memória) com id aleatório e TTL de
   10 minutos e responde uma página HTML de login em português (CSS inline, sem
   JavaScript, sem assets externos).
2. O formulário faz `POST /authorize` com `request_id`, `username` e `password`.
   As credenciais são comparadas em tempo constante (usuário e senha são sempre
   avaliados, sem curto-circuito).
3. Sucesso: o pending request é consumido (uso único, `GETDEL` no Redis), o
   `code` é emitido e a resposta é `302` para o `redirect_uri` com `code`,
   `state` e `iss` (RFC 9207). A metadata passa a anunciar
   `authorization_response_iss_parameter_supported: true`.
4. Erro: a página é re-renderizada com status `401` e a mensagem genérica
   "Usuário ou senha inválidos." (sem revelar qual campo errou). O mesmo
   `request_id` continua válido até expirar.
5. Rate limit: 10 tentativas de `POST /authorize` por IP a cada 10 minutos
   (janela fixa no store). Excedido, a resposta é `429` com a mesma página,
   mensagem em português e cabeçalho `Retry-After`.

Cabeçalhos da página: `Content-Security-Policy: default-src 'none';
style-src 'unsafe-inline'; form-action 'self' <origin do redirect_uri>;
frame-ancestors 'none'; base-uri 'none'`, `X-Frame-Options: DENY`,
`Cache-Control: no-store`, `Referrer-Policy: no-referrer`. A origin do
`redirect_uri` (sempre vinda da allowlist) entra no `form-action` porque os
navegadores aplicam essa diretiva também ao redirect que segue o POST do
formulário; só com `'self'` o `302` final para o cliente OAuth seria bloqueado.

`client_credentials` nunca passa pela tela de login. `refresh_token` também não.

Logs: os eventos `oauth_login_succeeded`, `oauth_login_failed`,
`oauth_login_rate_limited` e `oauth_login_request_invalid` saem no logger
`nn_mcp_auth` com `client_ip` (nunca usuário ou senha). Chame
`configure_logging(logger_name="nn_mcp_auth")` no entrypoint do MCP para
recebê-los como JSON.

### Senha em hash

`OAUTH_LOGIN_PASSWORD` aceita texto puro ou hash scrypt
(`scrypt$<salt_b64>$<hash_b64>`, N=16384, r=8, p=1, os mesmos defaults do
`crypto.scryptSync` do Node). Para gerar o hash:

```bash
uv run python -m nn_mcp_auth.hash_password            # pergunta a senha duas vezes
printf '%s' "$SENHA" | uv run python -m nn_mcp_auth.hash_password
```

Só o hash vai para o stdout. Um valor que começa com `scrypt$` mas está
malformado derruba a carga da configuração com `ConfigurationError` (o valor
não aparece na mensagem). Preencher só uma das duas variáveis também gera
`ConfigurationError`, no mesmo padrão de `OAUTH_CLIENT_ID`/`OAUTH_CLIENT_SECRET`.

### IP do cliente atrás de proxy

O rate limit usa `request.client.host`, que respeita o tratamento de proxy do
uvicorn. Atrás do Traefik do Coolify, configure `FORWARDED_ALLOW_IPS` (ex.:
`FORWARDED_ALLOW_IPS=*` quando só o Traefik alcança o container; por padrão o
Traefik descarta o `X-Forwarded-For` enviado por clientes não confiáveis e grava
o IP real) para que cada usuário tenha a própria janela; sem isso todos
compartilham o IP do proxy e o
limite passa a ser global (mais restritivo, nunca mais permissivo). O cabeçalho
`X-Forwarded-For` cru não é lido pela biblioteca, para não permitir contornar o
limite trocando o cabeçalho.

### Stores

`RedisOAuthStores` e `MemoryOAuthStores.create()` já trazem os stores novos
(`pending` e `login_limiter`). Quem monta `OAuthStores(access=..., refresh=...,
code=...)` na mão continua funcionando: com o login ligado, a biblioteca usa
versões em memória como fallback (ok para uma réplica; prefira Redis).

Chaves novas no Redis:

- `{prefix}:pending_authz:{id}` → JSON do pedido (TTL 600 s)
- `{prefix}:login_attempts:{ip}` → contador (TTL 600 s)

## Run tests

```bash
uv sync --python 3.12 --extra dev
uv run pytest
uv run ruff check
uv run mypy src tests
```
