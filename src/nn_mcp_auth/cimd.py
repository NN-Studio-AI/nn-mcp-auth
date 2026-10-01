"""OAuth Client ID Metadata Documents (draft-ietf-oauth-client-id-metadata-document).

A client identifies itself with an HTTPS URL (e.g.
``https://chatgpt.com/oauth/client.json``) that serves a JSON document with
its name, redirect URIs and token-endpoint authentication method. The
authorization server fetches that document instead of requiring the client to
be pre-registered, so a ChatGPT or Claude connector only needs the person to
log in.

Security posture of this implementation:

- only hosts in ``OAUTH_CIMD_ALLOWED_HOSTS`` (and their subdomains) are fetched;
- the URL must be ``https`` with a path, no userinfo/fragment/dot segments,
  no IP literal nor ``localhost``, and must resolve to public addresses;
- redirects are never followed and documents are capped in size;
- ``private_key_jwt`` assertions are verified against the document's keys with
  issuer, subject, audience, lifetime and single-use ``jti`` checks;
- the endpoint factory only enables CIMD when a person login (Entra or
  password) is configured, so an auto-approving server never hands tokens to
  arbitrary clients.
"""

from __future__ import annotations

import ipaddress
import logging
import re
import socket
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, Final, Protocol
from urllib.parse import urlsplit

import httpx
import jwt
from starlette.concurrency import run_in_threadpool

from .errors import NnMcpAuthError
from .jwks import SUPPORTED_JWS_ALGORITHMS, JwksCache, JwksError, StaticJwks
from .runtime import log_json

LOGGER = logging.getLogger("nn_mcp_auth")

CIMD_HTTP_TIMEOUT_SECONDS: Final[float] = 10.0
CIMD_MAX_DOCUMENT_BYTES: Final[int] = 16 * 1024
CIMD_DEFAULT_CACHE_SECONDS: Final[int] = 3600
CIMD_MIN_CACHE_SECONDS: Final[int] = 60
CIMD_MAX_CACHE_SECONDS: Final[int] = 86_400
CIMD_AUTH_METHODS: Final[frozenset[str]] = frozenset({"none", "private_key_jwt"})
CLIENT_ASSERTION_TYPE_JWT_BEARER: Final[str] = (
    "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
)
CLIENT_ASSERTION_MAX_LIFETIME_SECONDS: Final[int] = 600
CLIENT_ASSERTION_CLOCK_SKEW_SECONDS: Final[int] = 60

_MAX_AGE_RE: Final[re.Pattern[str]] = re.compile(r"(?:^|[,\s])max-age=(\d+)", re.IGNORECASE)
_HOSTNAME_RE: Final[re.Pattern[str]] = re.compile(
    r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,62}$"
)

HostResolver = Callable[[str], list[str]]


class ClientMetadataError(NnMcpAuthError):
    """The client identifier or its metadata document was rejected.

    ``reason`` is a short machine-readable tag safe for logs.
    """

    def __init__(self, reason: str) -> None:
        super().__init__(f"Client ID Metadata Document rejected: {reason}")
        self.reason = reason


@dataclass(frozen=True, slots=True)
class ClientMetadata:
    """The subset of a client metadata document this library acts on."""

    client_id: str
    host: str
    client_name: str
    redirect_uris: tuple[str, ...]
    auth_methods: frozenset[str]
    jwks_uri: str | None = None
    jwks: dict[str, Any] | None = None
    signing_alg: str | None = None

    def allows(self, method: str) -> bool:
        return method in self.auth_methods

    def is_redirect_uri_allowed(self, redirect_uri: str) -> bool:
        return bool(redirect_uri) and redirect_uri in self.redirect_uris


def is_client_id_url(value: str) -> bool:
    """``True`` when a ``client_id`` looks like a metadata document URL."""

    return value[:8].lower() == "https://"


def validate_client_id_url(value: str) -> str:
    """Enforce the draft's URL constraints (section 3); returns the lower-cased host."""

    if "#" in value:
        raise ClientMetadataError("client_id_fragment")
    parts = urlsplit(value)
    if parts.scheme != "https":
        raise ClientMetadataError("client_id_scheme")
    if "@" in parts.netloc or parts.username is not None or parts.password is not None:
        raise ClientMetadataError("client_id_userinfo")
    host = (parts.hostname or "").lower()
    if not host:
        raise ClientMetadataError("client_id_host")
    if not parts.path or parts.path == "/":
        raise ClientMetadataError("client_id_path")
    if any(segment in (".", "..") for segment in parts.path.split("/")):
        raise ClientMetadataError("client_id_dot_segments")
    if host == "localhost" or host.endswith(".localhost") or _is_ip_literal(host):
        raise ClientMetadataError("client_id_host")
    if not _HOSTNAME_RE.match(host):
        raise ClientMetadataError("client_id_host")
    return host


def _is_ip_literal(host: str) -> bool:
    try:
        ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        return False
    return True


def _resolve_host(host: str) -> list[str]:
    infos = socket.getaddrinfo(host, 443, proto=socket.IPPROTO_TCP)
    return [str(info[4][0]) for info in infos]


def _cache_ttl(cache_control: str | None) -> int:
    ttl = CIMD_DEFAULT_CACHE_SECONDS
    if cache_control:
        match = _MAX_AGE_RE.search(cache_control)
        if match:
            ttl = int(match.group(1))
    return max(CIMD_MIN_CACHE_SECONDS, min(CIMD_MAX_CACHE_SECONDS, ttl))


def parse_client_metadata(client_id: str, data: Any) -> ClientMetadata:
    """Validate a fetched document (draft sections 4 and 4.1)."""

    if not isinstance(data, dict):
        raise ClientMetadataError("document_not_object")
    if data.get("client_id") != client_id:
        raise ClientMetadataError("document_client_id_mismatch")
    if "client_secret" in data or "client_secret_expires_at" in data:
        raise ClientMetadataError("document_has_secret")

    raw_uris = data.get("redirect_uris")
    redirect_uris = tuple(
        uri for uri in (raw_uris if isinstance(raw_uris, list) else []) if isinstance(uri, str)
    )
    if not redirect_uris:
        raise ClientMetadataError("document_redirect_uris")
    for uri in redirect_uris:
        parts = urlsplit(uri)
        if parts.scheme not in ("https", "http") or not parts.netloc or "#" in uri:
            raise ClientMetadataError("document_redirect_uri_invalid")

    methods: set[str] = set()
    plural = data.get("token_endpoint_auth_methods_supported")
    if isinstance(plural, list):
        methods.update(m for m in plural if isinstance(m, str))
    singular = data.get("token_endpoint_auth_method")
    if isinstance(singular, str) and singular:
        methods.add(singular)
    if not methods:
        # RFC 7591 defaults to client_secret_basic, which section 4.1 forbids
        # for metadata documents; a document without a method is a public client.
        methods.add("none")
    auth_methods = frozenset(methods) & CIMD_AUTH_METHODS
    if not auth_methods:
        raise ClientMetadataError("document_auth_method")

    jwks_uri = data.get("jwks_uri")
    jwks = data.get("jwks")
    if jwks_uri is not None and (not isinstance(jwks_uri, str) or not jwks_uri):
        raise ClientMetadataError("document_jwks_uri")
    if jwks is not None and not isinstance(jwks, dict):
        raise ClientMetadataError("document_jwks")
    if "private_key_jwt" in auth_methods and not jwks_uri and not jwks:
        raise ClientMetadataError("document_jwks_missing")

    signing_alg = data.get("token_endpoint_auth_signing_alg")
    if signing_alg is not None and (
        not isinstance(signing_alg, str) or signing_alg not in SUPPORTED_JWS_ALGORITHMS
    ):
        raise ClientMetadataError("document_signing_alg")

    name = data.get("client_name")
    host = urlsplit(client_id).hostname or client_id
    return ClientMetadata(
        client_id=client_id,
        host=host.lower(),
        client_name=name.strip() if isinstance(name, str) and name.strip() else host,
        redirect_uris=redirect_uris,
        auth_methods=auth_methods,
        jwks_uri=jwks_uri if isinstance(jwks_uri, str) else None,
        jwks=jwks if isinstance(jwks, dict) else None,
        signing_alg=signing_alg if isinstance(signing_alg, str) else None,
    )


class ReplayGuard(Protocol):
    """What :meth:`ClientMetadataResolver.verify_client_assertion` needs to reject replays."""

    def claim(self, key: str, ttl_seconds: int) -> bool:
        """Record ``key`` for ``ttl_seconds``; ``False`` when it was already recorded."""


class ClientMetadataResolver:
    """Fetches, validates and caches client metadata documents for allowed hosts."""

    def __init__(
        self,
        *,
        allowed_hosts: tuple[str, ...],
        clock: Callable[[], float] = time.monotonic,
        host_resolver: HostResolver | None = None,
    ) -> None:
        self._allowed_hosts = frozenset(h.strip().lower() for h in allowed_hosts if h.strip())
        self._clock = clock
        self._resolve_host = host_resolver or _resolve_host
        self._documents: dict[str, tuple[ClientMetadata, float]] = {}
        self._jwks: dict[str, JwksCache] = {}

    @property
    def allowed_hosts(self) -> frozenset[str]:
        return self._allowed_hosts

    def is_host_allowed(self, host: str) -> bool:
        host = host.lower()
        return any(
            host == allowed or host.endswith("." + allowed) for allowed in self._allowed_hosts
        )

    async def resolve(self, client_id: str) -> ClientMetadata:
        """Return the (cached) metadata for ``client_id`` or raise :class:`ClientMetadataError`."""

        host = validate_client_id_url(client_id)
        if not self.is_host_allowed(host):
            raise ClientMetadataError("host_not_allowed")

        cached = self._documents.get(client_id)
        now = self._clock()
        if cached is not None and cached[1] > now:
            return cached[0]

        await self._assert_public_host(host)
        try:
            async with httpx.AsyncClient(
                timeout=CIMD_HTTP_TIMEOUT_SECONDS, follow_redirects=False
            ) as client:
                response = await client.get(
                    client_id, headers={"Accept": "application/json", "User-Agent": "nn-mcp-auth"}
                )
        except httpx.HTTPError as exc:
            raise ClientMetadataError("document_unreachable") from exc
        if response.status_code != 200:
            raise ClientMetadataError("document_status")
        if len(response.content) > CIMD_MAX_DOCUMENT_BYTES:
            raise ClientMetadataError("document_too_large")
        try:
            data = response.json()
        except ValueError as exc:
            raise ClientMetadataError("document_invalid_json") from exc

        metadata = parse_client_metadata(client_id, data)
        if metadata.jwks_uri is not None:
            jwks_host = validate_client_id_url(metadata.jwks_uri)
            if not self.is_host_allowed(jwks_host):
                raise ClientMetadataError("document_jwks_uri")
        ttl = _cache_ttl(response.headers.get("cache-control"))
        self._documents[client_id] = (metadata, now + ttl)
        log_json(
            LOGGER,
            logging.INFO,
            "oauth_cimd_document_loaded",
            client_id=client_id,
            client_name=metadata.client_name,
            auth_methods=sorted(metadata.auth_methods),
            cache_seconds=ttl,
        )
        return metadata

    async def verify_client_assertion(
        self,
        assertion: str,
        metadata: ClientMetadata,
        *,
        token_endpoint: str,
        issuer: str,
        replay_guard: ReplayGuard,
    ) -> None:
        """RFC 7523 ``private_key_jwt``: signature, iss/sub, aud, lifetime and single-use jti."""

        try:
            header = jwt.get_unverified_header(assertion)
        except jwt.PyJWTError as exc:
            raise ClientMetadataError("assertion_malformed") from exc
        alg = header.get("alg")
        if not isinstance(alg, str) or alg not in SUPPORTED_JWS_ALGORITHMS:
            raise ClientMetadataError("assertion_alg")
        if metadata.signing_alg and alg != metadata.signing_alg:
            raise ClientMetadataError("assertion_alg")
        kid = header.get("kid")
        if not isinstance(kid, str) or not kid:
            raise ClientMetadataError("assertion_kid")

        try:
            key = await self._client_keys(metadata).signing_key(kid)
        except JwksError as exc:
            raise ClientMetadataError(f"assertion_key:{exc.reason}") from exc

        try:
            claims = jwt.decode(
                assertion,
                key=key,
                algorithms=[alg],
                audience=[token_endpoint, issuer],
                issuer=metadata.client_id,
                leeway=CLIENT_ASSERTION_CLOCK_SKEW_SECONDS,
                options={"require": ["exp", "iss", "sub", "aud", "jti"]},
            )
        except jwt.PyJWTError as exc:
            raise ClientMetadataError(f"assertion_invalid:{type(exc).__name__}") from exc

        if claims.get("sub") != metadata.client_id:
            raise ClientMetadataError("assertion_subject")
        exp = claims.get("exp")
        now = time.time()
        if not isinstance(exp, int | float) or (
            exp - now > CLIENT_ASSERTION_MAX_LIFETIME_SECONDS + CLIENT_ASSERTION_CLOCK_SKEW_SECONDS
        ):
            raise ClientMetadataError("assertion_lifetime")
        jti = claims.get("jti")
        if not isinstance(jti, str) or not jti:
            raise ClientMetadataError("assertion_jti")
        ttl = int(max(1.0, exp - now)) + CLIENT_ASSERTION_CLOCK_SKEW_SECONDS
        if not replay_guard.claim(f"{metadata.client_id}|{jti}", ttl):
            raise ClientMetadataError("assertion_replayed")

    def _client_keys(self, metadata: ClientMetadata) -> JwksCache | StaticJwks:
        if metadata.jwks_uri:
            cache = self._jwks.get(metadata.jwks_uri)
            if cache is None:
                cache = JwksCache(
                    metadata.jwks_uri,
                    clock=self._clock,
                    failure_event="oauth_cimd_jwks_refresh_failed",
                )
                self._jwks[metadata.jwks_uri] = cache
            return cache
        return StaticJwks(metadata.jwks or {})

    async def _assert_public_host(self, host: str) -> None:
        try:
            addresses = await run_in_threadpool(self._resolve_host, host)
        except OSError as exc:
            raise ClientMetadataError("host_unresolvable") from exc
        if not addresses:
            raise ClientMetadataError("host_unresolvable")
        for address in addresses:
            try:
                parsed = ipaddress.ip_address(address)
            except ValueError as exc:
                raise ClientMetadataError("host_not_public") from exc
            if not parsed.is_global:
                raise ClientMetadataError("host_not_public")
