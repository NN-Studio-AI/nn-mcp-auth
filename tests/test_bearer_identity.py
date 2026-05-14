"""BearerAuthMiddleware: multi-token static map + subject propagation."""

from __future__ import annotations

import pytest
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route
from starlette.testclient import TestClient

from nn_mcp_auth import (
    BearerAuthMiddleware,
    MemoryOAuthStores,
    get_subject,
)


def _build_app(token, *, oauth_store=None):
    async def endpoint(request: Request) -> JSONResponse:
        return JSONResponse({"subject": get_subject(request.scope)})

    app = Starlette(routes=[Route("/mcp", endpoint, methods=["GET"])])
    app.add_middleware(
        BearerAuthMiddleware,
        token=token,
        protected_paths={"/mcp"},
        oauth_store=oauth_store,
    )
    return app


@pytest.fixture
def map_app() -> Starlette:
    return _build_app({"tok-ana": "ana", "tok-diretor": "diretor"})


@pytest.fixture
def str_app() -> Starlette:
    return _build_app("static-only-token")


def test_str_token_accepted_and_exposes_no_subject(str_app: Starlette) -> None:
    client = TestClient(str_app)
    response = client.get(
        "/mcp", headers={"authorization": "Bearer static-only-token"}
    )
    assert response.status_code == 200
    assert response.json() == {"subject": None}


def test_str_token_wrong_value_rejected(str_app: Starlette) -> None:
    client = TestClient(str_app)
    response = client.get("/mcp", headers={"authorization": "Bearer nope"})
    assert response.status_code == 401


def test_map_token_attaches_subject(map_app: Starlette) -> None:
    client = TestClient(map_app)
    response = client.get("/mcp", headers={"authorization": "Bearer tok-ana"})
    assert response.status_code == 200
    assert response.json() == {"subject": "ana"}


def test_map_token_attaches_different_subjects(map_app: Starlette) -> None:
    client = TestClient(map_app)
    response = client.get(
        "/mcp", headers={"authorization": "Bearer tok-diretor"}
    )
    assert response.status_code == 200
    assert response.json() == {"subject": "diretor"}


def test_map_unknown_token_rejected(map_app: Starlette) -> None:
    client = TestClient(map_app)
    response = client.get("/mcp", headers={"authorization": "Bearer mystery"})
    assert response.status_code == 401


def test_missing_authorization_rejected(map_app: Starlette) -> None:
    client = TestClient(map_app)
    response = client.get("/mcp")
    assert response.status_code == 401


def test_non_bearer_scheme_rejected(map_app: Starlette) -> None:
    client = TestClient(map_app)
    response = client.get(
        "/mcp", headers={"authorization": "Basic dXNlcjpwYXNz"}
    )
    assert response.status_code == 401


def test_empty_token_in_map_skipped() -> None:
    # An empty key in the map must not silently authenticate "Bearer "
    app = _build_app({"": "ghost", "tok-real": "real"})
    client = TestClient(app)
    bad = client.get("/mcp", headers={"authorization": "Bearer "})
    assert bad.status_code == 401
    good = client.get("/mcp", headers={"authorization": "Bearer tok-real"})
    assert good.status_code == 200
    assert good.json() == {"subject": "real"}


def test_oauth_fallback_still_works_with_map_token() -> None:
    stores = MemoryOAuthStores.create()
    issued_token, _ttl = stores.access.issue()
    app = _build_app({"tok-ana": "ana"}, oauth_store=stores.access)
    client = TestClient(app)
    response = client.get(
        "/mcp", headers={"authorization": f"Bearer {issued_token}"}
    )
    assert response.status_code == 200
    # OAuth tokens carry no identity yet — Phase 2.
    assert response.json() == {"subject": None}


def test_get_subject_accepts_scope_mapping() -> None:
    fake_scope = {"type": "http", "nn_mcp_auth.subject": "ana"}
    assert get_subject(fake_scope) == "ana"
    assert get_subject({"type": "http"}) is None
    assert get_subject("not a scope") is None
