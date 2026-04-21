import os
import sys

from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient
from starlette.requests import Request

sys.path.insert(0, os.path.abspath("../../../.."))

from litellm.proxy._types import UserAPIKeyAuth
from litellm.proxy.auth.user_api_key_auth import user_api_key_auth
from litellm.proxy.common_utils.debug_utils import router


def _make_app() -> FastAPI:
    app = FastAPI()
    app.include_router(router)
    return app


class TestDebugAsyncioTasksAuth:
    def test_unauthenticated_request_rejected(self):
        """GET /debug/asyncio-tasks without a key must be rejected (401/403)."""

        async def _reject(request: Request):
            raise HTTPException(status_code=401, detail="Unauthorized")

        app = _make_app()
        app.dependency_overrides[user_api_key_auth] = _reject
        client = TestClient(app, raise_server_exceptions=False)

        response = client.get("/debug/asyncio-tasks")

        assert response.status_code in (401, 403)

    def test_authenticated_request_succeeds(self):
        """GET /debug/asyncio-tasks with a valid key must return 200."""

        async def _allow(request: Request):
            return UserAPIKeyAuth(api_key="sk-test", user_id="test-user")

        app = _make_app()
        app.dependency_overrides[user_api_key_auth] = _allow
        client = TestClient(app, raise_server_exceptions=False)

        response = client.get(
            "/debug/asyncio-tasks",
            headers={"Authorization": "Bearer sk-test"},
        )

        assert response.status_code == 200
        data = response.json()
        assert "total_active_tasks" in data
        assert "by_name" in data


class TestMemoryUsageAuth:
    def test_unauthenticated_request_rejected(self, monkeypatch):
        """GET /memory-usage without a key must be rejected (401/403) when profiling enabled."""
        monkeypatch.setenv("LITELLM_PROFILE", "true")

        import importlib

        import litellm.proxy.common_utils.debug_utils as du

        importlib.reload(du)

        async def _reject(request: Request):
            raise HTTPException(status_code=401, detail="Unauthorized")

        app = FastAPI()
        app.include_router(du.router)
        app.dependency_overrides[user_api_key_auth] = _reject
        client = TestClient(app, raise_server_exceptions=False)

        response = client.get("/memory-usage")

        assert response.status_code in (401, 403)

        monkeypatch.delenv("LITELLM_PROFILE", raising=False)

    def test_authenticated_request_succeeds(self, monkeypatch):
        """GET /memory-usage with a valid key returns 200 when profiling enabled."""
        monkeypatch.setenv("LITELLM_PROFILE", "true")

        import importlib

        import litellm.proxy.common_utils.debug_utils as du

        importlib.reload(du)

        async def _allow(request: Request):
            return UserAPIKeyAuth(api_key="sk-test", user_id="test-user")

        app = FastAPI()
        app.include_router(du.router)
        app.dependency_overrides[user_api_key_auth] = _allow
        client = TestClient(app, raise_server_exceptions=False)

        response = client.get(
            "/memory-usage",
            headers={"Authorization": "Bearer sk-test"},
        )

        assert response.status_code == 200
        data = response.json()
        assert "top_50_memory_usage" in data

        monkeypatch.delenv("LITELLM_PROFILE", raising=False)
