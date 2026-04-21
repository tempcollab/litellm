"""
Security PoC tests demonstrating two vulnerabilities and their fixes.

Vulnerability 1: MCP .well-known query-string auth bypass
Vulnerability 2: Unauthenticated /debug/asyncio-tasks endpoint
"""

import os
import sys
from unittest.mock import patch

import pytest
from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient
from starlette.requests import Request

sys.path.insert(0, os.path.abspath("../../../.."))

from litellm.proxy._experimental.mcp_server.auth.user_api_key_auth_mcp import (
    MCPRequestHandler,
)
from litellm.proxy._types import UserAPIKeyAuth
from litellm.proxy.auth.user_api_key_auth import user_api_key_auth
from litellm.proxy.common_utils.debug_utils import router as debug_router

EXPLOIT_PATH = "/v1/mcp/tools"
EXPLOIT_QUERY = b"x=.well-known"
WELL_KNOWN_PATH = "/.well-known/oauth-authorization-server"


def _build_scope(path: str, query_string: bytes, headers: list) -> dict:
    return {
        "type": "http",
        "method": "GET",
        "path": path,
        "query_string": query_string,
        "headers": headers,
        "scheme": "http",
        "server": ("testserver", 80),
        "root_path": "",
    }


@pytest.mark.asyncio
class TestWellKnownQueryStringBypass:
    """
    PoC tests for MCP authentication bypass via .well-known in the query string.

    Vulnerability description:
        The original check `'.well-known' in str(request.url)` matched any URL that
        contained the substring ".well-known" anywhere, including in the query string.
        An attacker could send GET /v1/mcp/tools?x=.well-known and skip authentication
        entirely, receiving an anonymous UserAPIKeyAuth() without LiteLLM ever calling
        user_api_key_auth to validate the request.

    Severity: Critical - Authentication Bypass
    """

    async def test_vulnerable_pattern_bypassed_by_query_string(self):
        """
        Demonstrates the vulnerable string-matching pattern.

        Exploit:
            GET /v1/mcp/tools?x=.well-known

        With the vulnerable check `'.well-known' in str(request.url)`, the query
        string matches and auth is skipped. This test proves the substring ".well-known"
        appears in the full URL string even when it is only in the query string.

        Impact: Any unauthenticated client can enumerate tools, invoke MCP methods, and
        access any resource exposed via the MCP server by appending ?x=.well-known.

        Severity: Critical - Authentication Bypass
        """
        scope = _build_scope(EXPLOIT_PATH, EXPLOIT_QUERY, [])
        request = Request(scope=scope)

        # Prove the vulnerable check would fire: ".well-known" IS in the full URL string
        full_url = str(request.url)
        assert ".well-known" in full_url, (
            f"Expected '.well-known' to appear in full URL '{full_url}' via query string"
        )
        # Confirm it is NOT in the path component
        assert ".well-known" not in request.url.path, (
            "'.well-known' should not be in the path for the exploit URL"
        )

    async def test_fixed_pattern_not_bypassed_by_query_string(self):
        """
        Demonstrates the fixed string-matching pattern.

        Fix:
            Replace `'.well-known' in str(request.url)` with
            `'/.well-known' in request.url.path`

        With the fixed check, the exploit URL /v1/mcp/tools?x=.well-known does NOT
        match, so authentication proceeds normally.

        Severity: Critical - Authentication Bypass (remediated)
        """
        scope = _build_scope(EXPLOIT_PATH, EXPLOIT_QUERY, [])
        request = Request(scope=scope)

        # Prove the fixed check does NOT fire for the exploit URL
        assert "/.well-known" not in request.url.path, (
            f"Fixed check should not match path '{request.url.path}' for exploit URL"
        )

    async def test_legitimate_well_known_path_still_works(self):
        """
        Confirms the fix does not break legitimate .well-known routes.

        A legitimate OAuth discovery request to /.well-known/oauth-authorization-server
        must still be treated as a public route (no auth required).

        Both the vulnerable and fixed patterns should match a genuine /.well-known path.

        Severity: N/A - Regression check
        """
        scope = _build_scope(WELL_KNOWN_PATH, b"", [])
        request = Request(scope=scope)

        # Both patterns match a legitimate .well-known path
        full_url = str(request.url)
        assert ".well-known" in full_url, (
            "Vulnerable pattern should still match legitimate .well-known path"
        )
        assert "/.well-known" in request.url.path, (
            "Fixed pattern should still match legitimate .well-known path"
        )

    async def test_full_exploit_flow_vulnerable_vs_fixed(self):
        """
        Full end-to-end PoC using the real (patched) process_mcp_request.

        Exploit attempt:
            Send GET /v1/mcp/tools?x=.well-known with a valid api key header.

        Expected behaviour after the fix:
            user_api_key_auth IS called (bypass blocked). The fixed check
            `'/.well-known' in request.url.path` does not match the exploit URL,
            so the code falls through to the real auth function.

        Exploit simulation (without fix):
            A local helper reproduces the vulnerable check inline to confirm the
            bypass would have succeeded: it returns an anonymous UserAPIKeyAuth()
            without ever calling the mock, because ".well-known" is in str(request.url).

        Severity: Critical - Authentication Bypass (fixed)
        """
        exploit_scope = _build_scope(
            EXPLOIT_PATH,
            EXPLOIT_QUERY,
            [(b"x-litellm-api-key", b"sk-test")],
        )

        async def _allow(api_key: str, request: Request) -> UserAPIKeyAuth:
            return UserAPIKeyAuth(api_key=api_key, user_id="test-user")

        # --- Part A: Fixed code blocks the exploit ---
        # Mock _get_mcp_client_side_auth_header_name to avoid importing proxy_server
        # (which requires optional dependencies not present in unit test environments).
        with patch.object(
            MCPRequestHandler,
            "_get_mcp_client_side_auth_header_name",
            return_value="x-mcp-auth",
        ), patch(
            "litellm.proxy._experimental.mcp_server.auth.user_api_key_auth_mcp.user_api_key_auth",
            side_effect=_allow,
        ) as mock_auth:
            (auth_result, *_) = await MCPRequestHandler.process_mcp_request(
                exploit_scope
            )

        # With the fix applied, auth IS called — bypass is blocked
        mock_auth.assert_called_once()
        # The key is stored hashed by UserAPIKeyAuth; check user_id instead to confirm
        # the correct auth object was returned from our _allow stub
        assert auth_result.user_id == "test-user"

        # --- Part B: Simulate what the vulnerable code would have done ---
        # Reproduce the vulnerable check inline to prove the bypass would have worked
        request = Request(scope=exploit_scope)
        vulnerable_check_fired = ".well-known" in str(request.url)
        assert vulnerable_check_fired, (
            "The vulnerable pattern '.well-known' in str(request.url) fires for the "
            "exploit URL, meaning an anonymous UserAPIKeyAuth() would have been returned "
            "without calling user_api_key_auth — proving the bypass was exploitable."
        )

        # Confirm anonymous auth would be returned under the vulnerable check
        if vulnerable_check_fired:
            simulated_vulnerable_result = UserAPIKeyAuth()
            assert simulated_vulnerable_result.api_key is None, (
                "Anonymous UserAPIKeyAuth has no api_key — anyone could call MCP endpoints"
            )


class TestDebugEndpointUnauthenticated:
    """
    PoC tests for unauthenticated access to the /debug/asyncio-tasks endpoint.

    Vulnerability description:
        Before the fix, the GET /debug/asyncio-tasks endpoint had no authentication
        dependency. Any unauthenticated client could call it and receive the full list
        of active asyncio task coroutine names, revealing internal proxy architecture,
        active background jobs, provider names, and timing information.

    Severity: Medium - Information Disclosure
    """

    def test_vulnerable_endpoint_no_auth_dependency(self):
        """
        Demonstrates the vulnerability: an endpoint with no auth dependency returns 200
        to any unauthenticated caller.

        Exploit:
            GET /debug/asyncio-tasks  (no Authorization header)

        Impact:
            An unauthenticated attacker receives coroutine names such as:
            - "send_usage_data_to_litellm_server" (reveals proxy is a LiteLLM instance)
            - "async_log_success_event" (reveals logging pipeline architecture)
            - "run_redis_cache_flush" (reveals Redis usage and data residency)
            - "flush_spend_logs_to_db" (reveals spend-tracking and database config)
            This intelligence can be used to tailor further attacks.

        Severity: Medium - Information Disclosure
        """
        import asyncio

        vulnerable_app = FastAPI()

        # Simulate the original unprotected endpoint (no Depends(user_api_key_auth))
        @vulnerable_app.get("/debug/asyncio-tasks")
        async def unprotected_get_active_tasks_stats():
            all_tasks = asyncio.all_tasks()
            active_tasks = [t for t in all_tasks if not t.done()]
            return {
                "total_active_tasks": len(active_tasks),
                "by_name": {},
            }

        client = TestClient(vulnerable_app, raise_server_exceptions=False)
        response = client.get("/debug/asyncio-tasks")

        # An unauthenticated request succeeds against the vulnerable endpoint
        assert response.status_code == 200, (
            f"Vulnerable endpoint returned {response.status_code} — expected 200. "
            "A real deployment without auth would return 200 to any caller."
        )
        data = response.json()
        assert "total_active_tasks" in data

    def test_fixed_endpoint_requires_auth(self):
        """
        Confirms the fix: the real router with Depends(user_api_key_auth) rejects
        unauthenticated requests.

        Fix applied:
            @router.get("/debug/asyncio-tasks", dependencies=[Depends(user_api_key_auth)])

        With the fix, an unauthenticated request is rejected with 401/403.

        Implementation note:
            FastAPI captures the dependency function object at decoration time when using
            `dependencies=[Depends(fn)]`. To intercept it in tests, we use
            `app.dependency_overrides` which FastAPI checks at request dispatch time.

        Severity: Medium - Information Disclosure (remediated)
        """

        async def _reject(request: Request) -> None:
            raise HTTPException(status_code=401, detail="Unauthorized")

        app = FastAPI()
        app.include_router(debug_router)
        app.dependency_overrides[user_api_key_auth] = _reject
        client = TestClient(app, raise_server_exceptions=False)

        response = client.get("/debug/asyncio-tasks")

        assert response.status_code in (401, 403), (
            f"Fixed endpoint must reject unauthenticated requests, got {response.status_code}"
        )

    def test_fixed_endpoint_allows_authenticated(self):
        """
        Confirms the fix still allows authenticated access.

        A valid API key results in 200 and returns the expected task statistics payload.

        Expected response:
            {"total_active_tasks": <int>, "by_name": {<coroutine_name>: <count>}}

        Implementation note:
            Uses `app.dependency_overrides` to replace the real `user_api_key_auth`
            dependency with a stub that returns a valid auth object, bypassing the
            actual key-validation logic for test isolation.

        Severity: N/A - Regression check
        """

        async def _allow(request: Request) -> UserAPIKeyAuth:
            return UserAPIKeyAuth(api_key="sk-test", user_id="test-user")

        app = FastAPI()
        app.include_router(debug_router)
        app.dependency_overrides[user_api_key_auth] = _allow
        client = TestClient(app, raise_server_exceptions=False)

        response = client.get(
            "/debug/asyncio-tasks",
            headers={"Authorization": "Bearer sk-test"},
        )

        assert response.status_code == 200, (
            f"Authenticated request to fixed endpoint should succeed, got {response.status_code}"
        )
        data = response.json()
        assert "total_active_tasks" in data, "Response must include 'total_active_tasks'"
        assert "by_name" in data, "Response must include 'by_name'"
        assert isinstance(data["total_active_tasks"], int)
        assert isinstance(data["by_name"], dict)
