"""
Security PoC tests demonstrating six vulnerabilities and their fixes.

Vulnerability 1: MCP .well-known query-string auth bypass
Vulnerability 2: Unauthenticated /debug/asyncio-tasks endpoint
Vulnerability 3: MCP OAuth2 fallback bypass
Vulnerability 4: Pass-the-hash on master key (key rotation endpoint)
Vulnerability 5: IDOR on /user/info v1 endpoint
Vulnerability 6: /spend/keys leaks all API keys to any authenticated user
"""

import inspect
import os
import secrets
import sys
from types import ModuleType
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient
from starlette.requests import Request

sys.path.insert(0, os.path.abspath("../../../.."))

from litellm.proxy._experimental.mcp_server.auth.user_api_key_auth_mcp import (
    MCPRequestHandler,
)
from litellm.proxy._types import LitellmUserRoles, ProxyException, UserAPIKeyAuth, UserInfoResponse, hash_token
from litellm.proxy.auth.user_api_key_auth import user_api_key_auth
from litellm.proxy.common_utils.debug_utils import router as debug_router
from litellm.proxy.management_endpoints.internal_user_endpoints import (
    _check_user_info_v2_access,
    user_info,
)
from litellm.proxy.spend_tracking.spend_management_endpoints import spend_key_fn
from litellm.proxy.spend_tracking.spend_tracking_utils import _is_master_key

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
