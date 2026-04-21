# LiteLLM Proxy — Security Audit Report

| | |
|---|---|
| **Date** | 2026-04-21 |
| **Target** | LiteLLM proxy server, commit `b9bedc8153` on branch `litellm_internal_staging` |
| **Scope** | Authentication, authorization, and network request handling in the proxy server |
| **Method** | Static analysis → execution path tracing → live exploitation against a real proxy instance |
| **Tools** | AutoFyn (vulnerability discovery), Claude Code (verification and live exploitation) |
| **Reproduction** | `./tests/autofyn_audit/run_live_tests.sh` — fully automated, tears down after completion |

---

## Executive Summary

This audit identified **7 vulnerabilities** in the LiteLLM proxy server, all confirmed by live exploitation against a real instance backed by PostgreSQL. No mocks or simulated components were used.

The most severe finding is a **conditional full proxy takeover** (CHAIN-1) that combines two independent vulnerabilities: unauthenticated access to Prometheus metrics and a pass-the-hash flaw in the master key verification function. When the prerequisites are met, any user holding a low-privilege API key can rotate the master key and gain full administrative control of the proxy, including access to all configured LLM provider credentials.

Five additional vulnerabilities identified during initial static analysis were **disproved** through live testing and are documented in the appendix for transparency.

### Findings Overview

| ID | Title | Severity | CVSS 3.1 Est. | Prereqs |
|---|---|---|---|---|
| **CHAIN-1** | Full proxy takeover via `/metrics` + pass-the-hash | **Critical** | 9.1 | Prometheus enabled, metrics auth off (default when Prometheus is on), prior master-key usage, any valid API key |
| **F-5** | `_is_master_key()` accepts SHA-256 hash as credential | **Critical** | 9.1 | Knowledge of master key hash |
| **F-3** | Unauthenticated `/metrics/` exposes master key hash | **High** | 7.5 | Prometheus enabled, default metrics auth setting |
| **F-2** | `/spend/keys` returns all key rows to any internal user | **High** | 6.5 | Any `INTERNAL_USER` or `INTERNAL_USER_VIEW_ONLY` key |
| **F-6** | MCP OAuth discovery follows arbitrary URLs (SSRF) | **High** | 5.0 | Admin registers attacker-influenced MCP server |
| **F-4** | Unauthenticated `/token` endpoint | **Medium** | 5.3 | Stored malicious `token_url` via F-6 |
| **F-1** | Unauthenticated `/debug/asyncio-tasks` | **Low** | 3.7 | None |

---

## CHAIN-1: Conditional Full Proxy Takeover

**Severity:** Critical
**Components:** F-3 + F-5
**CWE:** CWE-836 (Use of Password Hash Instead of Password), CWE-306 (Missing Authentication)

### Prerequisites

All of the following must be true for this chain to be exploitable:

1. **Prometheus is enabled** — the proxy is configured with `callbacks: ["prometheus"]`.
2. **Metrics authentication is disabled** — `require_auth_for_metrics_endpoint` is `false` or unset. This is the default when Prometheus is enabled; LiteLLM provides this setting but does not enable it by default.
3. **The master key has been used for at least one request** — any request type (LLM completion, admin API call, health check) authenticated with the master key causes its SHA-256 hash to appear in Prometheus metric labels. We confirmed this includes non-LLM endpoints such as `/user/new`.
4. **The attacker holds any valid API key** — the lowest-privilege role (`INTERNAL_USER_VIEW_ONLY`) is sufficient. In deployments with SSO, this role is auto-assigned to any user who completes the SSO flow via `/sso/callback`.

The attacker does **not** need: the plaintext master key, admin role, database access, or access to the Prometheus backend separately.

### Attack Steps

```
1.  [PRECONDITION] An administrator has made ≥1 request using the master key.
    Prometheus records: hashed_api_key="<sha256_of_master_key>" in metric labels.

2.  [ATTACKER] GET /metrics/                          ← no authentication
    Response: Prometheus text format containing
      hashed_api_key="1c807cf78eeea8ea9b30e583dab15a057d4e5c95..."

3.  [ATTACKER] POST /key/regenerate
    Authorization: Bearer <any-valid-low-priv-key>
    Body: {"key": "<hash_from_step_2>", "new_master_key": "sk-attacker-value"}
    Response: 200 OK — master key rotated.

4.  [ATTACKER] Full administrative access.
    Create admin keys, revoke existing keys, access all LLM provider credentials.
```

### Root Cause

Two independent bugs combine:

**F-3** — `/metrics/` is served without authentication when Prometheus is enabled and `require_auth_for_metrics_endpoint` is not set. Metric labels embed `hashed_api_key`, which is the SHA-256 of the caller's API key. After any master-key-authenticated request, the master key hash becomes publicly readable.

**F-5** — The function `_is_master_key()` in `spend_tracking_utils.py:55-69` accepts both the plaintext master key and its SHA-256 hash via `secrets.compare_digest`. The `/key/regenerate` endpoint passes the request body field `data.key` to this function (not the `Authorization` header), and master key regeneration is explicitly exempt from the enterprise license check (line 3894-3896).

### Live Reproduction

```
CHAIN-1: /metrics (unauth) → master hash → /key/regenerate → TAKEOVER
  [ATTACKER] Scraped /metrics/ (no auth) → got master key hash: 1c807cf78eeea8ea9b30...
  [VULNERABLE] Full takeover: unauth /metrics → hash → low-priv /key/regenerate → master key rotated
```

### Obtaining a Low-Privilege Key

The attack requires any valid API key. Realistic paths:

- **SSO auto-provisioning** — `/sso/callback` creates users with `INTERNAL_USER_VIEW_ONLY` role automatically. Any employee who completes the organization's SSO flow receives a key without admin approval.
- **Invitation links** — `/onboarding/get_token` generates keys from valid (time-limited, single-use) invitation links.
- **Existing users** — any developer, tester, or service account with a proxy key is sufficient.

### Recommended Fix

1. Remove the hash comparison branch from `_is_master_key()`. Accept only `secrets.compare_digest(api_key, _master_key)`.
2. Change the default for `require_auth_for_metrics_endpoint` to `true`, or remove `hashed_api_key` from Prometheus labels.

Either fix independently breaks the chain.

---

## F-5: Pass-the-Hash Enables Master Key Rotation

| | |
|---|---|
| **Severity** | Critical |
| **CWE** | CWE-836 (Use of Password Hash Instead of Password for Authentication) |
| **Location** | `litellm/proxy/spend_tracking/spend_tracking_utils.py:55-69` |
| **Affected endpoint** | `POST /key/regenerate` |
| **Live confirmed** | Yes — 200 OK, master key rotated by low-privilege user |

### Description

`_is_master_key()` treats the SHA-256 hash of the master key as equivalent to the master key itself:

```python
def _is_master_key(api_key, _master_key):
    if secrets.compare_digest(api_key, _master_key):
        return True
    if secrets.compare_digest(api_key, hash_token(_master_key)):  # ← hash accepted
        return True
    return False
```

The `/key/regenerate` endpoint passes the caller-supplied `data.key` field to this function. When `new_master_key` is also provided, the enterprise license gate is skipped (`if premium_user is not True and not is_master_key_regeneration` at line 3894-3896 — master key regeneration is exempt).

### Proof of Concept

```http
POST /key/regenerate HTTP/1.1
Authorization: Bearer sk-low-privilege-user-key
Content-Type: application/json

{"key": "1c807cf78eeea8ea9b30e583dab15a057d4e5c95...", "new_master_key": "sk-attacker-value"}
```

**Result:** `200 OK` — master key rotated.

### Recommendation

Remove the hash comparison branch. Only accept the plaintext master key.

---

## F-3: Unauthenticated `/metrics/` Exposes Master Key Hash

| | |
|---|---|
| **Severity** | High |
| **CWE** | CWE-306 (Missing Authentication), CWE-359 (Exposure of Private Information) |
| **Location** | `litellm/integrations/prometheus.py:3477` |
| **Condition** | Prometheus enabled; `require_auth_for_metrics_endpoint` unset (default) |
| **Live confirmed** | Yes — 200 with no auth, master key hash in labels |

### Description

When Prometheus is enabled, `/metrics/` is served without authentication by default. Metric labels include `hashed_api_key`, the SHA-256 hash of the API key used for each request. After any request authenticated with the master key, the hash is publicly readable:

```
litellm_proxy_total_requests_metric_total{
  hashed_api_key="1c807cf78eeea8ea9b30e583dab15a057d4e5c9551dd8c565f55ad1e4f18a0c4",
  route="/chat/completions",
  ...
} 1.0
```

We confirmed this applies to any request type, including admin API calls (`/user/new`, `/key/generate`), not only LLM completions.

A `require_auth_for_metrics_endpoint` setting exists but defaults to `false`.

### Recommendation

Default `require_auth_for_metrics_endpoint` to `true`.

---

## F-2: `/spend/keys` Leaks All Key Rows to Any Internal User

| | |
|---|---|
| **Severity** | High |
| **CWE** | CWE-200 (Exposure of Sensitive Information to an Unauthorized Actor) |
| **Location** | `litellm/proxy/spend_tracking/spend_management_endpoints.py:34-66` |
| **Live confirmed** | Yes — internal user receives all key rows |

### Description

The `spend_key_fn()` handler has no `user_api_key_dict` parameter and performs no caller-based filtering:

```python
async def spend_key_fn():
    key_info = await prisma_client.get_data(table_name="key", query_type="find_all")
    return key_info
```

The route is in `spend_tracking_routes`, which grants access to both `INTERNAL_USER` and `INTERNAL_USER_VIEW_ONLY` roles.

### Exposed Data

- SHA-256 hashes of all user-generated API keys (the master key hash is **not** in this table)
- Key names, aliases, and associated user/team IDs
- Budget limits and current spend for every key
- Full metadata dictionaries

### Note

We investigated whether `/spend/logs` also leaks the master key hash. It does not — `view_spend_logs()` (line 2261-2265) and `ui_view_spend_logs()` (line 1914-1952) both enforce `user_id` filtering for non-admin roles.

### Recommendation

Add `user_api_key_dict: UserAPIKeyAuth = Depends(user_api_key_auth)` to the handler. Filter results by the caller's role and user ID.

---

## F-6: MCP OAuth Discovery SSRF

| | |
|---|---|
| **Severity** | High |
| **CWE** | CWE-918 (Server-Side Request Forgery) |
| **Location** | `litellm/proxy/_experimental/mcp_server/mcp_server_manager.py:1481-1704` |
| **Live confirmed** | Yes — proxy fetched attacker-controlled internal URL |

### Description

When an MCP server is registered with `auth_type: oauth2`, the proxy performs RFC 9728 OAuth discovery. It connects to the server URL, expects a `401` response, then follows the `resource_metadata` URL extracted from the `WWW-Authenticate` header — with no private-IP validation and no scheme restriction.

```python
resource_metadata_url, scopes = self._parse_www_authenticate_header(header_value)
if resource_metadata_url:
    authorization_servers, resource_scopes = await self._fetch_oauth_metadata_from_resource(
        resource_metadata_url  # ← arbitrary URL, no validation
    )
```

The same lack of validation applies to `_fetch_single_authorization_server_metadata()` (line 1687), which fetches well-known OAuth endpoints from URLs derived from the attacker-controlled response.

### Proof of Concept

A mock HTTP server returns:
```
HTTP/1.1 401 Unauthorized
WWW-Authenticate: Bearer resource_metadata="http://169.254.169.254/latest/meta-data/iam/security-credentials/"
```

The proxy fetches `http://169.254.169.254/...` — SSRF to the AWS instance metadata service.

### Prerequisite

A `PROXY_ADMIN` must register the attacker-controlled server. The realistic scenario is an admin adding a legitimate-looking third-party MCP server that is compromised or malicious. `IPAddressUtils` exists elsewhere in the codebase but is not applied in this code path.

### Recommendation

Apply the existing `IPAddressUtils` private-IP blocklist and enforce `https://` scheme on all URLs fetched during OAuth discovery.

---

## F-4: Unauthenticated `/token` Endpoint

| | |
|---|---|
| **Severity** | Medium |
| **CWE** | CWE-918 (Server-Side Request Forgery) |
| **Location** | `litellm/proxy/_experimental/mcp_server/discoverable_endpoints.py:589` |
| **Live confirmed** | Yes — returns 404 (not 401) with no auth |

### Description

The `/token` endpoint is intentionally unauthenticated to support OAuth token exchange flows. It POSTs to the `token_url` stored for the MCP server with no URL validation. Combined with F-6, an attacker who controls the stored `token_url` can relay POST requests to internal services.

### Recommendation

Add URL validation to `exchange_token_with_server()`, applying the same private-IP blocklist used elsewhere.

---

## F-1: Unauthenticated `/debug/asyncio-tasks`

| | |
|---|---|
| **Severity** | Low |
| **CWE** | CWE-306 (Missing Authentication for Critical Function) |
| **Location** | `litellm/proxy/common_utils/debug_utils.py:53` |
| **Live confirmed** | Yes — 200 with no auth |

### Description

The route lacks `Depends(user_api_key_auth)`. Any network client can enumerate active asyncio task names, revealing internal infrastructure details:

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

This discloses: database backend (Prisma/Postgres), alerting integration (Slack), and monitoring architecture.

### Recommendation

Add `dependencies=[Depends(user_api_key_auth)]` to the route decorator.

---

## Reproduction

All findings are reproducible with a single command:

```bash
./tests/autofyn_audit/run_live_tests.sh
```

**Requirements:** Docker, `uv`, `prisma generate` run once.

**What the script does:**
1. Starts a dedicated PostgreSQL container (port 15432)
2. Starts a LiteLLM proxy instance (port 14000) with Prometheus enabled
3. Seeds one master-key request so the hash appears in metrics
4. Runs all exploit tests
5. Tears down all containers and processes

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

| Priority | Finding | Effort | Impact |
|---|---|---|---|
| **P0 — Immediate** | F-5: Remove hash branch from `_is_master_key()` | 1 line | Eliminates pass-the-hash and breaks CHAIN-1 |
| **P0 — Immediate** | F-3: Default `require_auth_for_metrics_endpoint` to `true` | Config change | Eliminates hash exposure and independently breaks CHAIN-1 |
| **P1 — High** | F-2: Add caller-based filtering to `/spend/keys` | Small | Prevents key enumeration by low-priv users |
| **P1 — High** | F-6: Apply `IPAddressUtils` to MCP OAuth discovery | Medium | Prevents SSRF via malicious MCP servers |
| **P2 — Standard** | F-4: Add URL validation to `/token` relay | Medium | Prevents SSRF amplification |
| **P3 — Low** | F-1: Add auth to `/debug/asyncio-tasks` | Trivial | Prevents info disclosure |

---

## Appendix A: Disproved Claims

The initial static analysis identified 5 additional potential vulnerabilities. Live testing against a real proxy instance determined these are **not exploitable**. We include them here for completeness and to document the verification work performed.

| Claim | Verdict | Explanation |
|---|---|---|
| MCP `.well-known` query-string auth bypass | Not exploitable | The main `user_api_key_auth` middleware rejects the request before the MCP-specific handler runs. The `.well-known` substring check in `user_api_key_auth_mcp.py:120` is unreachable via this path. Live test returns `401`. |
| MCP OAuth2 fallback grants anonymous access | Not exploitable | Same root cause — the main auth middleware rejects invalid bearer tokens before MCP auth processing begins. Live test returns `401`. |
| `/spend/logs` leaks master key hash to internal users | Not exploitable | Both `view_spend_logs()` (line 2261-2265) and `ui_view_spend_logs()` (line 1914-1952) enforce `user_id` filtering for `INTERNAL_USER` and `INTERNAL_USER_VIEW_ONLY` roles. Internal users see only their own spend logs. |
| SSO callback creates admin users | Not exploitable | `/sso/callback` defaults new users to `INTERNAL_USER_VIEW_ONLY`. Assigning `PROXY_ADMIN` requires explicit SSO provider role mapping configuration. |
| `/user/new` accessible without authentication | Not exploitable | Returns `401 Unauthorized` without a valid API key. |

## Appendix B: Methodology

1. **Static analysis** — AutoFyn identified candidate vulnerability patterns in the source code.
2. **Code path tracing** — Each candidate was traced through the full execution path (middleware → route check → handler) to determine reachability.
3. **Live exploitation** — A real LiteLLM proxy instance backed by PostgreSQL was started. Each finding was tested end-to-end through the HTTP stack. Findings that could not be confirmed live were either downgraded or moved to the disproved appendix.
4. **Chain analysis** — Confirmed findings were analyzed for composability. CHAIN-1 was identified and tested as an integrated attack.
5. **Regression testing** — Previously claimed bypasses were re-tested to confirm they are blocked by upstream middleware, ensuring no false positives in the final report.

All test code, configuration, and the automated runner are included in `tests/autofyn_audit/` for independent verification.
