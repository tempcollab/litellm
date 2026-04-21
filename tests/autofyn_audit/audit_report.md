# LiteLLM Proxy — Security Audit Report

**Date:** 2026-04-21 | **Commit:** `b9bedc8153` on `litellm_internal_staging`
**Method:** AutoFyn static analysis → code path tracing → live exploitation (PostgreSQL-backed proxy, no mocks)
**Reproduce:** `./tests/autofyn_audit/run_live_tests.sh` — automated setup, test, teardown

---

## Findings

| ID | Title | Severity | Prerequisites |
|---|---|---|---|
| CHAIN-1 | `/metrics` + pass-the-hash → proxy takeover | Critical | Prometheus on, metrics auth off, prior master-key request, `internal_user` key |
| F-5 | `_is_master_key()` accepts hash → master key rotation | Critical | Master key hash + `internal_user` key |
| F-3 | Unauthenticated `/metrics/` leaks master key hash | High | Prometheus on (opt-in), metrics auth off (default) |
| F-2 | `/spend/keys` returns all keys to any internal user | High | `internal_user` or `internal_user_viewer` key |
| F-6 | MCP OAuth discovery SSRF | High | Admin registers attacker-influenced MCP server |
| F-4 | Unauthenticated `/token` endpoint | Medium | Stored malicious `token_url` via F-6 |
| F-1 | Unauthenticated `/debug/asyncio-tasks` | Low | None |

---

## CHAIN-1: Proxy Takeover via `/metrics` + Pass-the-Hash

**Requires:** Prometheus enabled, `require_auth_for_metrics_endpoint` unset (default), admin has used master key for ≥1 request, attacker has `internal_user` role key.

**Does NOT work with:** plain keys, `internal_user_viewer` (SSO default). Both return 401 on `/key/regenerate`. Only `internal_user` or higher can access key management routes.

```
1. Admin makes any request with master key → Prometheus labels record its SHA-256 hash
2. GET /metrics/ (no auth) → attacker extracts hashed_api_key="1c807cf78..."
3. POST /key/regenerate (Authorization: Bearer <internal_user_key>)
   Body: {"key": "<hash>", "new_master_key": "sk-attacker-value"}
   → 200 OK, master key rotated
```

**Root cause:** Two bugs combine. F-3: `/metrics/` is unauthenticated and embeds key hashes in labels. F-5: `_is_master_key()` accepts `hash_token(master_key)` as equivalent to the plaintext, and `/key/regenerate` is exempt from the enterprise license gate for master key rotation.

**Fix:** Either fix breaks the chain: (1) remove hash branch from `_is_master_key()`, (2) default metrics auth to `true`.

---

## F-5: Pass-the-Hash Master Key Rotation

### Privilege escalation

`internal_user` is a non-admin role defined as: "can login, view/create/delete **their own keys**, view their spend" (`_types.py:104`). The role description (`_types.py:148`) repeats: "view/create/delete their own keys, view their own spend." Master key rotation is not listed — it is an admin operation. Other admin-only handlers enforce this explicitly (e.g. `mcp_management_endpoints.py:1217`: `if PROXY_ADMIN != user_api_key_dict.user_role: raise 403`). But `/key/regenerate` has no such check (`key_management_endpoints.py:3882-3939`) — any `internal_user` can rotate the master key.

`spend_tracking_utils.py:55-69` — `_is_master_key()` compares against both plaintext and `hash_token()`:

```python
is_master_key = secrets.compare_digest(api_key, hash_token(_master_key))  # BUG
```

`/key/regenerate` passes the request body `data.key` to this function. Enterprise gate skipped for master key regeneration (`key_management_endpoints.py:3894`: `if premium_user is not True and not is_master_key_regeneration`). No role check — works on both free and enterprise deployments.

**Fix:** Remove the hash comparison branch. Add `PROXY_ADMIN` role check before master key rotation.

---

## F-3: Unauthenticated `/metrics/` Leaks Master Key Hash

When Prometheus is enabled and `require_auth_for_metrics_endpoint` is unset (default), `/metrics/` is public. Labels include `hashed_api_key` — the SHA-256 of the caller's key. Confirmed: ANY request type (including `/user/new`, not just LLM calls) with the master key writes the hash to labels.

**Fix:** Default `require_auth_for_metrics_endpoint` to `true`.

---

## F-2: `/spend/keys` Returns All Key Rows

`spend_management_endpoints.py:34-66` — `spend_key_fn()` has no `user_api_key_dict` param, returns all keys unfiltered. Accessible to `internal_user` and `internal_user_viewer`. Exposes: all key hashes, names, user/team IDs, budgets, metadata. Does NOT expose master key hash (not in `LiteLLM_VerificationToken`).

**Fix:** Add `user_api_key_dict` dependency, filter by caller role/user.

---

## F-6: MCP OAuth Discovery SSRF

`mcp_server_manager.py:1481-1704` — When admin registers MCP server with `auth_type: oauth2`, proxy follows `resource_metadata` URL from `WWW-Authenticate` header with no private-IP or scheme validation. Live test: mock server returns header pointing to `http://127.0.0.1:PORT/ssrf-canary`, proxy fetches it. `IPAddressUtils` exists in codebase but not applied here.

**Fix:** Apply `IPAddressUtils` blocklist and enforce `https://`.

---

## F-4: Unauthenticated `/token`

`discoverable_endpoints.py:589` — Public endpoint (intentional for OAuth). POSTs to stored `token_url` without URL validation. Combined with F-6, enables SSRF relay.

**Fix:** Add URL validation to `exchange_token_with_server()`.

---

## F-1: Unauthenticated `/debug/asyncio-tasks`

`debug_utils.py:53` — No `Depends(user_api_key_auth)`. Reveals: DB type, alerting config, monitoring tasks.

**Fix:** Add auth dependency.

---

## Fix Priority

| Priority | Fix | Effort |
|---|---|---|
| P0 | F-5: Remove hash branch from `_is_master_key()` | 1 line change |
| P0 | F-3: Default metrics auth to `true` | Config default change |
| P1 | F-2: Filter `/spend/keys` by caller | Add param + filter |
| P1 | F-6: Apply IP blocklist to MCP OAuth | Medium |
| P2 | F-4: Validate `/token` relay URL | Medium |
| P3 | F-1: Add auth to debug endpoint | Trivial |

---

## Appendix: Disproved Claims

| Claim | Why not exploitable |
|---|---|
| MCP `.well-known` query-string bypass | Main auth middleware rejects before MCP handler. Returns 401. |
| MCP OAuth2 fallback anonymous access | Same — main middleware rejects invalid tokens first. |
| `/spend/logs` leaks master key hash | Endpoint filters by `user_id` for non-admin roles. |
| SSO creates admin users | Defaults to `internal_user_viewer`. Admin requires explicit role mapping. |
| `/user/new` without auth | Returns 401. |
