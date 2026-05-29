# Twenty CRM Security Audit Report

**Scope:** Self-hosted Twenty CRM instance  
**Repo commit:** `fc90b4ba8bb0a5d7c12c846fe9b2305527a0f7a8`  
**Server image:** `twentycrm/twenty@sha256:fd6faa713fd2042d5d87e5705d47d24e492fc5202e7394e188f438085b483fad`  
**DB image:** `postgres:16@sha256:4b7183ac05f8ef417db21fd72d71047a4238340c261d3cc3ddb6d579ab5071ae`  
**Redis image:** `redis:7-alpine@sha256:6ab0b6e7381779332f97b8ca76193e45b0756f38d4c0dcda72dbb3c32061ab99`  
**Date:** 2026-05-29  
**Status:** Pending live verification

---

## Finding A — Arbitrary OS Code Execution via Logic Function (No Sandbox)

### Severity

**CRITICAL** — CVSS v3.1 indicative score: **9.9** (AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H)

This is an *intended feature deployed without a sandbox and without an entitlement gate beyond
self-service admin registration*. It is a deployment/design weakness, not a classic code-injection bug.

### Affected Component

| File | Line(s) | Role |
|------|---------|------|
| `packages/twenty-server/src/engine/core-modules/logic-function/logic-function-drivers/drivers/local.driver.ts` | 496–499 | Spawns child process with inherited parent env |
| `packages/twenty-server/src/engine/metadata-modules/logic-function/logic-function.resolver.ts` | 152–169 | `createOneLogicFunction` / `executeOneLogicFunction` mutations |
| `packages/twenty-server/src/engine/metadata-modules/permissions/permissions.service.ts` | 244–246 | WORKFLOWS permission requires `canUpdateAllSettings` (admin) |
| `packages/twenty-server/src/engine/metadata-modules/roles/utils/create-standard-flat-role-metadata.util.ts` | 18–19 | Workspace creator receives admin role |

### Preconditions

All must be true:

1. `IS_SIGN_UP_ENABLED=true` — any anonymous person can register (confirmed in target env).
2. `LOGIC_FUNCTION_TYPE=LOCAL` (or equivalent) — the local driver must be active. If `LOGIC_FUNCTION_TYPE` is `DISABLED` or absent in a production build, the exploit prints `PRECONDITION_NOT_MET` and exits with code 3.
3. No additional entitlement/billing gate on workspace creation or logic function execution.

### Attack Path

1. Attacker self-registers via `signUp` mutation (public, no captcha required in target env).
2. Attacker calls `signUpInNewWorkspace` (bearer = agnostic token) to create a fresh workspace where they are automatically assigned the admin role (`canUpdateAllSettings: true`).
3. Attacker calls `activateWorkspace` to transition the workspace from `PENDING_CREATION` to active.
4. Attacker calls `createOneLogicFunction(input: CreateLogicFunctionFromSourceInput!)` with a handler body that:
   - Imports `child_process` via `await import('node:child_process')` (ESM; fallback to `require`).
   - Executes `id`, `uname -a`, `head -n 1 /etc/passwd` to prove OS code execution.
   - Reads `process.env.APP_SECRET`, `process.env.ENCRYPTION_KEY`, `process.env.PG_DATABASE_URL` from the inherited parent process environment.
5. Attacker calls `executeOneLogicFunction`. The local driver spawns `node [runnerPath]` with `{ env: { ...cleanProcessEnv, ...cleanUserEnv } }` — the parent env is inherited, so global secrets are directly readable.
6. The return value of the handler is returned in `data`, logs in `logs`.

### Reproduction

```bash
bash autofyn_audit/setup.sh
python3 autofyn_audit/exploits/finding_a_logic_function_rce.py
```

Evidence file produced: `autofyn_audit/evidence/finding_a.json`  
Secret values (not printed to stdout): `autofyn_audit/evidence/finding_a_secret.txt`

### Observed Impact

**LIVE VERIFICATION RESULT: pending**

`<TO BE FILLED BY REVIEWER FROM evidence/finding_a.json>`

Expected if PASS:
- `data.id` field contains `uid=...` proving OS command execution inside the server container.
- `data.APP_SECRET` is non-null (prefix logged; full value in `finding_a_secret.txt`).
- `data.ENCRYPTION_KEY` is non-null (used to decrypt all workspace connection secrets — cross-tenant impact).
- `data.PG_DATABASE_URL` is non-null (direct database access credentials).

**Impact chain if confirmed:**
- Any person who can register an account can execute arbitrary OS commands in the server container.
- `APP_SECRET` is the instance-wide JWT signing key — possession allows forging auth tokens for any user in any workspace.
- `ENCRYPTION_KEY` decrypts all tenants' stored OAuth tokens, IMAP credentials, API keys, etc.
- `PG_DATABASE_URL` provides direct database access (all tenant data).
- Together these constitute full multi-tenant compromise from a single self-registered account.

### Remediation (advisory — do NOT implement during audit)

1. **Sandbox all logic function execution**: Run handlers inside gVisor, Firecracker microVMs, or a seccomp-restricted container with a deny-all syscall policy. The current `spawn(process.execPath, ...)` with no `--disallow-code-generation-from-strings`, no chroot, and no seccomp policy is equivalent to unauthenticated shell access.
2. **Never inherit the parent process environment**: Construct the child process `env` from a strict allowlist. Remove `APP_SECRET`, `ENCRYPTION_KEY`, `PG_DATABASE_URL`, `DATABASE_URL`, and any DSN-like variables before passing to the handler.
3. **Gate behind an explicit non-self-service entitlement**: The `WORKFLOWS` settings permission is only checked within the workspace; workspace creation is free to any registrant. Add an instance-level flag or billing entitlement for the LOCAL driver.
4. **Default `LOGIC_FUNCTION_TYPE` to `DISABLED`** in production builds instead of `LOCAL`. The current default is `LOCAL` when `NODE_ENV=development`, but production deployments can set `NODE_ENV=production` with `LOGIC_FUNCTION_TYPE` absent or still mapped to LOCAL.

---

## Finding B — SSRF / Internal TCP Port-Scan via IMAP Connection Test

### Severity

**HIGH** — CVSS v3.1 indicative score: **8.6** (AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:N/A:N)

### Affected Component

| File | Line(s) | Role |
|------|---------|------|
| `packages/twenty-server/src/engine/core-modules/imap-smtp-caldav-connection/services/imap-smtp-caldav-connection.service.ts` | 34–105 | `testImapConnection` — opens raw TCP socket to user-supplied host:port |
| `packages/twenty-server/src/engine/core-modules/imap-smtp-caldav-connection/imap-smtp-caldav-connection.resolver.ts` | 74–132 | `saveImapSmtpCaldavAccount` mutation |
| `packages/twenty-server/src/engine/core-modules/secure-http-client/secure-http-client.service.ts` | 114–120 | `getValidatedHost` returns raw hostname unchanged when `OUTBOUND_HTTP_SAFE_MODE_ENABLED=false` |
| `packages/twenty-server/src/engine/metadata-modules/roles/role.service.ts` | 379 | Default Member role has `canAccessAllTools: true` |
| `packages/twenty-server/src/engine/metadata-modules/permissions/permissions.service.ts` | 240–253 | `CONNECTED_ACCOUNTS` is a tool permission; granted to any member |

### Preconditions

All must be true:

1. `IS_SIGN_UP_ENABLED=true` (confirmed in target env).
2. `OUTBOUND_HTTP_SAFE_MODE_ENABLED=false` (confirmed in target env — disables all SSRF protection).
3. `IS_IMAP_SMTP_CALDAV_CONNECTION_TEST_ENABLED=true` (confirmed in target env — enables connection testing before save).

### Attack Path

1. Attacker self-registers via `signUp` (lowest privilege — member role in default workspace suffices).
2. Attacker calls `saveImapSmtpCaldavAccount(handle, connectionParameters: { IMAP: { host, port, ... } })`.
3. The server calls `testImapConnection`, which calls `getValidatedHost(host)` (no-op when safe mode off), then opens an `ImapFlow` TCP socket to the attacker-controlled `host:port`.
4. Error message oracle:
   - `ECONNREFUSED` → GraphQL error: `"IMAP connection refused..."` — port **closed**.
   - Any other error (timeout, protocol mismatch, banner response) → `"IMAP connection failed: ..."` — port **reached/open** (SSRF confirmed).
   - This differential proves the server is performing attacker-directed TCP connections to internal hosts.
5. By probing multiple ports on an internal IP and comparing responses, the attacker builds a TCP port-scan of the internal network.

### Reproduction

```bash
bash autofyn_audit/setup.sh
python3 autofyn_audit/exploits/finding_b_imap_ssrf.py
```

Evidence file produced: `autofyn_audit/evidence/finding_b.json`

### Observed Impact

**LIVE VERIFICATION RESULT: pending**

`<TO BE FILLED BY REVIEWER FROM evidence/finding_b.json>`

Expected if PASS:
- Probe to `172.20.0.2:5432` (Postgres) classifies as OPEN/reached.
- Probe to `172.20.0.3:6379` (Redis) classifies as OPEN/reached.
- Probe to `172.20.0.2:1` (control, expected closed) classifies as CLOSED.
- Differential confirms the server is performing attacker-directed internal TCP connections.

**Impact if confirmed:**
- Network topology enumeration of all hosts reachable from the server container.
- Protocol-level probing: Redis on port 6379 in this deployment has no authentication configured — an attacker who can reach it via SSRF may be able to interact further (e.g. via SMTP protocol smuggling or CalDAV channel).
- Establishes a foothold for further lateral movement when combined with other vulnerabilities.

### Remediation (advisory — do NOT implement during audit)

1. **Enforce `getValidatedHost` regardless of `OUTBOUND_HTTP_SAFE_MODE_ENABLED`** for connection tests: safe-mode should never gate basic SSRF protection for user-supplied connection parameters.
2. **Block private/link-local/loopback ranges** (RFC 1918: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16; loopback 127.0.0.0/8; link-local 169.254.0.0/16; IPv6 equivalents) in `getValidatedHost` and in the IMAP/SMTP/CalDAV validator service.
3. **Do not leak connection error detail** (error code, message) back to the GraphQL caller — return a generic `"Connection failed"` message regardless of underlying error type to eliminate the OPEN/CLOSED oracle.
4. **Add a CIDR deny-list** at the network level (iptables/nftables) so the server container cannot initiate TCP connections to other containers on the internal Docker network.

---

## Appendix — Pinned Hashes

| Component | Value |
|-----------|-------|
| Repo commit | `fc90b4ba8bb0a5d7c12c846fe9b2305527a0f7a8` |
| Server image | `twentycrm/twenty@sha256:fd6faa713fd2042d5d87e5705d47d24e492fc5202e7394e188f438085b483fad` |
| DB image | `postgres:16@sha256:4b7183ac05f8ef417db21fd72d71047a4238340c261d3cc3ddb6d579ab5071ae` |
| Redis image | `redis:7-alpine@sha256:6ab0b6e7381779332f97b8ca76193e45b0756f38d4c0dcda72dbb3c32061ab99` |

## Appendix — Environment Flags (Target Instance)

| Flag | Value | Significance |
|------|-------|--------------|
| `IS_SIGN_UP_ENABLED` | `true` | Anyone can register |
| `AUTH_PASSWORD_ENABLED` | `true` | Password auth works |
| `OUTBOUND_HTTP_SAFE_MODE_ENABLED` | `false` | All SSRF protection disabled |
| `IS_IMAP_SMTP_CALDAV_CONNECTION_TEST_ENABLED` | `true` | Connection testing active |
| `LOGIC_FUNCTION_TYPE` | `LOCAL` (inferred from run_state) | Local driver executes handlers as child processes |
| `IS_EMAIL_VERIFICATION_REQUIRED` | `false` (default) | Token exchange succeeds without email verify |
