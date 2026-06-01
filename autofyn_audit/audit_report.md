# Security Audit Report: Twenty CRM

**Audit Firm:** AutoFyn SignalPilot

**Audit Model:** Claude Opus 4.8 (Anthropic)

**Target:** Twenty CRM (https://github.com/twentyhq/twenty)

**Repository:** `twenty`

**Commit Reviewed:** Running release `v2.8.3` (image `twentycrm/twenty@sha256:fd6faa713fd2042d5d87e5705d47d24e492fc5202e7394e188f438085b483fad`); source verified against repo commit `fc90b4ba8bb0a5d7c12c846fe9b2305527a0f7a8`

**Date:** 2026-05-30

**Status:** 1 High Vulnerability Confirmed + 1 Low/Informational + 1 End-to-End Exploit Chain

---

## Executive Summary

This audit assessed Twenty CRM v2.8.3 (self-hosted Docker deployment) against a live, pinned instance. The codebase is broadly well-defended: SSRF, path traversal, SQL injection, cross-tenant IDOR, auth-token weaknesses, and upload XSS were all investigated and ruled out against the running build (see §4). One genuine object-level authorization defect was confirmed, plus one low-severity information-disclosure weakness.

Strongest live-confirmed issue:

- **TWENTY-001 (High) — Workflow-object RBAC bypass.** A single early-`return` in the ORM permission check (`validateOperationIsPermittedOrThrow`) skips record-permission enforcement for `isSystem` objects. For the workflow-related object class (`workflow`, `workflowRun`, `workflowVersion`) — which the permissions cache gates behind the `WORKFLOWS` settings flag — this lets a workspace member who is correctly denied on the dedicated workflow resolvers nonetheless read and write those objects through the generic GraphQL data API, leaking workflow-embedded `Authorization: Bearer` credentials and tampering with automations.

The High finding is supported by an **end-to-end exploit chain** (CHAIN-01) proven live against the running instance: a restricted member steals an admin's workflow Bearer credential via the bypass and replays it against an external API to obtain protected data — elevating the impact from "readable field" to "compromise of an external account/credential held by the org." The chain's confirmed boundary is an authenticated low-privilege insider (PR:Low); it is not an unauthenticated attack.

The Low/Informational finding (TWENTY-002) is an unauthenticated, captcha-less, unthrottled email-existence oracle (`checkUserExists`). It is reported as hardening guidance rather than a product vulnerability — it is a near-ubiquitous, accepted-risk UX pattern, and the platform already ships an opt-in captcha mitigation that simply defaults off.

---

## Evidence Types

- **Direct Twenty Exploit** — PoC executed against Twenty's own running implementation; the documented effect (e.g. a low-privilege member reading/writing data its role forbids) reproduced live with a per-run random nonce asserted in the member's own response.
- **Direct Twenty Exploit + Attacker Infrastructure** — PoC executed against the running instance with an attacker-controlled auxiliary service (a token-gated mock external API on the audit network) to prove downstream impact such as credential replay.
- **Controlled Reproduction** — vulnerable code path confirmed by source/compiled-code review with limited live probing; behavior observed but not packaged as a self-asserting PoC.

---

## Findings Table

| ID | Vulnerability | Severity | CVSS | Status | Evidence |
|----|---------------|----------|------|--------|----------|
| TWENTY-001 | Workflow-object RBAC bypass via `isSystem` early-return in `validateOperationIsPermittedOrThrow` (read/write `workflow`/`workflowRun`/`workflowVersion`, leaking embedded `Bearer` credentials) | High | 8.1 | Confirmed | Direct Twenty Exploit |
| TWENTY-002 | Unauthenticated user/email enumeration via `checkUserExists` (no captcha, no rate-limit) | Low/Informational | 5.3 | Confirmed | Direct Twenty Exploit |

---

## Exploit Chains

### Chain Evidence Matrix

| Chain | Severity | Vulnerabilities | Exploit Script | Evidence |
|-------|----------|-----------------|----------------|----------|
| CHAIN-01 | High | TWENTY-001 | `exploits/chain_01_workflow_secret_to_external_compromise.sh` | Direct Twenty Exploit + Attacker Infrastructure |

### CHAIN-01 — Workflow secret theft → external-account compromise

**Severity:** High
**Vulnerabilities:** TWENTY-001
**Exploit script:** `exploits/chain_01_workflow_secret_to_external_compromise.sh`
**Evidence tier:** Direct Twenty Exploit + Attacker Infrastructure

This chain proves the TWENTY-001 read-bypass yields a **live external credential**, not just a readable field. The chain's entry point is an authenticated low-privilege insider (custom role, `canReadAllObjectRecords=false`, no `WORKFLOWS` flag) — it is **not** unauthenticated.

**Attack flow:**
1. An admin builds a legitimate automation: a workflow `HTTP_REQUEST` step that authenticates to a third-party API with `Authorization: Bearer <LIVE_SECRET>`. (Modeled by a token-gated mock service on the audit network that returns `PROTECTED-DATA-<nonce>` only for the exact token, and HTTP 401 + body `DENIED` otherwise.)
2. A lowest-privilege insider reads the admin's Bearer token out of `workflowVersions{steps...settings.input.headers.Authorization}` via the TWENTY-001 `isSystem` bypass — despite having no role permission to read workflows (the same member is correctly DENIED on `companies`).
3. The attacker replays the stolen token directly against the third-party API and receives `PROTECTED-DATA-<nonce>`; the same request with no token returns HTTP 401. The stolen credential grants live external access as the victim org.

> **Honest scope note.** The *server-side* variant (member writes a malicious HTTP step then triggers it so the Twenty server exfiltrates the secret) is BLOCKED by `SettingsPermissionGuard(WORKFLOWS)` at the workflow resolvers, independent of the ORM bypass. The chain therefore uses **client-side replay** of the stolen credential — the action that actually works in default config and the realistic attacker move. The chain adds no new vulnerability; it strengthens the impact narrative for TWENTY-001 (and the C:H component of its CVSS).

**Confirmed output** (per-run nonces differ each run; verdict shape is identical):
```
secret_planted=true
stolen_by_restricted_member=true
control_denied_on_companies=true
replay_with_stolen_token=AUTHORIZED
replay_without_token=DENIED
RESULT=CONFIRMED exploit=chain_01_workflow_secret_to_external_compromise ::
  restricted member (canReadAllObjectRecords=false) stole an admin workflow Bearer credential
  via the TWENTY-001 isSystem RBAC bypass and replayed it for live access to an external API
  (got PROTECTED-DATA); no-token control denied — impact = external credential compromise,
  not just field read
```
The "stolen" assertion uses `grep -qF` on the **restricted member's own raw response** (not the admin's), and the no-token negative control is a hard gate (must return HTTP 401/403 + body `DENIED` and must NOT contain `PROTECTED-DATA`, else the run aborts without a CONFIRMED claim).

---

## Vulnerability Details

### TWENTY-001 — Workflow-object RBAC bypass via `isSystem` early-return

**Severity:** High — CVSS 3.1 **8.1** `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N`

**CWE:** CWE-863: Incorrect Authorization

**Affected Code:**
`packages/twenty-server/src/engine/twenty-orm/repository/permissions.utils.ts` — `validateOperationIsPermittedOrThrow` (lines 116–124; compiled as `dist/engine/twenty-orm/repository/permissions.utils.js`).

**Description:**
The ORM-level record-permission check returns early for any object with `isSystem === true` (except `workspaceMember`), *before* the `switch(operationType)` block that enforces `canReadObjectRecords` / `canUpdateObjectRecords` / `canSoftDeleteObjectRecords` / `canDestroyObjectRecords`. For the workflow-related object class (`workflow`, `workflowRun`, `workflowVersion`), the role-permissions cache computes record access as `hasWorkflowsPermissions` (the `WORKFLOWS` settings flag) — so a role *without* that flag has a cache-computed `canReadObjectRecords = false`. The dedicated workflow resolvers enforce `SettingsPermissionGuard(WORKFLOWS)` and correctly deny such a member, but the generic auto-generated GraphQL data API has no settings-permission guard and relies solely on the early-returning check. The result is an enforcement inconsistency: the generic data API serves (and mutates) workflow objects the member's computed permission forbids — including HTTP-step `Authorization: Bearer` credentials embedded in `workflowVersions.steps`.

**Vulnerable Code:**
```typescript
const objectMetadataIsSystem = objectMetadata.isSystem === true;
const isWorkspaceMemberObject =
  objectMetadata.universalIdentifier ===
  WORKSPACE_MEMBER_OBJECT_UNIVERSAL_IDENTIFIER;

// TODO: this should be improved, we may have more complex permission configuration for is system objects
if (objectMetadataIsSystem && !isWorkspaceMemberObject) {
  return; // returns BEFORE the switch(operationType) that enforces canReadObjectRecords, etc.
}
```

**Scope (verified):** The early-return mechanically reaches *every* `isSystem` object, but only the workflow-related class is an actual privilege escalation. Other `isSystem` objects (`blocklist`, `messageThread`, …) are granted `canRead = true` unconditionally by the cache (`isSystem ? true`) and cannot be restricted by any role (`object-permission.service.ts` throws `CANNOT_ADD_OBJECT_PERMISSION_ON_SYSTEM_OBJECT`), so reading them is intended behavior — not an escalation. `message` bodies and `calendarEvent` details are additionally protected by independent visibility-restriction hooks the bypass does not defeat (see §4).

**Attack Scenario:**
A workspace admin assigns a low-trust member a custom role with `canReadAllObjectRecords=false` and without the `WORKFLOWS` permission. That member queries `workflowVersions` through the standard data API, reads an admin's embedded third-party `Bearer` token, and replays it off-platform — while the same member is correctly denied on `companies`/`people`/`workflows`.

**Proof of Concept:**
```bash
# Core read/write bypass (plants a per-run random secret as admin, reads it back as the restricted member):
bash autofyn_audit/exploits/04_system_object_permission_bypass.sh

# End-to-end credential theft + external replay (CHAIN-01):
bash autofyn_audit/exploits/chain_01_workflow_secret_to_external_compromise.sh
```
Confirmed live output (per-run marker elided):
```
RESULT=CONFIRMED exploit=04_system_object_permission_bypass :: read_bypass=true control_denied=true
  write_bypass=true workflows_denied=true secret_marker=SUPERSECRET-<32hex> workflowVersionId=<uuid>
  :: member reads all workflowVersions.steps (including embedded HTTP Authorization headers) despite
  role having no WORKFLOWS settings flag — permissions.utils.js early-return for isSystem objects
  bypasses canRead=false enforcement; company read correctly denied
```

**Remediation:**
Make the generic data-API path honor the same permission the cache already computes, rather than short-circuiting it: for cache flag-gated system objects (the workflow-related set, alongside the existing `workspaceMember` handling), fall through to the normal `switch(operationType)` enforcement so a role lacking the `WORKFLOWS` flag is denied on the generic API exactly as on the dedicated resolvers. Objects the cache grants unconditionally can remain exempt (no role can restrict them anyway), which avoids regressing internal features that assume universally-readable system objects.

---

### TWENTY-002 — Unauthenticated user/email enumeration via `checkUserExists`

**Severity:** Low/Informational — CVSS 3.1 **5.3** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N`

**CWE:** CWE-204: Observable Response Discrepancy

**Affected Code:**
`packages/twenty-server/src/engine/core-modules/auth/auth.resolver.ts` — `checkUserExists` query (line 130), served on the unauthenticated `/metadata` GraphQL endpoint (`@MetadataResolver()`, guarded by `PublicEndpointGuard` + `NoPermissionGuard`). Captcha no-ops when no driver is configured: `packages/twenty-server/src/engine/core-modules/captcha/captcha.service.ts` returns `{ success: true }` when `CAPTCHA_DRIVER` is unset (the default).

**Description:**
The `checkUserExists` query returns a distinguishable response for registered vs unregistered emails (`{exists:true,isEmailVerified:…}` vs `{exists:false}`), is reachable without authentication or a captcha token, and has no server-side rate limiting. This is a textbook account-existence oracle. It is reported as Low/Informational because it is an accepted-risk UX pattern for the "Continue with Email" flow and the platform already ships an opt-in captcha mitigation.

**Attack Scenario:**
An unauthenticated attacker scripts `checkUserExists` across an email list to build a validated set of accounts for phishing or password-spray, and to confirm whether a target organization uses the instance.

**Proof of Concept:**
```bash
bash autofyn_audit/exploits/03_user_enumeration_no_captcha.sh
```
Confirmed live output:
```
Known-existing email  → {"data":{"checkUserExists":{"exists":true,"isEmailVerified":false}}}
Random absent email   → {"data":{"checkUserExists":{"exists":false}}}
Rate-limit            → 30/30 sequential unauthenticated calls succeeded, 0 throttled
```

**Remediation:**
Configure a captcha driver for `checkUserExists` in production and add IP-keyed server-side rate-limiting (e.g. `@nestjs/throttler`) on unauthenticated auth-surface queries; optionally return a uniform response to remove the oracle entirely.

---

## Reproduction Instructions

**Prerequisites:**
- Docker with the pinned target running on network `twenty-audit-net`: `audit-twenty-server` (image `twentycrm/twenty@sha256:fd6faa713fd2…`), serving `v2.8.3`.
- `setup.sh` verifies the pinned digest, health, and the attacker listener. Scripts are portable to stock macOS (Bash 3.2, BSD `head`, no `timeout`) and Linux/CI.

**Run:**
```bash
bash autofyn_audit/setup.sh      # idempotent; verifies pinned digest, health, listener
bash autofyn_audit/run_all.sh    # runs PoCs live; prints per-PoC RESULT= + a final N CONFIRMED / N total
bash autofyn_audit/exploits/chain_01_workflow_secret_to_external_compromise.sh  # CHAIN-01 (manages its own mock)
bash autofyn_audit/teardown.sh   # removes ONLY the attacker listener; leaves target intact
```

**Expected output:**
- `04_system_object_permission_bypass` → `RESULT=CONFIRMED` (read_bypass=true, control_denied=true, write_bypass=true).
- `04b_system_object_blast_radius` → `RESULT=CONFIRMED` (6/6 isSystem reached, 3/3 non-system controls denied).
- `03_user_enumeration_no_captcha` → `RESULT=CONFIRMED` (existing=true / absent=false; 30/30 unthrottled).
- `chain_01_…` → `RESULT=CONFIRMED` (stolen token AUTHORIZED at mock; no-token DENIED).

> **Reading the runner output.** `RESULT=CONFIRMED` means the script's mechanism reproduced live — it is NOT a claim of product vulnerability. Only `04`/`04b` (TWENTY-001, High) and `03` (TWENTY-002, Low/Informational) are reported findings. `01` and `02` reproduce their mechanisms on the test container but are **ruled out as product vulnerabilities** in a default deployment (see §4): `01` requires possession of two unguessable 122-bit UUIDs; `02`'s internal/IMDS SSRF requires the non-default `OUTBOUND_HTTP_SAFE_MODE_ENABLED=false`.

**Cleanup:**
`bash autofyn_audit/teardown.sh` removes only the `audit-attacker-listener` container. The chain script removes its own mock container on exit. No changes are made to the target application.

---

## 4. Investigated and Ruled Out

These vectors were examined against the compiled v2.8.3 code (and, where applicable, probed) and are **not** product vulnerabilities in a default deployment. They are documented for transparency.

| Vector | Verdict | Reason (verified in v2.8.3) |
|--------|---------|------------------------------|
| Unauthenticated webhook trigger `POST /webhooks/workflows/:workspaceId/:workflowId` | **By design — not a vuln** | Endpoint is intentionally public (`PublicEndpointGuard`). Security rests on two unguessable 122-bit UUIDs (workspace id + workflow id) the owner shares with their integration, like a GitHub/Stripe webhook URL. Without those UUIDs an attacker cannot trigger anything; triggering one's own workflow is not an exploit. |
| SSRF via `HTTP_REQUEST` workflow action / `testHttpRequest` | **Not a vuln in default config** | The outbound HTTP client is SSRF-hardened when `OUTBOUND_HTTP_SAFE_MODE_ENABLED` is on, and that flag **defaults to `true`** in v2.8.3 (`config-variables.js`). Only the test container set it to `false`. A default deployment blocks private-IP/metadata SSRF. |
| Path traversal on `GET /file/public-assets/:workspaceId/:applicationId/*path` | **Not a vuln** | Four independent defenses: `..`-segment rejection, a per-segment `^[a-zA-Z0-9._-]+$` allowlist, a DB lookup requiring a matching `file` record before any byte is served, and `realpathSync` + storage-root containment in the local driver. |
| `/s/*path` public route-trigger (logic functions) | **Not exploitable in default config** | Fully public for all verbs, but logic-function execution is gated by `LOGIC_FUNCTION_TYPE`, which defaults to `DISABLED` in the standard Docker deployment. (Operator note: if logic functions are enabled and a route's `isAuthRequired` is false, this becomes an unauthenticated cross-workspace invocation surface — worth hardening, not exploitable as shipped.) |
| Cross-workspace IDOR / tenant isolation | **Not a vuln** | The active workspace is derived from the verified JWT's `workspaceId` claim (`bindDataToRequestObject`), not from any client-supplied header or argument. |
| Password-reset / token flows | **Not a vuln** | Reset tokens use `crypto.randomBytes(32)` (256-bit), are SHA-256-hashed at rest, and expire (5m). JWT verification pins a single-element `algorithms` array, preventing algorithm-confusion. |
| SQL injection in dynamic record API (filter/orderBy) | **Not a vuln** | Filter keys are validated against a server-side metadata field allowlist (`fieldIdByName`) and rejected before any SQL is built; values are TypeORM-parameterized. |
| File-upload stored XSS / upload abuse | **Not a vuln** | Magic-byte content-type detection, DOMPurify sanitization for SVG, and `Content-Disposition: attachment` for non-inline types. |
| Predictable dev-seed invite hash (`apple.`/`yc.dev-invite-hash`) → unauthenticated workspace join | **Working as intended — not a product vuln** | The public invite-link feature is intentional (`isPublicInviteLinkEnabled` defaults `true`); an invite hash is a bearer credential by design. In production `inviteHash` is a 122-bit UUID v4. The literal `apple.`/`yc.` hashes exist only in the dev-seed demo workspaces, not real deployments. (Operator note: invite hashes never expire/rotate — worth hardening.) |
| Admin-panel config exposure (`getConfigVariablesGrouped`, `getDatabaseConfigVariable`) | **Not a vuln** | `isSensitive` values are masked by `maskSensitiveValue()` before return; resolvers are double-gated by `AdminPanelGuard` (superadmin) + `SettingsPermissionGuard(SECURITY)`. |
| Cross-workspace role assignment via user-supplied `roleId` | **Not a vuln** | Role lookups resolve against workspace-scoped flat maps loaded for the caller's `workspaceId`; a foreign `roleId` is undefined and throws `ROLE_NOT_FOUND`/`FlatEntityMapsException` before any assignment. |
| SNS/SES inbound webhook subscription-confirmation SSRF | **Not exploitable in default config** | SNS signature verification runs before the subscription-confirmation fetch, and the topic must be in `SES_SNS_TOPIC_ARN_ALLOWLIST` (empty by default → rejected). |
| OAuth `redirectLocation` open redirect (`connection-provider-oauth.controller.ts`) | **Low / not a vuln** | `redirectLocation` is carried in an `APP_SECRET`-signed state JWT and applied via `url.pathname`; the Node `URL.pathname` setter cannot change the host, so the redirect stays same-host. |
| **TWENTY-001 → mass email body / calendar event exfiltration** | **Ruled out — live-tested** | `message` and `calendarEvent` ARE `isSystem=true`, so the ORM bypass IS reached — but both run independent application-layer visibility hooks the bypass does not defeat. `apply-messages-visibility-restrictions.service.ts` (line 92–93) throws `NotFoundError('Associated message channels not found')` — failing the entire `messages` query — for any message without a `messageChannelMessageAssociation` row (and redacts `subject`/`text` to `FIELD_RESTRICTED_ADDITIONAL_PERMISSIONS_REQUIRED` for non-owners even when a channel exists). `apply-calendar-events-visibility-restrictions.service.ts` (line 135) splices out events without a `calendarChannelEventAssociation`, reducing `edges` to empty. Live evidence: admin-planted nonce-marked `message`/`calendarEvent` records were created, but a subsequent read — even by the planting admin — returned `messages:null` (`code:NOT_FOUND`) and empty `calendarEvents.edges`. Only `messageThread.subject` (no visibility hook) read back, and `messageThread` is unconditionally member-readable by design. Confirmed negative: TWENTY-001 does not expose email bodies or calendar event details. |

> **Second-finding hunt (transparency).** A dedicated pass over impersonation (`canImpersonate`), the admin panel, SSO/Google/Microsoft OAuth state and `returnToPath` handling, invitation/2FA flows, the REST API, billing/messaging webhooks, row-level permission predicates, and API-key minting found **no additional independent high/critical product vulnerability** beyond TWENTY-001. The codebase is otherwise well-defended.

---

## Conclusion

Twenty CRM v2.8.3 is broadly well-defended against the common critical attack classes — the audit ruled out SSRF, path traversal, SQLi, tenant-isolation IDOR, auth-token weaknesses, and upload XSS against the running build. The one systemic issue is an authorization-layering inconsistency: object-record permissions are computed correctly in the role cache (including the `WORKFLOWS`-flag gate for workflow objects), but the generic data-API enforcement path short-circuits that computation for `isSystem` objects via a single early-`return`. That gap turns a settings-permission boundary into a no-op on the generic API for the workflow-object class, exposing embedded third-party credentials.

**Priority remediation order:**
1. **TWENTY-001 (High):** Stop early-returning for cache flag-gated system objects in `validateOperationIsPermittedOrThrow`; honor the computed `canReadObjectRecords`/`canUpdateObjectRecords`/etc. so the generic data API matches the dedicated workflow resolvers.
2. **TWENTY-002 (Low/Informational):** Enable a captcha driver and add IP-keyed rate-limiting on unauthenticated auth-surface queries; consider a uniform `checkUserExists` response.

---

## Files Delivered

```
autofyn_audit/
├── audit_report.md                              # this report
├── README.md                                    # quick-start + finding summary
├── setup.sh                                     # verify pinned digest, health, listener
├── run_all.sh                                   # run PoCs live; print RESULT= + summary
├── teardown.sh                                  # remove only the attacker listener
├── lib/
│   └── common.sh                                # v2.8.3 auth helpers (/metadata, signUp/bootstrap, oracle)
├── exploits/
│   ├── 00_recon.sh                              # environment recon (informational)
│   ├── 01_unauth_webhook_trigger.sh             # RULED OUT mechanism demo (§4)
│   ├── 02_ssrf_via_webhook_http_request.sh      # RULED OUT mechanism demo (§4)
│   ├── 03_user_enumeration_no_captcha.sh        # TWENTY-002 PoC (Low/Informational)
│   ├── 04_system_object_permission_bypass.sh    # TWENTY-001 PoC: read/write bypass (High)
│   ├── 04b_system_object_blast_radius.sh        # TWENTY-001 mechanism probe (companion)
│   └── chain_01_workflow_secret_to_external_compromise.sh  # CHAIN-01 impact proof (High)
└── docs/
    └── CVE-TWENTY-001.md                         # advisory for the High finding
```
