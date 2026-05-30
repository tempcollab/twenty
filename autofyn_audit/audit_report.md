# Twenty CRM — Security Audit Report

**Date:** 2026-05-30
**Auditor:** AutoFyn security audit team
**Result:** 2 confirmed findings: 1 CRITICAL (system-object RBAC bypass) + 1 Medium (user enumeration). Several plausible critical vectors were investigated and ruled out (see §4).

---

## 1. Target & Reproducibility

| Item | Value |
|------|-------|
| Target Docker image | `twentycrm/twenty@sha256:fd6faa713fd2042d5d87e5705d47d24e492fc5202e7394e188f438085b483fad` |
| Running release | **v2.8.3** (from `/client-config` → `appVersion`) |
| Repo base commit (audit checkout) | `fc90b4ba8bb0a5d7c12c846fe9b2305527a0f7a8` |
| Live instance | `http://audit-twenty-server:3000` on docker network `twenty-audit-net` |
| Helper (attacker) image | `curlimages/curl@sha256:b3f1fb2a51d923260350d21b8654bbc607164a987e2f7c84a0ac199a67df812a` |
| Listener image | `alpine@sha256:de0eb0b3f2a47ba1eb89389859a9bd88b28e82f5826b6969ad604979713c2d4f` |

> **Version note (important for accuracy).** The repo is checked out at commit `fc90b4ba`, but the *running container* is release **v2.8.3**, whose compiled GraphQL schema and route guards differ from `fc90b4ba`. All API shapes, route patterns, guards, and config defaults cited in this report were verified against the **compiled code inside the running v2.8.3 container** (`/app/packages/twenty-server/dist/...`), not against `fc90b4ba` source.

**Reproduce (fully scripted, against the live pinned instance):**
```bash
bash autofyn_audit/setup.sh      # idempotent; verifies pinned digest, health, listener
bash autofyn_audit/run_all.sh    # runs confirmed PoCs live; prints RESULT= + summary
bash autofyn_audit/teardown.sh   # removes ONLY the attacker listener; leaves target intact
```
`run_all.sh` executes six PoCs in order: `00_recon` (informational), `01_unauth_webhook_trigger`, `02_ssrf_via_webhook_http_request`, `03_user_enumeration_no_captcha`, `04_system_object_permission_bypass`, and `04b_system_object_blast_radius`. It prints a per-PoC `RESULT=` line and a final `N CONFIRMED / N total` count.

> **Reading the runner output (important).** In `run_all.sh`, `RESULT=CONFIRMED` means *the mechanism the script exercises reproduced live* — it is NOT a statement that the mechanism is a product vulnerability. Only **two** of the reproduced mechanisms are reported as findings: **Finding 04 / 04b** (CRITICAL) and **Finding 03** (Medium). `01` and `02` reproduce their mechanisms on this test container but are **ruled out as product vulnerabilities in a default deployment** — see §4 for the precise reasons (01 requires possession of two unguessable 122-bit UUIDs; 02's internal/IMDS SSRF requires the non-default `OUTBOUND_HTTP_SAFE_MODE_ENABLED=false`). They are kept in the runner only so maintainers can observe the underlying behavior end-to-end.

---

## 2. Scope & Rules of Engagement

- **Audit only** — no changes were made to the target application.
- **Live-confirmed only** — a vector is reported as a finding ONLY if a PoC produced `RESULT=CONFIRMED` against the live pinned instance. Suspected-but-unconfirmed code paths are listed in §4 as ruled-out or open, never as findings.
- **Honest severity** — severity reflects real impact in a **default v2.8.3 deployment**. A weakness that is only reachable under a deliberately non-default/misconfigured environment is NOT reported as a product vulnerability.
- **Independent findings** — each PoC is self-contained.
- **No collateral** — the only container created by this audit is `audit-attacker-listener`; teardown removes only that.

---

## 3. Confirmed Findings

### Finding 04 — System-object permission bypass (RBAC bypass: cross-role read/write of all `isSystem` objects including secrets, email bodies, and calendar events)

**Severity: CRITICAL** (business impact: any authenticated workspace member, regardless of role, can read and modify every system object in the workspace — leaking embedded credentials, email content, and calendar PII, and tampering with automations).

**CVSS 3.1:** `AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N` → **8.1 (High)**. Privileges-required is LOW because an authenticated workspace member account is required (PR:None would require no account at all, which is not what the live run demonstrates). The CVSS numeric score is 8.1/High; the qualitative CRITICAL rating reflects the concrete blast radius — secrets, PII, and write access — proven live.

**Status: CONFIRMED live, deterministic across multiple independent runs** (re-verified 2/2 in the latest independent verification pass; reproduced on every run that reached the test phase).

**Affected component (v2.8.3, compiled):**
`/app/packages/twenty-server/dist/engine/twenty-orm/repository/permissions.utils.js` — `validateOperationIsPermittedOrThrow`:
```js
const objectMetadataIsSystem = objectMetadata.isSystem === true;
const isWorkspaceMemberObject =
    objectMetadata.universalIdentifier === WORKSPACE_MEMBER_OBJECT_UNIVERSAL_IDENTIFIER;
if (objectMetadataIsSystem && !isWorkspaceMemberObject) {
    return;  // early return BEFORE the switch(operationType) that enforces canReadObjectRecords
}
```
For any `isSystem===true` object except `workspaceMember`, the function returns before the `switch(operationType)` block that enforces `canReadObjectRecords`, `canUpdateObjectRecords`, `canSoftDeleteObjectRecords`, and `canDestroyObjectRecords`. Role record-permissions are silently ignored for the entire system-object class.

**Threat model:** Any authenticated workspace member assigned a custom role with `canReadAllObjectRecords=false` — the lowest-privilege posture a workspace admin can configure. No admin account, no victim interaction, and no special knowledge beyond having a workspace account are required.

**Reproduction:**
```bash
bash autofyn_audit/exploits/04_system_object_permission_bypass.sh   # core: secret plant + read/write bypass
bash autofyn_audit/exploits/04b_system_object_blast_radius.sh       # blast radius across all isSystem objects
```
Both scripts are included in `run_all.sh`.

**Evidence (live runs against v2.8.3; reproduced deterministically across every independent run that reached the test phase):**

Restricted member is correctly denied on non-system objects (all runs):
```json
{"data":{"companies":null},"errors":[{"message":"Entity performing the request does not have permission",
  "extensions":{"userFriendlyMessage":"User does not have permission.",
                "subCode":"PERMISSION_DENIED","code":"FORBIDDEN"}}]}
```
`code=FORBIDDEN subCode=PERMISSION_DENIED`, zero rows → `CONTROL_DENIED=true`. The `workflows` non-system object is denied identically (`workflows_denied=true`). RBAC is enforced for non-system objects, isolating the defect to the `isSystem` early-return.

Same restricted member (a separate principal, `canReadAllObjectRecords=false`) reads the planted secret marker out of `workflowVersions{steps[].settings.input.headers.Authorization}` — an HTTP-step `Bearer` token planted by the admin and verified via an admin self-read assert — with no permission error, on every run.

The marker is a **fresh per-run random nonce** of the form `SUPERSECRET-<32 hex chars>`; a maintainer re-running the PoC will see a different value each time (the PoC asserts the value it just planted, so this is not a hard-coded match). Representative values actually observed in independent verification runs:
- `secret_marker=SUPERSECRET-98c786d7df1fab85d6313b5956d44c86` (run reading back `workflowVersionId=bdb4285b-...`) → `READ_BYPASS=true`
- `secret_marker=SUPERSECRET-b27a3cfb862099a298aefe9be5292df2` (run reading back `workflowVersionId=453e263c-...`) → `READ_BYPASS=true`

The read is a genuine cross-principal exfiltration: a low-privilege member reads a secret a higher-privilege admin embedded in a workflow the member has no role-permission to read.

Same restricted member also writes a `workflowVersion` via `updateWorkflowVersion` (every run), despite `canUpdateAllObjectRecords=false`:
```json
{"data":{"updateWorkflowVersion":{"id":"<workflowVersionId>","name":"AuditWriteBypassed"}}}
```
`WRITE_BYPASS=true` — integrity impact, not just confidentiality.

Representative RESULT line (per-run marker/id elided to `<...>`; the verdict shape is identical on every run):
```
RESULT=CONFIRMED exploit=04_system_object_permission_bypass :: read_bypass=true control_denied=true
  write_bypass=true workflows_denied=true secret_marker=SUPERSECRET-<32hex>
  workflowVersionId=<uuid> :: member reads all workflowVersions.steps
  (including embedded HTTP Authorization headers) despite role having no WORKFLOWS settings flag —
  permissions.utils.js early-return for isSystem objects bypasses canRead=false enforcement;
  company read correctly denied
```

Blast-radius probe (`04b_system_object_blast_radius.sh`, verified live, **2/2 deterministic** in the latest independent verification) — same denied member, all isSystem queries accepted (no FORBIDDEN), while all non-system controls are correctly denied:

```
Object                           Bypassed  Rows
-------------------------------- --------- -----
workflowVersions (system)        yes       2     (returns real records including planted secret)
messageThreads   (system)        yes       0     (no email sync data in audit workspace; no denial)
calendarEvents   (system)        yes       0     (no calendar sync data; no denial)
messages/email bodies (system)   yes       0     (no email sync data; no denial)
blocklists       (system)        yes       0     (no denial)
workflowRuns     (system)        yes       0     (no denial)

companies  (non-system)          DENIED    0     (FORBIDDEN/PERMISSION_DENIED)
people     (non-system)          DENIED    0     (FORBIDDEN/PERMISSION_DENIED)
workflows  (non-system)          DENIED    0     (FORBIDDEN/PERMISSION_DENIED)
```

Empty `edges:[]` for `messageThreads`, `calendarEvents`, `messages`, `blocklists`, and `workflowRuns` reflects the absence of email/calendar integration data in the fresh audit workspace — NOT a denial. The bypass signal is the absence of a FORBIDDEN error, not the row count. In any production workspace with email or calendar sync, these tables hold the most sensitive PII in the product.

**Impact:** The bypass spans the full system-object class — read AND write — for any restricted workspace member:
- **Credentials leak:** workflow-embedded HTTP `Authorization: Bearer` tokens in `workflowVersions.steps`.
- **Email content:** `messages` (bodies) and `messageThreads` (threads) in any workspace with email sync.
- **Calendar PII:** `calendarEvents` in any workspace with calendar sync.
- **Automation tamper:** `workflowVersions` and `workflowRuns` writable by a denied member.
- **Blocklist exposure:** `blocklists` readable (contact suppression data).

Complete breakdown of object-level RBAC for the system-object class. Confidentiality and integrity both compromised.

**Remediation (suggested to maintainers; not applied):**
Remove the blanket `isSystem` early-return in `validateOperationIsPermittedOrThrow` so that system objects pass through the same `canReadObjectRecords`/`canUpdateObjectRecords`/`canSoftDeleteObjectRecords`/`canDestroyObjectRecords` enforcement as non-system objects. Treat `workspaceMember` as the narrow, documented exception rather than the entire `isSystem` class. If specific system objects must be world-readable within a workspace for operational reasons, add an explicit audited allowlist of object names — not a blanket class exemption.

---

### Finding 03 — Unauthenticated user/email enumeration via `checkUserExists` (no captcha, no rate-limit)

**Severity: Medium** (information disclosure; not a direct system compromise).
**CVSS 3.1:** `AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N` → **5.3 (Medium)**.

**Status: CONFIRMED live.**

**Affected component (v2.8.3, compiled):**
- Auth resolver `checkUserExists(email)` query, served unauthenticated on the **`/metadata`** GraphQL endpoint (in v2.8.3 the `AuthResolver` is a `MetadataResolver`; the resolver is reachable without any token).
- Captcha is a no-op in default config: the captcha service returns success when no captcha driver is configured. `/client-config` reports `captcha.driver: null` on this instance, confirming no captcha driver is active in the default Docker deployment.

**Threat model:** Any unauthenticated, remote attacker. No account, token, or victim interaction required.

**Reproduction:** `bash autofyn_audit/exploits/03_user_enumeration_no_captcha.sh`
The PoC registers a throwaway account via `signUp` (to obtain a guaranteed-existing email), then issues `checkUserExists` for that email and for a random non-existent email — both **unauthenticated, with no `captchaToken`** — and measures rate-limiting over 30 sequential calls.

**Evidence (observed live, v2.8.3):**
```
Known-existing email  → {"data":{"checkUserExists":{"exists":true,"isEmailVerified":false}}}
Random absent email   → {"data":{"checkUserExists":{"exists":false}}}
Rate-limit            → 30/30 sequential unauthenticated calls succeeded, 0 throttled (~10s)
RESULT=CONFIRMED exploit=03_user_enumeration_no_captcha :: checkUserExists distinguishes
  accounts (existing=true absent=false) with no Authorization header and no captchaToken
  on /metadata; rate_limit=30/30 succeeded (no throttling observed)
```

**Impact:** A distinguishable existence oracle lets an attacker confirm whether any given email is registered on the instance. At scale (no captcha and no rate-limit observed) this enables:
- Building a list of valid accounts for targeted **phishing** and **credential-stuffing / password-spray** campaigns.
- Confirming whether specific individuals/organizations use the instance.
The `isEmailVerified` flag additionally leaks per-account verification state.

This is **not** a direct compromise (no auth bypass, no data theft beyond existence/verification state), hence Medium, not High/Critical.

**Remediation (suggested to maintainers; not applied):**
1. Configure a captcha driver for `checkUserExists` in production, and add server-side rate-limiting (e.g. `@nestjs/throttler`) keyed on IP for unauthenticated auth-surface queries.
2. Consider removing the existence oracle entirely (e.g. always return a uniform response, or fold the check into a flow that does not reveal existence).

---

## 4. Investigated and Ruled Out

These vectors were examined against the compiled v2.8.3 code (and, where applicable, probed) and are **not** product vulnerabilities in a default deployment. They are documented for transparency and to scope future work.

| # | Vector | Verdict | Reason (verified in v2.8.3) |
|---|--------|---------|------------------------------|
| 01 | Unauthenticated webhook trigger `POST /webhooks/workflows/:workspaceId/:workflowId` | **By design — not a vuln** | The endpoint is intentionally public (`PublicEndpointGuard`). Security rests on two unguessable 122-bit UUIDs (workspace id + workflow id) that the workflow owner shares with their integration, exactly like a GitHub/Stripe webhook URL. An attacker without those UUIDs cannot trigger anything; triggering one's own workflow is not an exploit. |
| 02 | SSRF via `HTTP_REQUEST` workflow action / `testHttpRequest` | **Not a vuln in default config** | The outbound HTTP client is SSRF-hardened when `OUTBOUND_HTTP_SAFE_MODE_ENABLED` is on, and that flag **defaults to `true`** in v2.8.3 (`config-variables.js`). Only our test container explicitly set it to `false`. A default deployment blocks private-IP/metadata SSRF. Reporting this as a product vuln would be inaccurate. |
| — | Path traversal on public file route `GET /file/public-assets/:workspaceId/:applicationId/*path` | **Not a vuln** | Four independent defenses: path normalization rejecting `..` segments, a per-segment `^[a-zA-Z0-9._-]+$` allowlist, a DB lookup requiring a matching `file` record before any byte is served, and `realpathSync` + storage-root containment check in the local driver. |
| — | `/s/*path` public route-trigger (logic functions) | **Not exploitable in default config** | Fully public for all HTTP verbs, but logic-function execution is gated by `LOGIC_FUNCTION_TYPE`, which defaults to `DISABLED` in the standard Docker deployment, so no code executes. (Note for operators: if logic functions are enabled and a route's `isAuthRequired` is false, this becomes an unauthenticated cross-workspace invocation surface — worth hardening, but not exploitable as shipped.) |
| — | Cross-workspace IDOR / tenant isolation | **Not a vuln** | The active workspace is derived from the verified JWT's `workspaceId` claim (`bindDataToRequestObject`), not from any client-supplied header or argument. Manipulating IDs/Origin does not cross tenants. |
| — | Password-reset / token flows | **Not a vuln** | Reset tokens use `crypto.randomBytes(32)` (256-bit), are SHA-256-hashed at rest, and expire (5m). JWT verification pins a single-element `algorithms` array, preventing algorithm-confusion. |
| — | SQL injection in dynamic record API (filter/orderBy) | **Not a vuln** | Filter keys are validated against a server-side metadata field allowlist (`fieldIdByName`) and rejected before any SQL is built; values are TypeORM-parameterized. |
| — | File-upload stored XSS / upload abuse | **Not a vuln** | Magic-byte content-type detection, DOMPurify sanitization for SVG, and `Content-Disposition: attachment` for non-inline types (SVG is not inline-safe). Defense-in-depth holds. |
| — | Predictable dev-seed invite hash (`apple.dev-invite-hash` / `yc.dev-invite-hash`) → unauthenticated workspace join via `signUpInWorkspace` | **Working as intended — not a product vuln** | The public invite-link feature is intentionally enabled (`isPublicInviteLinkEnabled` defaults to `true`), and an invite hash is a bearer credential by design (same model as a GitHub/Stripe invite URL). In **production**, `inviteHash` is a 122-bit UUID v4 — unguessable without prior exposure. The literal `apple.`/`yc.` hashes only exist in the **dev-seed demo workspaces** shipped for evaluation, not in real deployments. Reporting this as a vulnerability would misrepresent a demo-seed convenience as a product flaw. (Operator note: invite hashes never expire/rotate — worth hardening, but not a default-config product vuln.) |
| — | Admin-panel config exposure (`getConfigVariablesGrouped`, `getDatabaseConfigVariable`) | **Not a vuln** | `isSensitive` values are masked by `maskSensitiveValue()` before return, and the resolvers are double-gated by `AdminPanelGuard` (server-level superadmin) + `SettingsPermissionGuard(SECURITY)`. Not reachable by regular members/admins. |
| — | Cross-workspace role assignment via user-supplied `roleId` (`updateWorkspaceMemberRole`, `upsertObjectPermissions`) | **Not a vuln** | Role lookups resolve against workspace-scoped flat maps (`flatRoleMaps`/`universalIdentifierById` loaded for the caller's `workspaceId`); a foreign `roleId` is undefined and throws `ROLE_NOT_FOUND`/`FlatEntityMapsException` before any assignment. |
| — | SNS/SES inbound webhook subscription-confirmation SSRF | **Not exploitable in default config** | SNS signature verification runs before the subscription-confirmation fetch, and the topic must be in `SES_SNS_TOPIC_ARN_ALLOWLIST` (empty by default → rejected). |
| — | OAuth `redirectLocation` open redirect (`connection-provider-oauth.controller.ts`) | **Low / not a vuln** | `redirectLocation` is carried in an `APP_SECRET`-signed state JWT and applied via `url.pathname`; the Node `URL.pathname` setter cannot change the host, so the redirect stays same-host. |

> **Round-6 second-finding hunt (transparency).** A dedicated pass over impersonation (`canImpersonate`), the admin panel, SSO/Google/Microsoft OAuth state and `returnToPath` handling, invitation/2FA flows, the REST API, billing/messaging webhooks, row-level permission predicates, and API-key minting found **no additional independent critical/high product vulnerability** beyond Finding 04. The candidates examined are recorded above. This confirms the codebase is otherwise well-defended; Finding 04 stands as the single critical issue.

---

## 5. Posture Summary

This audit confirmed **one CRITICAL object-level RBAC bypass** and **one Medium information-disclosure weakness** against the live v2.8.3 pinned instance.

The CRITICAL finding (Finding 04) is a complete breakdown of role-based record-permission enforcement for the `isSystem=true` object class. Any authenticated workspace member, regardless of role restrictions, can read and write every system object — including workflow-embedded credentials, email message bodies and threads, calendar events, blocklists, and automation run state. The root cause is a single unconditional early-return in compiled server code (`permissions.utils.js`) that predates any role-permission check.

The Medium finding (Finding 03) is an unauthenticated email-existence oracle with no captcha and no rate-limit in the default deployment.

The common critical attack classes — SSRF, path traversal, SQLi, IDOR/tenant-isolation, auth-token weaknesses, upload XSS — were investigated and ruled out (§4). That hardening is genuine but does not offset the severity of the RBAC bypass.

**Files:**
- `setup.sh` / `run_all.sh` / `teardown.sh` — scripted setup, live PoC run, and safe teardown.
- `lib/common.sh` — v2.8.3 auth helpers (`/metadata` endpoint, `signUp`/workspace bootstrap, enumeration oracle helper).
- `exploits/00_recon.sh` — environment recon (informational).
- `exploits/03_user_enumeration_no_captcha.sh` — confirmed Finding 03 PoC (Medium).
- `exploits/04_system_object_permission_bypass.sh` — confirmed Finding 04 PoC: core RBAC bypass with planted secret, read and write (CRITICAL).
- `exploits/04b_system_object_blast_radius.sh` — confirmed Finding 04 blast-radius probe: uniform bypass across all isSystem objects (CRITICAL, companion to 04).
- `exploits/01_*`, `exploits/02_*` — **mechanism demonstrations, RULED OUT as product vulnerabilities** (see §4). They are run by `run_all.sh` so maintainers can observe the behavior end-to-end; their `RESULT=CONFIRMED` denotes a reproduced mechanism, NOT a finding.
