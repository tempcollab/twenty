# Twenty CRM Security Audit — 2026-05-29

**Status: PENDING LIVE CONFIRMATION — findings filled only after reviewer runs `run_all.sh` against live.**

## Target

- **Image:** `twentycrm/twenty@sha256:fd6faa713fd2042d5d87e5705d47d24e492fc5202e7394e188f438085b483fad`
- **Commit:** `fc90b4ba8bb0a5d7c12c846fe9b2305527a0f7a8`
- **Instance:** `http://audit-twenty-server:3000` on docker network `twenty-audit-net`
- **Date:** 2026-05-29

---

## Scope & Rules

- **Audit only.** No fixes applied to the target.
- **Findings are live-confirmed only.** Suspected code paths insufficient — each finding requires `RESULT=CONFIRMED` from a PoC run against the live pinned instance.
- **Independent findings.** Each PoC (01, 02, 03) is self-contained and does not depend on another PoC succeeding.
- **No unrelated containers touched.** Only `audit-attacker-listener` auxiliary infra was created by this audit.

---

## Methodology

1. **Static triage** — read source at commit `fc90b4ba` to identify candidate vulnerabilities.
2. **PoC scripting** — write reproducible shell scripts under `autofyn_audit/exploits/`.
3. **Live PoC confirmation** — reviewer runs scripts against the live pinned instance.

**How to reproduce:**
```bash
bash autofyn_audit/setup.sh      # idempotent; verify network + listener
bash autofyn_audit/run_all.sh    # run all PoCs; prints RESULT= per exploit
bash autofyn_audit/teardown.sh   # remove auxiliary infra only
```

**Authentication note:** All PoCs that require authentication (01, 02) bootstrap by logging in as the seeded workspace member `tim@apple.dev` (password: `tim@apple.dev`). Findings depending on auth are CONFIRMABLE only if this account exists on the target image. If the seeded account is absent, those PoCs will print `NOT-CONFIRMED` with reason `bootstrap unavailable: <reason>` — this is a correct, non-buggy outcome.

---

## Environment / Reproducibility

| Item | Value |
|------|-------|
| Target image digest | `sha256:fd6faa713fd2042d5d87e5705d47d24e492fc5202e7394e188f438085b483fad` |
| Target commit | `fc90b4ba8bb0a5d7c12c846fe9b2305527a0f7a8` |
| Docker network | `twenty-audit-net` |
| Helper image | `curlimages/curl@sha256:b3f1fb2a51d923260350d21b8654bbc607164a987e2f7c84a0ac199a67df812a` |
| Listener image | `alpine@sha256:de0eb0b3f2a47ba1eb89389859a9bd88b28e82f5826b6969ad604979713c2d4f` |
| Listener name | `audit-attacker-listener` |
| Listener port | `8888` |

---

## Findings

---

### Finding 01 — Unauthenticated Webhook Trigger

**Title:** Unauthenticated POST to `/webhooks/workflows/:workspaceId/:workflowId` triggers arbitrary workflow execution

**Status:** PENDING LIVE CONFIRMATION

**Severity:** `<TBD — fill after live confirmation>`

**CVSS-style vector:** `<TBD>`

**CVSS rationale:** `<TBD>`

**Affected component:**
- File: `packages/twenty-server/src/engine/core-modules/workflow/controllers/workflow-trigger.controller.ts:53-74`
- Guards: `@UseGuards(PublicEndpointGuard, NoPermissionGuard)`
- `PublicEndpointGuard.canActivate` returns `true` unconditionally (`engine/guards/public-endpoint.guard.ts:16`)

**Preconditions:**
- Attacker knows a valid `workspaceId` and `workflowId` for a published WEBHOOK-triggered workflow.
- The workflow must be activated (`lastPublishedVersionId` set, version `status=ACTIVE`, trigger `type=WEBHOOK`).

**Reproduction steps:** Run `bash autofyn_audit/exploits/01_unauth_webhook_trigger.sh`

**Evidence:** `<TBD — paste RESULT=CONFIRMED line + workflowRunId from live run>`

**Impact:** `<TBD — any unauthenticated external caller can trigger workflow execution; depending on workflow steps, this may exfiltrate data, send emails, or chain into further attacks>`

**Remediation:** Require authentication or HMAC signature verification on the webhook endpoint. Add a secret/token to the webhook URL or validate a shared signature header before executing the workflow.

**Independence note:** Self-contained — own workflow created under bootstrap account. Does not depend on 02 or 03.

---

### Finding 02 — SSRF via Unauthenticated Webhook-Triggered HTTP_REQUEST Step

**Title:** Unauthenticated webhook trigger drives server-side HTTP request to attacker-controlled host (SSRF)

**Status:** PENDING LIVE CONFIRMATION

**Severity:** `<TBD — fill after live confirmation>`

**CVSS-style vector:** `<TBD>`

**CVSS rationale:** `<TBD>`

**Affected components:**
- `workflow-trigger.controller.ts:53-74` (unauthenticated trigger — no auth required)
- HTTP_REQUEST workflow step: server-side outbound HTTP call to step-configured URL
- `secure-http-client.service.ts`: `OUTBOUND_HTTP_SAFE_MODE_ENABLED` defaults true; blocks private IPs at DNS lookup but allows external hosts

**Preconditions:**
- Attacker can create a WEBHOOK workflow with an HTTP_REQUEST step (requires authenticated workflow creation — bootstrap account used in PoC).
- Attacker knows the `workspaceId` and `workflowId` (obtained after creation).

**Reproduction steps:** Run `bash autofyn_audit/exploits/02_ssrf_via_webhook_http_request.sh`

**Evidence:** `<TBD — paste RESULT=CONFIRMED line + SSRF token received at listener>`

**Blast-radius note:** `<TBD — paste informational internal SSRF probe result: BLOCKED or REACHABLE>`

**Impact:** `<TBD — server sends outbound HTTP to attacker-controlled URL without authentication; can be used to bypass `OUTBOUND_HTTP_SAFE_MODE_ENABLED` for external hosts, perform reconnaissance against external services from the server's IP, or exfiltrate internal metadata in future rounds if safe-mode is disabled>`

**Remediation:** Require authentication on the webhook trigger endpoint (see Finding 01 remediation). Additionally, validate and restrict the HTTP_REQUEST step URL at workflow creation time, not only at execution time.

**Independence note:** Self-contained — own workflow with own SSRF token. Does not depend on 01 confirming.

---

### Finding 03 — User Enumeration via Unauthenticated `checkUserExists` (No Captcha, No Rate-Limit)

**Title:** `checkUserExists` GraphQL query reveals account existence without captcha or rate-limiting

**Status:** PENDING LIVE CONFIRMATION

**Severity:** `<TBD — fill after live confirmation>`

**CVSS-style vector:** `<TBD>`

**CVSS rationale:** `<TBD>`

**Affected component:**
- File: `packages/twenty-server/src/engine/core-modules/auth/auth.resolver.ts:130-138`
- Guards: `@UseGuards(CaptchaGuard, PublicEndpointGuard, NoPermissionGuard)`
- `captcha.service.ts:11-19`: returns `{success: true}` when `CAPTCHA_DRIVER` env var is unset — captcha guard always passes in default config

**Preconditions:**
- `CAPTCHA_DRIVER` env var must be unset (default Docker deployment).
- No separate rate-limiting middleware on this endpoint.

**Reproduction steps:** Run `bash autofyn_audit/exploits/03_user_enumeration_no_captcha.sh`

**Evidence:** `<TBD — paste RESULT=CONFIRMED line + oracle distinguishability result + rate-limit result>`

**Impact:** `<TBD — attacker can enumerate all registered email addresses via high-volume automated queries; enables targeted phishing and password-spray attacks>`

**Remediation:** Configure `CAPTCHA_DRIVER` in production deployments. Add rate-limiting middleware (e.g. `@nestjs/throttler`) to the `checkUserExists` query. Consider returning a non-distinguishable response to prevent enumeration even with captcha configured.

**Independence note:** Does not require authentication — depends only on the seeded account's email as oracle. Self-contained from 01 and 02.

---

## Recon Summary (00_recon — informational, not a finding)

`<TBD — paste RESULT= line from 00_recon live run including bootstrap=ok|unavailable workspaceId introspection signup status>`

---

*All findings above carry status PENDING LIVE CONFIRMATION. Severity, CVSS vectors, and evidence fields will be filled after the reviewer runs `bash autofyn_audit/run_all.sh` against the live pinned instance and observes `RESULT=CONFIRMED` for each.*
