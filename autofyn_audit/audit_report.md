# Twenty CRM — Security Audit Report

**Date:** 2026-05-29
**Auditor:** AutoFyn security audit team
**Result:** 1 confirmed finding (Medium). No critical or high-severity exploit was found; several plausible critical vectors were investigated and ruled out (see §4).

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
`run_all.sh` executes `00_recon` (informational) and `03_user_enumeration_no_captcha` (the confirmed finding). It prints a final `N CONFIRMED / N total` line.

---

## 2. Scope & Rules of Engagement

- **Audit only** — no changes were made to the target application.
- **Live-confirmed only** — a vector is reported as a finding ONLY if a PoC produced `RESULT=CONFIRMED` against the live pinned instance. Suspected-but-unconfirmed code paths are listed in §4 as ruled-out or open, never as findings.
- **Honest severity** — severity reflects real impact in a **default v2.8.3 deployment**. A weakness that is only reachable under a deliberately non-default/misconfigured environment is NOT reported as a product vulnerability.
- **Independent findings** — each PoC is self-contained.
- **No collateral** — the only container created by this audit is `audit-attacker-listener`; teardown removes only that.

---

## 3. Confirmed Finding

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

---

## 5. Posture Summary

Twenty v2.8.3 is, on the evidence of this audit, **well-hardened** against the common critical classes (SSRF, path traversal, SQLi, IDOR/tenant-isolation, auth-token weaknesses, upload XSS). The one confirmed weakness is an unauthenticated, unthrottled, captcha-less **user-enumeration oracle** (Medium). We deliberately do **not** claim a critical finding where the evidence does not support one.

**Files:**
- `setup.sh` / `run_all.sh` / `teardown.sh` — scripted setup, live PoC run, and safe teardown.
- `lib/common.sh` — v2.8.3 auth helpers (`/metadata` endpoint, `signUp`/workspace bootstrap, enumeration oracle helper).
- `exploits/00_recon.sh` — environment recon (informational).
- `exploits/03_user_enumeration_no_captcha.sh` — the confirmed Finding 03 PoC.
- `exploits/01_*`, `exploits/02_*` — retained but marked **RULED OUT** (see §4); excluded from `run_all.sh`.
