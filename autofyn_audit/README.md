# autofyn_audit — Twenty CRM Security Audit PoC Package

Reproducible audit package for Twenty CRM targeting:
- **Image:** `twentycrm/twenty@sha256:fd6faa713fd2042d5d87e5705d47d24e492fc5202e7394e188f438085b483fad`
- **Running release:** `v2.8.3` (API shapes/guards/config defaults verified against the compiled code in the running container)
- **Repo base commit (audit checkout):** `fc90b4ba8bb0a5d7c12c846fe9b2305527a0f7a8`

See `audit_report.md` for findings. **Confirmed: 2 findings — 1 HIGH + 1 Low/Informational.**
- **HIGH — Finding 04:** workflow-object RBAC bypass. A workspace member whose role lacks the `WORKFLOWS` settings permission (cache-computed `canRead=false`, correctly denied on the dedicated workflow resolvers) can still read AND write `workflow`/`workflowRun`/`workflowVersion` via the generic GraphQL data API, because `validateOperationIsPermittedOrThrow` early-returns for `isSystem` objects before consulting the computed permission. Impact: exfiltration of workflow-embedded `Authorization: Bearer` secrets (replayable against the external API) and automation tampering — proven live end-to-end (`04`, blast-radius companion `04b`, and impact chain `chain_01`). Scope note: the early-return mechanically reaches all `isSystem` objects, but only the workflow-related class is an actual escalation — other `isSystem` objects (`blocklist`, `messageThread`) are workspace-readable by design and cannot be restricted by any role; `message`/`calendarEvent` are independently protected by visibility hooks. See `audit_report.md` §3–§4.
- **Low/Informational — Finding 03:** unauthenticated, captcha-less, unthrottled user enumeration via `checkUserExists` — an accepted-risk UX pattern with a shipped opt-in captcha mitigation.

## Usage

```bash
bash autofyn_audit/setup.sh      # Step 1: verify pinned image, health-check server, start listener
bash autofyn_audit/run_all.sh    # Step 2: run all PoCs; prints RESULT=CONFIRMED/NOT-CONFIRMED per exploit
bash autofyn_audit/teardown.sh   # Step 3: remove auxiliary infra (listener only; harness containers untouched)
```

To run a single exploit:
```bash
bash autofyn_audit/run_all.sh 03   # runs only 03_user_enumeration_no_captcha
```

## Prerequisites

- `docker` on PATH, with access to docker socket
- `jq` on the host (used for JSON extraction in scripts)
- Docker network `twenty-audit-net` must exist with `audit-twenty-server` container running
- Helper images must be pulled:
  - `curlimages/curl@sha256:b3f1fb2a51d923260350d21b8654bbc607164a987e2f7c84a0ac199a67df812a`
  - `alpine@sha256:de0eb0b3f2a47ba1eb89389859a9bd88b28e82f5826b6969ad604979713c2d4f`

## Pinned Digests

Resolved at build time via `docker images --digests`:

| Image | Digest |
|-------|--------|
| `curlimages/curl:latest` | `sha256:b3f1fb2a51d923260350d21b8654bbc607164a987e2f7c84a0ac199a67df812a` |
| `alpine:3.18` | `sha256:de0eb0b3f2a47ba1eb89389859a9bd88b28e82f5826b6969ad604979713c2d4f` |

## Exploit Map

In `run_all.sh`, `RESULT=CONFIRMED` means the script's **mechanism reproduced live**, NOT that it is a product vulnerability. Only `04`/`04b` (HIGH) and `03` (Low/Informational) are reported findings; `01`/`02` are ruled-out mechanism demonstrations (see `audit_report.md` §4).

| Script | Status | Auth Required | Run by run_all.sh |
|--------|--------|---------------|-------------------|
| `00_recon.sh` | Informational recon | No | Yes |
| `04_system_object_permission_bypass.sh` | **FINDING — HIGH** — workflow-object RBAC bypass: cross-principal secret read-back + write (deterministic across independent runs) | Yes (restricted member) | Yes |
| `04b_system_object_blast_radius.sh` | **FINDING — HIGH (companion)** — mechanism probe: early-return reaches all isSystem objects (only workflow class is an escalation) | Yes (restricted member) | Yes |
| `chain_01_workflow_secret_to_external_compromise.sh` | **FINDING — HIGH (impact proof)** — stolen workflow Bearer token replayed for live external-API access | Yes (restricted member) | No (run separately; manages own mock) |
| `03_user_enumeration_no_captcha.sh` | **FINDING — Low/Informational** — user enumeration, no captcha, no rate-limit | No | Yes |
| `01_unauth_webhook_trigger.sh` | **RULED OUT** — by-design public endpoint secured by unguessable 122-bit UUIDs (see `audit_report.md` §4) | n/a | Yes (mechanism demo only) |
| `02_ssrf_via_webhook_http_request.sh` | **RULED OUT** — SSRF safe-mode defaults ON in v2.8.3; only our test env disabled it (see `audit_report.md` §4) | n/a | Yes (mechanism demo only) |

## Auth Bootstrap

The confirmed PoC needs only a known-existing email, obtained via a real `signUp`
on the `/metadata` endpoint (auth resolvers live at `/metadata`, not `/graphql`,
in v2.8.3). `lib/common.sh` also provides a full workspace-scoped ACCESS-token
chain (`signUp` → `signUpInNewWorkspace` → `getAuthTokensFromLoginToken`) for any
authenticated probing. There is **no** reliance on a seeded `tim@apple.dev`
account — that dev-seeder account is absent from the production image.

## Constraints

- **No harness containers touched.** `setup.sh` and `teardown.sh` never modify `audit-twenty-*` containers.
- **All network calls have timeouts.** `--max-time 15` on every curl; `timeout 120` per exploit in `run_all.sh`.
- **Idempotent.** Re-running `setup.sh` or `run_all.sh` is safe.
