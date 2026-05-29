# autofyn_audit — Twenty CRM Security Audit PoC Package

Reproducible audit package for Twenty CRM targeting:
- **Image:** `twentycrm/twenty@sha256:fd6faa713fd2042d5d87e5705d47d24e492fc5202e7394e188f438085b483fad`
- **Commit:** `fc90b4ba8bb0a5d7c12c846fe9b2305527a0f7a8`

## Usage

```bash
bash autofyn_audit/setup.sh      # Step 1: verify pinned image, health-check server, start listener
bash autofyn_audit/run_all.sh    # Step 2: run all PoCs; prints RESULT=CONFIRMED/NOT-CONFIRMED per exploit
bash autofyn_audit/teardown.sh   # Step 3: remove auxiliary infra (listener only; harness containers untouched)
```

To run a single exploit:
```bash
bash autofyn_audit/run_all.sh 01   # runs only 01_unauth_webhook_trigger
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

| Script | Vulnerability | Auth Required |
|--------|--------------|--------------|
| `00_recon.sh` | Environment recon + bootstrap resolution | No |
| `01_unauth_webhook_trigger.sh` | Unauthenticated webhook trigger | Bootstrap login |
| `02_ssrf_via_webhook_http_request.sh` | SSRF via webhook HTTP_REQUEST step | Bootstrap login |
| `03_user_enumeration_no_captcha.sh` | User enumeration, no captcha | No |

## Auth Bootstrap

PoCs 01 and 02 authenticate by logging in as the seeded workspace member:
- Email: `tim@apple.dev`
- Password: `tim@apple.dev`

This is a dev-seeder account. If absent on the target (non-dev image), PoCs 01/02 will print `NOT-CONFIRMED` with reason `bootstrap unavailable: <reason>` — this is expected behavior, not a script error.

## Constraints

- **No harness containers touched.** `setup.sh` and `teardown.sh` never modify `audit-twenty-*` containers.
- **All network calls have timeouts.** `--max-time 15` on every curl; `timeout 120` per exploit in `run_all.sh`.
- **Idempotent.** Re-running `setup.sh` or `run_all.sh` is safe.
