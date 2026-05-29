# Twenty CRM Security Audit — Exploit Harness

**Authorized internal security audit of self-hosted Twenty CRM.**  
**Do NOT run against any instance without explicit authorization.**

## Pinned Hashes

| Component | Value |
|-----------|-------|
| Repo commit | `fc90b4ba8bb0a5d7c12c846fe9b2305527a0f7a8` |
| Server image | `twentycrm/twenty@sha256:fd6faa713fd2042d5d87e5705d47d24e492fc5202e7394e188f438085b483fad` |
| DB image | `postgres:16@sha256:4b7183ac05f8ef417db21fd72d71047a4238340c261d3cc3ddb6d579ab5071ae` |
| Redis image | `redis:7-alpine@sha256:6ab0b6e7381779332f97b8ca76193e45b0756f38d4c0dcda72dbb3c32061ab99` |

## Prerequisites

- `python3` in PATH (stdlib only — no pip installs required)
- `curl` in PATH (for connectivity check in setup.sh)
- `docker` CLI accessible (for `docker network connect` if needed)
- The reviewer container must be able to reach `172.20.0.4:3000`

## Quick Start

```bash
# 1. Run setup (idempotent — also connects to docker network if needed)
bash autofyn_audit/setup.sh

# 2. Run all exploits (continues even if one fails)
bash autofyn_audit/run_all_exploits.sh

# 3. Clean up created artifacts
bash autofyn_audit/teardown.sh
```

## Expected Outputs

### Finding A — Logic Function RCE

**PASS** (when `LOGIC_FUNCTION_TYPE=LOCAL`):
```
RESULT: PASS
  OS command output (id): uid=1000(twenty) gid=1000(twenty) groups=...
  APP_SECRET: abc123... (len=64)
  ENCRYPTION_KEY: def456... (len=32)
  ...
```

**PRECONDITION_NOT_MET** (when driver is disabled):
```
RESULT: PRECONDITION_NOT_MET
  LOGIC_FUNCTION_TYPE is not LOCAL — execution is disabled on this instance.
```

Exit codes: 0 = PASS, 1 = FAIL, 2 = setup error, 3 = PRECONDITION_NOT_MET

### Finding B — IMAP SSRF

**PASS**:
```
RESULT: PASS
  At least one internal service port (5432 or 6379) classified OPEN/reached
  AND the control closed port classified ECONNREFUSED.
```

**FAIL** (if safe mode is on or connection test is disabled):
```
RESULT: FAIL
  open_internal=False, closed_control=True
```

## File Tree

```
autofyn_audit/
├── README.md                        # This file
├── setup.sh                         # Env prep + network connect + config.env
├── run_all_exploits.sh              # Runs both exploits; prints summary table
├── teardown.sh                      # Deletes logic functions; documents un-cleanables
├── audit_report.md                  # Audit findings with file:line citations
├── lib/
│   ├── __init__.py
│   └── twenty_client.py             # Shared GraphQL client (stdlib only)
├── exploits/
│   ├── finding_a_logic_function_rce.py
│   └── finding_b_imap_ssrf.py
└── evidence/                        # Created at runtime
    ├── .gitkeep
    ├── finding_a.json               # Finding A evidence
    ├── finding_a_secret.txt         # Full secret values (restrict access)
    ├── finding_b.json               # Finding B evidence
    ├── created_objects.json         # IDs for teardown
    ├── exploit_a.log                # Full stdout+stderr from Finding A
    └── exploit_b.log                # Full stdout+stderr from Finding B
```

## Notes

- Each run generates fresh attacker email addresses to avoid collisions.
- `evidence/finding_a_secret.txt` contains the full `APP_SECRET`/`ENCRYPTION_KEY` values — restrict access.
- `evidence/` is gitignored by default to prevent accidental secret commit.
- Teardown cannot remove connected accounts or user/workspace rows via the public API;
  see `teardown.sh` for manual DB cleanup instructions (audit firm does not perform these).
