# Twenty CRM Security Audit

## Pinned versions

| Item | Value |
|---|---|
| Repo commit | `tempcollab/twenty @ fc90b4ba8bb0a5d7c12c846fe9b2305527a0f7a8` |
| Docker image | `twentycrm/twenty@sha256:fd6faa713fd2042d5d87e5705d47d24e492fc5202e7394e188f438085b483fad` (v2.8.3) |

## How to run

### 1. Provision the live instance

```bash
bash autofyn_audit/setup.sh
```

This starts four containers on docker network `twenty-audit-net`:

| Container | Role |
|---|---|
| `audit-twenty-db` | PostgreSQL 16 |
| `audit-twenty-redis` | Redis 7 |
| `audit-twenty-server` | Twenty server (port 3000 on 127.0.0.1) |
| `audit-twenty-worker` | Twenty background worker |

The script waits until `http://127.0.0.1:3000/healthz` returns 200 before exiting.

### 2. Run exploits

```bash
# From the host (default):
bash autofyn_audit/run_exploits.sh

# From inside the docker network (e.g. another container):
TARGET=http://audit-twenty-server:3000 bash autofyn_audit/run_exploits.sh
```

The script discovers all `autofyn_audit/exploits/<name>/run.sh` files, executes each,
and prints a pass/fail summary table.

### 3. Tear down

```bash
bash autofyn_audit/teardown.sh
```

Removes all four containers and the `twenty-audit-net` network.

## Adding exploits

Create a directory under `autofyn_audit/exploits/<exploit-name>/` containing at minimum:

- `run.sh` — executable script that exits 0 on confirmed exploitation, non-zero on failure.
  The `TARGET` environment variable is set by `run_exploits.sh` (default `http://127.0.0.1:3000`).

Example layout:

```
autofyn_audit/exploits/
  .gitkeep
  ssrf-webhook/
    run.sh
    README.md
  rce-code-interpreter/
    run.sh
    payload.js
    README.md
```
