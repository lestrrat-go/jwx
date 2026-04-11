# Companion Modules

## Overview

Extension modules under `github.com/jwx-go/*` (asmbase64, ed448, es256k, examples,
jwkcache, mldsa, x448, benchmarks) are managed as "companion modules." They live in
separate repos but share CI workflows, dependabot config, and development tooling.

## Directory Layout

```
companions.yaml          # Module registry (tracked in git)
.companions/
  repo/                  # Cloned companion repos (gitignored)
    asmbase64/
    ed448/
    ...
  templates/             # Standardized workflow templates (tracked in git)
    ci.yml
    lint.yml
    dependabot.yml
    ...
```

- `companions.yaml` — lists every companion module: name, repo URL, default branch,
  and flags (e.g. `runtests: false` for benchmarks).
- `.companions/repo/` — shallow clones, managed by scripts and skills. Gitignored.
- `.companions/templates/` — canonical CI/config files that get synced to all modules.
  Tracked in git — these are the source of truth.

## Tools

### `scripts/test-companion.sh`

Runs `go test -race ./...` against companion modules using the local jwx checkout
via a temporary `go.work` file. Clones are placed in `.companions/repo/`.

```bash
# Test all companion modules
./scripts/test-companion.sh

# Test specific modules
./scripts/test-companion.sh "ed448,x448"
```

### `/jwx-companion-bulk` skill

Applies bulk operations (CI sync, dependency bumps, file updates) across all or
selected companion modules. See `.claude/skills/jwx-companion-bulk/SKILL.md` for
full documentation.

```
/jwx-companion-bulk sync ci.yml and lint.yml from templates --pr
/jwx-companion-bulk bump jwx dependency to latest --modules=ed448,x448
```

## Template Workflow

To standardize a workflow file across companion modules:

1. Edit the template in `.companions/templates/` (e.g. `ci.yml`).
2. Use `/jwx-companion-bulk` to sync it across modules.
3. Templates may contain placeholders that get adapted per module (branch patterns,
   module-specific paths). The skill handles adaptation automatically.

## companions.yaml Schema

```yaml
modules:
  - name: asmbase64                          # Directory name under .companions/repo/
    repo: git@github.com:jwx-go/asmbase64.git
    branch: develop/v4                       # Default branch
  - name: benchmarks
    repo: git@github.com:jwx-go/benchmarks.git
    branch: main
    runtests: false                          # Skip in test-companion.sh
```
