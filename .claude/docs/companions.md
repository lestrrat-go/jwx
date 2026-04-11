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

## Template System

Templates in `.companions/templates/` use `{{placeholder}}` syntax for per-module
values. All placeholder values come from `companions.yaml`.

### Available Placeholders

| Placeholder | Source | Example |
|-------------|--------|---------|
| `{{name}}` | `modules[].name` | `ed448` |
| `{{branch}}` | `modules[].branch` | `develop/v4` |

### Rendering

`scripts/companion-render-template.py` renders a template for a single module:

```bash
python3 scripts/companion-render-template.py .companions/templates/dependabot.yml ed448
```

Reads `companions.yaml`, substitutes placeholders, writes to stdout.

### Workflow

To standardize a file across companion modules:

1. Edit the template in `.companions/templates/`.
2. Use `/jwx-companion-bulk` to render and sync across modules.
3. The bulk skill calls the render script per module, then commits the output.

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
