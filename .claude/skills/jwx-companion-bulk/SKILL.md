---
name: jwx-companion-bulk
description: Apply bulk operations across all jwx companion modules. Args: <instructions...>
---

# jwx-companion-bulk

Apply a uniform operation across jwx companion modules (github.com/jwx-go/*).
Handles cloning, branching, applying changes, verifying, committing, and reporting.

## Arguments

`/jwx-companion-bulk <instructions...>`

- `$INSTRUCTIONS` (required) — what to do across companion modules. Free-form text.

### Flags (parsed from instructions)

- `--modules=<name,name,...>` — target only these modules (comma-separated names)
- `--ref-module=<name>` — use this module as the reference/template for file-copy operations
- `--pr` — push branches and create PRs (off by default; commits locally only)
- `--dry-run` — show what would change without modifying anything

If instructions are ambiguous, ask the user before proceeding.

## 1. Read Config

1. Read `companions.yaml` from the project root.
2. Parse the `modules` list. Each entry has: `name`, `repo`, `branch`.
3. If `--modules=` was provided, filter to only those names. Error if a name is not found.

## 2. Ensure Clones

For each module in the (filtered) list:

1. If `$PROJECT/.companions/repo/<name>/` does not exist:
   ```
   cd $PROJECT
   git clone <repo> .companions/repo/<name>
   ```

2. If it already exists, update it:
   ```
   cd $PROJECT/.companions/repo/<name>
   git fetch origin
   ```

3. Determine the default branch for each module:
   - If `branch` is set in the config, use that.
   - Otherwise, read `origin/HEAD`:
     ```
     cd $PROJECT/.companions/repo/<name>
     git symbolic-ref refs/remotes/origin/HEAD
     ```
     This returns e.g. `refs/remotes/origin/develop/v4` — strip the prefix.
   - If `origin/HEAD` is not set, query GitHub:
     ```
     gh repo view <org>/<name> --json defaultBranchRef --jq .defaultBranchRef.name
     ```

4. Checkout the default branch:
   ```
   cd $PROJECT/.companions/repo/<name>
   git checkout <default-branch>
   ```
   ```
   cd $PROJECT/.companions/repo/<name>
   git pull --ff-only
   ```

## 3. Pre-flight Checks

Run these on ALL targeted modules BEFORE modifying ANY:

1. **Clean working tree**: `git status --porcelain` must produce empty output.
   If any module is dirty, report which ones and STOP.

2. **Remote reachable** (only if `--pr`): `git ls-remote origin HEAD` must succeed.

3. **gh auth** (only if `--pr`): `gh auth status` must succeed.

If pre-flight fails, report the failures and stop. Do not partially proceed.

## 4. Determine Execution Strategy

Decide whether this is a **mechanical** or **creative** operation:

- **Mechanical** (same change replicated): dependency bumps, file sync/copy,
  adding identical files, updating CI workflows, version string changes.
- **Creative** (independent work per module): lint-fix, refactor, bug fixes,
  anything where changes differ per module.

Heuristics:
- Keywords "fix", "refactor", "lint" suggest creative.
- Keywords "update", "sync", "add", "copy", "bump" suggest mechanical.

When unsure, ask the user: "Same mechanical change per module, or independent work per module?"

### Mechanical: Prototype then Replicate

1. Pick first module from list (or `--ref-module` if specified).
2. Create a feature branch from the module's default branch:
   ```
   cd $PROJECT/.companions/repo/<name>
   git checkout -b <branch-name> <default-branch>
   ```
   Use ordinary branch naming: `<category>-<short-description>` (e.g. `chore-bump-jwx-dep`).
3. Apply instructions to this module.
4. Verify (if module has `go.mod`):
   ```
   cd $PROJECT/.companions/repo/<name>
   go build ./...
   ```
   ```
   cd $PROJECT/.companions/repo/<name>
   golangci-lint run ./...
   ```
5. Record exactly what changed: files modified/added/deleted, nature of change.
6. For each remaining module:
   a. Create feature branch (same name).
   b. Replicate the change, adapting module-specific values (module name in
      import paths, go.mod module path, etc.).
   c. Verify (go build + golangci-lint if has go.mod).
   d. If verification fails, revert (`git checkout .`), delete the branch,
      record failure, continue to next module.

### Creative: Parallel Subagents

1. Spawn one Agent per module, all in a single parallel block.
2. Each agent receives:
   - Module path: `$PROJECT/.companions/repo/<name>`
   - Default branch name
   - The instructions
   - Directions to: create a feature branch, do the work, verify, commit.
3. Subagents do NOT have Skill tool access. Give them explicit instructions.
4. Wait for all agents, collect results.

## 5. Commit

For each module where changes were made and verification passed:

1. Stage relevant files:
   ```
   cd $PROJECT/.companions/repo/<name>
   git add <files>
   ```
2. Commit following standard commit message rules.

## 6. PR (only with `--pr`)

For each module where changes were committed:

1. Push the feature branch:
   ```
   cd $PROJECT/.companions/repo/<name>
   git push -u origin <branch-name>
   ```
2. Create PR:
   ```
   cd $PROJECT/.companions/repo/<name>
   gh pr create --title "<title>" --body "<body>"
   ```
   Target the module's default branch.
3. Record PR URL.

## 7. Report

Always end with a report:

```
## Companion Module Bulk Operation Report

**Operation**: <summary of instructions>
**Date**: YYYY-MM-DD
**Modules targeted**: N
**Succeeded**: X | **Skipped**: Y | **Failed**: Z

| Module | Branch | Status | PR | Notes |
|--------|--------|--------|----|-------|
| ... | ... | success/skipped/failed | URL or — | ... |

### Files Changed
- <list of files modified across modules>

### Errors (if any)
- **<module>**: <error description>
```

## Adaptation Rules

When replicating changes across modules, adapt these patterns:

| Pattern | Adaptation |
|---------|-----------|
| Module name in `go.mod` | Read actual module path from the target's `go.mod` |
| Module name in CI YAML | Package-specific test paths |
| Import paths | Adjust `jwx-go/<proto>` to `jwx-go/<target>` |
| Default branch | Use `branch` from `companions.yaml` for each module |
| Modules without `go.mod` (benchmarks) | Skip Go-specific steps (build, lint, dep update) |

## Error Handling

| Error | Response |
|-------|----------|
| Dirty working tree | STOP entirely (pre-flight) |
| `go build` fails after change | Revert, record failure, continue others |
| `golangci-lint` fails after change | Revert, record failure, continue others |
| Module not applicable (e.g. no go.mod for dep update) | Skip, report "not applicable" |
| PR creation fails | Report failure, branch still pushed |
| Git push fails | Report, do not retry, continue others |
| File already matches desired state | Report "already up to date", skip |

## Hard Rules

- NEVER commit directly to default branch — always create a feature branch.
- NEVER force-push.
- NEVER proceed on a module with dirty working tree.
- ALWAYS run pre-flight on ALL modules before modifying ANY.
- ALWAYS verify `go build ./...` and `golangci-lint run ./...` before committing (for modules with go.mod).
- ALWAYS report per-module results even on partial failure.
- ALWAYS `cd` into `$PROJECT/.companions/repo/<name>` before running ANY command (git, go, golangci-lint) for that module. NEVER use `git -C`, `--git-dir`, or `--work-tree` instead — they don't apply to non-git tools, and the shell's working directory stays in the parent jwx repo so its git context leaks through.
- NEVER use compound commands (`&&`, `||`, `;`) in Bash calls.
- PRs are OFF by default. Only push/create PRs when `--pr` is specified.
