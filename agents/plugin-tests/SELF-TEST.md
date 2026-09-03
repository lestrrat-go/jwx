# Self-test: `jwx-dev-v4:guide` documentation retrieval

This document verifies that the `jwx-dev-v4:guide` skill enables an answering agent to navigate the **scattered** documentation surface — jwx core docs, the examples repo, companion-module docs, and the Go module cache — and synthesize them into correct, compiling jwx code.

The skill is intended for end-users who **do not have any of these repos locally checked out**. It must direct agents to the right source for each question and let them combine sources when one source alone is insufficient.

## Documentation sources the skill points at

A passing test confirms agents can effectively use:

1. **jwx core narrative docs** — `https://github.com/lestrrat-go/jwx/blob/develop/v4/docs/*.md`
2. **Go module cache** — `$(go env GOMODCACHE)/github.com/lestrrat-go/jwx/v4@<ver>/` (and the same for any companion module the user has imported)
3. **pkg.go.dev** — `https://pkg.go.dev/github.com/lestrrat-go/jwx/v4/...` and `https://pkg.go.dev/github.com/jwx-go/<companion>/v4`
4. **Examples repo (topical index)** — `https://github.com/jwx-go/examples/blob/develop/v4/README.md` and its linked `*_example_test.go` files
5. **Companion-module own READMEs** — `https://github.com/jwx-go/<companion>` (repo root README)

## Prerequisites

- The latest source `agents/plugin/skills/guide/SKILL.md` has been installed and cached. Recipe:
  ```
  /plugin uninstall jwx-dev-v4@jwx-v4
  /plugin install jwx-dev-v4@jwx-v4
  /reload-plugins
  ```
- Verify cache matches source:
  ```
  diff -q agents/plugin/skills/guide/SKILL.md \
    ~/.claude/plugins/cache/jwx-v4/jwx-dev-v4/<version>/skills/guide/SKILL.md
  ```
  No output = match.

## Setup: fresh-context test session

Do **not** rely on the current Claude session that authored the skill. Either:

- Launch a fresh `claude` session in a directory that has **no jwx checkout and no prior context**, or
- Dispatch an `Agent` subagent with `subagent_type: general-purpose` and a self-contained prompt — the subagent inherits tools but not conversation history.

The test agent must have at least: `Skill`, `WebFetch`, `Read`, `Write`, `Edit`, `Bash`. It must not be told the answers; it must be told only the user's question and instructed to use the `jwx-dev-v4:guide` skill.

### Required: build a real Go program

For every case, the test agent must **construct a runnable Go program from scratch in a temporary directory** and verify it compiles. This is the load-bearing part of the test — text-only answers are easy to bluff; a `go build` either succeeds or doesn't.

Recipe the agent should follow:

```bash
WORKDIR="$(mktemp -d)"
cd "$WORKDIR"
go mod init example.com/jwx-self-test/case-N
# write main.go with all required imports + func main() so it links
# encoding/json/v2 is behind GOEXPERIMENT=jsonv2 on Go 1.26 and in the standard
# library from Go 1.27 on. Probe the toolchain instead of hardcoding a version.
if ! GOEXPERIMENT= go list encoding/json/v2 >/dev/null 2>&1; then
	export GOEXPERIMENT=jsonv2
fi
go mod tidy
go build ./...
```

The test passes a case only when `go build` exits 0. A successful build proves:

- Every imported package path is real.
- Every `package.Symbol` used exists with a compatible signature.
- Generic call sites have the correct type parameters.

If `go build` fails, the agent iterates: read the error, consult docs again, fix. Up to three fix attempts per case. Report the trajectory.

### Network policy

The test agent has network access via `WebFetch` and `go mod tidy`. It must not clone any jwx-related repo (jwx core or companions). For cases that exercise the offline path (Case 5), deny network access entirely after the initial `go mod tidy` and verify the agent recovers via the Go module cache for **both jwx core and the relevant companion** when applicable.

## Test cases

Cases are split into two families: **single-source** cases (one doc carries the answer) and **multi-source / index-navigation** cases (the answer requires combining or navigating across sources).

### Family A — Single-source retrieval

#### Case 1 — Custom claim validator (target: `docs/01-jwt.md`)

**User question**: "How do I write a custom validator that checks the `scope` claim contains `read:users` and rejects the token otherwise?"

**Why this requires docs**: SKILL.md doesn't cover `jwt.Validator`/`jwt.WithValidator`. `docs/01-jwt.md` "Use a custom validator" is the source.

**Pass criteria**:
- `go build` passes.
- Code uses `jwt.WithValidator` + `jwt.Validator` (or `jwt.ValidatorFunc`).
- Validator returns a plain `error` (not `jwt.NewValidationError`, which does not exist).
- No fabricated APIs.

#### Case 2 — Per-recipient JWE headers (target: `docs/03-jwe.md`)

**User question**: "Encrypt a single JWE for two recipients, each with a different `kid` in its per-recipient header. Each recipient must independently decrypt the message."

**Why this requires docs**: SKILL.md only shows single-recipient `jwe.Encrypt`. Multi-recipient assembly + `jwe.WithJSON` + `jwe.WithPerRecipientHeaders` live in `docs/03-jwe.md`.

**Pass criteria**:
- `go build` passes.
- Code uses `jwe.WithJSON()`, `jwe.WithPerRecipientHeaders`, two `jwe.WithKey(...)` calls.
- Both recipients decrypt successfully (if the test agent runs the program).

#### Case 3 — Framework integration with Echo (target: `docs/21-frameworks.md`)

**User question**: "Echo middleware that pulls a bearer JWT from `Authorization: Bearer …`, verifies against a JWKS endpoint, stashes the verified token on the request context."

**Why this requires docs**: SKILL.md mentions `docs/21-frameworks.md` exists but contains no Echo-specific guidance.

**Pass criteria**:
- `go build` passes (Echo + jwkfetch resolve).
- Middleware calls `jwt.Parse` with `jwt.WithKeySet` from a `jwkfetch.Cache`.
- Token stored on `echo.Context` for handler use.

### Family B — Multi-source / index navigation

#### Case 4 — ML-DSA signing (target: jwx's `docs/10-extensions.md` **plus** the mldsa companion's own godoc/README)

**User question**: "Generate a fresh ML-DSA-65 keypair, sign a payload, verify the signature. Show me a complete program."

**Why this exercises companion navigation**: jwx's `docs/10-extensions.md` introduces the companion, but the algorithm constructor (`MLDSA65()`) and raw key generation are exposed by the companion module, not jwx core. The agent must consult the companion's own source.

**Pass criteria**:
- `Companion docs fetched` in the report must include at least one mldsa source (`pkg.go.dev/github.com/jwx-go/mldsa/v4` or the companion repo's README).
- `go build` passes.
- Side-effect import of `github.com/jwx-go/mldsa/v4`.
- `jws.Sign` + `jwxmldsa.MLDSA65()` (or the actual exported symbol).
- Verification with the public key succeeds.

#### Case 5 — Module-cache fallback (offline)

**User question**: Same as Case 1.

**Constraint**: After the agent's initial `go mod tidy` populates the module cache, deny `WebFetch`. The agent must complete the task using only locally cached sources.

**Why this exercises a separate path**: forces use of `$(go env GOMODCACHE)/github.com/lestrrat-go/jwx/v4@<ver>/docs/01-jwt.md` and equivalent companion paths.

**Pass criteria**:
- Agent runs `go list -m -f '{{.Version}}' github.com/lestrrat-go/jwx/v4` (and similar for any companion) + `go env GOMODCACHE` to resolve paths.
- `go build` passes.
- All sources fetched are local paths under `GOMODCACHE`, not URLs.

#### Case 6 — Examples-README navigation (target: examples repo's `README.md` as topical index)

**User question**: "Thread a `context.Context` into a custom JWT validator so the validator can read a request-scoped value."

**Why this exercises the examples-README path**: jwx core `docs/01-jwt.md` covers custom validators but doesn't focus on context plumbing. The examples repo has `jwt_with_context_example_test.go` and `README.md` lists it under "JWT — Validating — Pass request context."

**Pass criteria**:
- Agent fetches `examples/README.md` *and* the linked `jwt_with_context_example_test.go`.
- `go build` passes.
- Code uses `jwt.WithContext(ctx)` + `jwt.WithValidator` with a validator whose first arg receives the context.

#### Case 7 — Companion-module own docs (target: jwkfetch companion's godoc/README)

**User question**: "I'm using `jwkfetch.Cache` in a long-lived server. How do I shut it down cleanly on app exit so the background refresh goroutines stop?"

**Why this exercises a companion-only path**: jwx core `docs/04-jwk.md` introduces `jwkfetch.Cache` but the lifecycle (Shutdown contract, goroutine cleanup) is documented in the companion's own godoc.

**Pass criteria**:
- `Companion docs fetched` in the report must include at least one jwkfetch source (`pkg.go.dev/github.com/jwx-go/jwkfetch/v4` or the companion repo's README). A non-empty list there is the trajectory evidence — the test reviewer cross-checks this against the listed sources.
- `go build` passes.
- Code calls the actual shutdown API the companion exposes (whatever its current name — `Shutdown`, `Close`, etc.).

#### Case 8 — Multi-source synthesis (target: 2+ *kinds* of source)

**User question**: "Verify a JWT against an Auth0 JWKS endpoint with a 30-minute refresh interval and reject the token if its `azp` claim is not equal to my client ID. Show me a complete program; client ID and JWKS URL come from env vars."

**Why this requires synthesis**:
- `jwkfetch.Cache` config (interval, registration) → jwkfetch companion docs or `docs/04-jwk.md`.
- Custom validator for `azp` → `docs/01-jwt.md` or examples repo.
- These can't be answered from a single source.

**Pass criteria**:
- Agent fetches sources from **at least two distinct kinds** of the five enumerated source types (e.g., one jwx core doc *and* one companion source; or one example file *and* one companion source). Two jwx core docs alone do NOT satisfy this — the test verifies cross-surface navigation, not in-repo navigation.
- `go build` passes.
- Code wires `jwkfetch.NewCache` with appropriate refresh options *and* a `jwt.WithValidator` for `azp`.

#### Case 9 — Nested JWS+JWE (target: `docs/01-jwt.md` "Serialize using JWE and JWS" + `docs/03-jwe.md`)

**User question**: "Produce a JWT that is first signed with RS256, then encrypted to a recipient with RSA-OAEP-256 + A256GCM. The recipient must decrypt and then verify it. Show both sides end to end."

**Why this requires synthesis**: nested-serialization is a JWT concept (`jwt.NewSerializer().Sign(...).Encrypt(...)`) that uses both JWS and JWE primitives. Neither `docs/01-jwt.md` alone nor `docs/03-jwe.md` alone is sufficient — the agent must combine the JWT-level serializer pattern with JWE algorithm/content-encryption knowledge.

**Pass criteria**:
- Agent fetches `docs/01-jwt.md` *and* `docs/03-jwe.md` (or their module-cache equivalents).
- `go build` passes.
- Sign side uses `jwt.NewSerializer().Sign(...).Encrypt(...).Serialize(tok)` (or the actual current API).
- Receive side decrypts the JWE envelope first, then calls `jwt.Parse` on the inner JWS payload.
- Roundtrip recovers the original token's claims.

## Negative cases (the skill should NOT need to fetch)

Cases the SKILL.md alone covers. Each negative case must also produce a code sample that **builds** — these are real questions an end user might ask, and the skill is responsible for them too. Fetching anyway isn't a failure but signals the skill body is unclear.

- "How do I verify an RS256 JWT?" — Verifying-a-JWT section.
- "Why doesn't `jwk.Import(raw)` compile?" — Critical Rules item 8.
- "How do I parse a JWK into a concrete type like `jwk.RSAPublicKey`?" — Critical Rules item 9.
- "Where do I import jwkfetch from?" — JWKS endpoint section.

## Reporting

For each case, record:

| Field | Value |
|-------|-------|
| Case | 1–9 |
| Skill invoked | yes / no |
| jwx core docs fetched | list of `docs/*.md` URLs or module-cache paths |
| Examples README fetched | yes / no |
| Example files fetched | list of `*_example_test.go` files |
| Companion docs fetched | list of pkg.go.dev/jwx-go/* or companion README URLs |
| Sources synthesized | integer count of distinct sources informing the final code |
| Build attempts | integer (1–3) |
| Build result | pass / fail |
| Fabricated APIs in final code | list (empty if clean) |
| Uncertainties flagged by the agent | list |

The skill passes when:

- **All Family A cases (1–3) build green**, with code grounded in the targeted single source.
- **Case 4 builds green AND `Companion docs fetched` lists an mldsa source.**
- **Case 5 builds green using only local cache paths** (no URLs fetched after the network cut-off).
- **Case 6 builds green AND the trajectory hit the examples README + the specific example file.**
- **Case 7 builds green AND `Companion docs fetched` lists a jwkfetch source.**
- **Case 8 builds green AND sources span at least two of the five enumerated source kinds** (jwx core docs / module cache / pkg.go.dev / examples / companion READMEs).
- **Case 9 builds green AND the trajectory hit both `docs/01-jwt.md` and `docs/03-jwe.md`** (or their module-cache equivalents).
- **Every negative case builds green from SKILL.md content alone**, with no fabricated APIs in the final code.

## When to re-run

- After any non-trivial edit to `SKILL.md`.
- After changes to jwx core `docs/*.md` that target one of the cases.
- After changes to the examples repo README (the topical index) or the addition of new example files referenced by a case.
- After changes to a companion module's public API that a case depends on.
- Whenever a user reports the skill steering wrong on a doc-backed question.
