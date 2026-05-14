# Cutting a Release

How to release a new version on a `develop/v*` → `v*` line (e.g. v3.1.0).
Assumes all code and changelog entries are already on `develop/v*`; this
doc covers only the tag-cut steps.

File note: `Changes` (no extension) is the per-version changelog with
`UNRELEASED` markers and release dates — this is what you edit.
`Changes-v*.md` documents cross-major breaking changes (v2→v3, v3→v4)
and is **not** touched during routine releases.

Release cuts happen directly on `develop/v*` — no feature branch, no
PR. This is the one exception to the usual worktree/PR workflow.

1. In `Changes`, find the `vX.Y.Z UNRELEASED` header for the version
   being cut and replace `UNRELEASED` with today's date (match the date
   style of prior entries in the same file). Leave other `UNRELEASED`
   sections alone.

2. Commit to `develop/vX` directly:

   ```bash
   git checkout develop/vX
   git pull --ff-only
   git add Changes
   git commit -m "release vX.Y.Z"
   git push origin develop/vX
   ```

3. Fast-forward `vX` to match `develop/vX`:

   ```bash
   git checkout vX
   git pull --ff-only
   git merge --ff-only develop/vX
   git push origin vX
   ```

   If the fast-forward fails, stop and investigate — `vX` should never
   have commits that aren't on `develop/vX`.

4. Tag the `vX` tip and push the tag:

   ```bash
   git tag vX.Y.Z
   git push origin vX.Y.Z
   ```

   The tag is bare semver (`v3.1.0`), not a path-prefixed submodule tag.
   Submodule tags (`cmd/jwx/vX.Y.Z`, `ed448/vX.Y.Z`, etc.) are cut
   separately when those modules release — see `companions.md` and
   memory for the nested-submodule rules.

5. Verify the tag appears under GitHub Releases, and
   `go list -m github.com/lestrrat-go/jwx/vX@vX.Y.Z` resolves.

## Picking the version number

- Patch bump (`vX.Y.Z+1`) for bug fixes and internal changes with no API
  additions.
- Minor bump (`vX.Y+1.0`) for new exported API or deliberate behavior
  changes (even source-compatible ones — see the v3.1.0 `jwk.PublicSetOf`
  bump as an example).
- Major bumps happen on a new `develop/vN+1` branch, not here.
