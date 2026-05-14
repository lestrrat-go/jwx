# Companion Template Action Sync

Pull newest GitHub Actions versions from companion repos back into
`.companions/templates/`. Dependabot updates each companion repo's rendered
workflows directly, but templates aren't scanned (see `companions.md`) — this
workflow reverse-syncs those bumps so the next `/jwx-companion-bulk sync`
doesn't regress them.

## When to run

- User asks to bump template actions / "sync templates with dependabot"
- Periodically, when template actions feel stale

## Procedure

1. **Sync every companion clone** under `.companions/repo/<name>/` to its
   origin default branch (fast-forward only). Every clone — this is a
   pre-read rule from memory.

2. **Scan `uses:` lines** across all companion workflow files:

   ```
   Grep pattern: uses:\s*\S+/\S+@
   path: .companions/repo
   glob: **/.github/**/*.yml
   ```

   Output goes to `.tmp/` if large.

3. **Pick newest version per action**, across all companion usages (ignore
   benchmarks' loose `@vN` tags — they're a different pin style). Tie-break by
   the version comment after `#`. Apply the single newest version everywhere.

4. **Diff against templates** in `.companions/templates/*.yml`. Edit templates
   so every `uses: owner/repo@<sha> # <ver>` matches the newest observed
   version (both SHA and comment).

5. **Worktree + PR** against `develop/v4`:
   - branch: `chore-bump-companion-template-actions`
   - commit: `bump <action> to <ver> in companion templates`
   - PR body: bullet list of file + action + old→new version

## Notes

- Only reverse-sync versions *observed in companions*. Don't query the GitHub
  API for newer releases — that's dependabot's job in the companion repos.
- If no companion has been bumped past the template yet, there's nothing to
  do.
- The `benchmarks` companion uses loose `@v6`/`@v9` tags for ci.yml/lint.yml
  (separate template variants scoped via `skip:`/`only:` in
  `.companions/templates.yaml`). Skip those when picking the newest pinned
  SHA.
