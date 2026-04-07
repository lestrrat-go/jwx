# Refactor genoptions and genreadfile

## genoptions (293 lines)

### Current State

Already well-structured with clean separation:
- `_main()` (lines 83-130): reads YAML, normalizes defaults, sorts, delegates
- `genOptions()` (lines 132-248): generates option interfaces, ident types, `With*` functions
- `genOptionTests()` (lines 250-293): generates ident string tests
- `writeComment()` (lines 31-58): formats multi-line doc comments

### Issues

1. **`WithCompact` → `WithSerialization` special case** (lines 207-209, 277-279): hardcoded name override for a single option. This should be in the YAML config.
2. **Hardcoded import list** (lines 141-149): always imports jwa, jwe, jwk, jws, jwt, option — relies on goimports pruning unused imports. Works, but fragile.
3. **`writeComment` is useful elsewhere**: other generators could use this for formatting multi-line YAML comments into Go doc comments.

### Proposed Changes

**Move `WithCompact` override to config**: Add an `ident_name` field to `options.yaml`:

```yaml
options:
  - ident: Compact
    option_name: WithCompact
    ident_name: WithSerialization  # used for ident.String() instead of option_name
    constant_value: fmtCompact
    interface: SerializeOption
```

This eliminates the hardcoded check `if option.OptionName == "WithCompact"`.

**Move `writeComment` to `internal/jwxcodegen/`**: This is a general-purpose utility for formatting YAML comments as Go doc comments. Other generators that add comment support could use it.

**No other changes needed.** The function sizes are appropriate and the logic is clear.

## genreadfile (81 lines)

### Current State

The simplest generator. Hardcoded definitions for 4 packages (jwk, jws, jwe, jwt). Each generates a `ParseFS` function that opens a file via `fs.FS` and delegates to `ParseReader`.

```go
type definition struct {
    Filename, Package, ReturnType string
}
```

### Issues

Minimal. The only concern is that the definitions are hardcoded in Go rather than in config, but with only 4 entries that rarely change, this is pragmatic.

### Proposed Changes

**No changes.** At 81 lines with clear, correct logic, refactoring this tool would be over-engineering. If a fifth package needs `ParseFS` in the future, adding one more struct literal to the slice is trivial.

The only shared helper this tool could benefit from is the `CodeFormatError` handling pattern (check error, print source, return wrapped error), which appears in every generator. If `internal/jwxcodegen/` provides a `WriteFileOrDump(o, filename)` helper, genreadfile could use it to save 4 lines. Not worth a separate change.
