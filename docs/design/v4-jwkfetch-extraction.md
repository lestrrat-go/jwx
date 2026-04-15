# v4: extracting HTTP JWK fetching into `jwkfetch`

## Context

v3 of `github.com/lestrrat-go/jwx` shipped HTTP-based JWK Set retrieval as part of the core `jwk` package. The package exported `jwk.Fetch`, `jwk.Fetcher`, `jwk.FetchFunc`, `jwk.HTTPClient`, `jwk.DefaultHTTPClient`, `jwk.WrapHTTPClientDefaults`, four whitelist types (`Whitelist`, `WhitelistFunc`, `InsecureWhitelist`, `BlockAllWhitelist`, `MapWhitelist`, `RegexpWhitelist`), three generated options (`WithHTTPClient`, `WithFetchWhitelist`, `WithMaxFetchBodySize`), and a `WhitelistError()` sentinel. `net/http` was imported from `jwk/fetch.go`.

v3 also had a separate companion `github.com/jwx-go/jwkcache` that provided background-refreshing JWKS caching on top of `httprc`. `jwkcache.Fetcher` wrapped `jwkcache.Cache` to adapt it to `jwk.Fetcher`. The `jwk.Fetcher` interface itself took a variadic `...jwk.FetchOption` that `jwkcache.Fetcher.Fetch` silently discarded — review finding `REV-CMP-20260414T114515Z-002` (high) flagged this as a silent-policy-bypass bug: callers who passed `jwk.WithFetchWhitelist(...)` to a jws/jwt `WithVerifyAuto` wired to a cache-backed fetcher saw their whitelist quietly ignored.

Investigating that finding surfaced a deeper layering problem. The core `jwk` package owned HTTP transport, whitelist policy, a global `jwk.Configure(...)` knobs for HTTP client and body size, and a generated option set — all of which are concerns of the HTTP client layer, not of the JWK parser. The main jwx module had a hard dependency on `net/http` (and transitively on `httprc` when callers reached for the companion). The `jwk.Fetcher` interface, which exists only so jws/jwt can be given a "somewhere to fetch keys from," was sculpted around HTTP-specific options that didn't belong in the abstract interface.

## Decision

Extract **all** HTTP JWK fetching into a single new companion, `github.com/jwx-go/jwkfetch`, and collapse `jwk.Fetcher` to a minimal options-free interface. The new companion supersedes both the v3 `jwk.Fetch` surface **and** the `jwx-go/jwkcache` companion — there is one home for HTTP JWKS retrieval in v4, not two.

### What stays in `jwk`

```go
type Fetcher interface {
    Fetch(ctx context.Context, url string) (Set, error)
}
```

That is the entire fetch surface in the core `jwk` package. No `Fetch` function, no `FetchFunc` adapter, no HTTP client or body-size options, no whitelist types, no error sentinels, no `net/http` import. Concrete implementations live exclusively in companion modules.

### What moves to `jwkfetch`

Two types, both implementing `jwk.Fetcher`:

- **`jwkfetch.Client`** — one-shot HTTP JWKS fetcher. Holds an `HTTPClient`, `Whitelist`, `MaxBodySize`, and `ParseOptions`. Constructed via `NewClient(opts ...ClientOption)`. Used for `jku`-style verification and any fetch where the URL may be attacker-controllable.
- **`jwkfetch.Cache`** — background-refreshed JWKS store backed by `httprc`. Holds an `HTTPClient`, `MaxBodySize`, `ParseOptions`, and an httprc controller. Constructed via `NewCache(ctx, *httprc.Client, opts ...CacheOption)`. Used for a small trusted set of issuer JWKS endpoints where amortizing fetch cost matters.

Both types are **closed structs** (all fields unexported). Configuration is via functional options from four interface types:

- `ClientOption` — accepted by `NewClient`
- `CacheOption` — accepted by `NewCache`
- `GlobalFetchOption` — satisfies both (shared HTTP/parse policy: `WithHTTPClient`, `WithMaxBodySize`, `WithParseOptions`)
- `RegisterOption` — accepted by `Cache.Register` for per-URL knobs (`WithWaitReady`, `WithConstantInterval`, `WithMinInterval`, `WithMaxInterval`)

`WithWhitelist` is a `ClientOption` only — `Cache` treats `Register` as the trust boundary for cached URLs, so passing `WithWhitelist(...)` to `NewCache` is a compile-time error. This is structural enforcement of the "Cache trusts what you registered" design without a foot-gun field.

### Safety defaults

`jwkfetch.NewClient()` with no `WithWhitelist` permits every URL. This is the right default for the overwhelming common case — a Client fetching a compile-time-constant or trusted-config JWKS URL — where the trust decision is already made at the call site and a whitelist would be redundant. Forcing every such call site to opt in via `WithWhitelist(InsecureWhitelist{})` would trade a minor-safety win at one call-site class for a friction cost at every call site, and would train users to reach for `InsecureWhitelist` reflexively, which is functionally equivalent to the permissive default.

For `jku`-style verification, where the URL comes from an untrusted JWS header, the caller MUST pass `WithWhitelist` with a restrictive `MapWhitelist` / `RegexpWhitelist` / `WhitelistFunc`. jwx does not prepend a default deny around the fetcher. A restrictive `Whitelist` on a Client is applied to both the initial URL and every redirect target — `Client.Fetch` wraps the `*http.Client`'s `CheckRedirect` at construction time so a hostile JWKS host cannot 302 into an off-allowlist URL.

`jws.WithVerifyAuto(nil)` and `jwt.WithVerifyAuto(nil)` are not supported — both error at jku-verification time rather than silently using any default. The variadic `...jwk.FetchOption` that v3 had on both signatures is gone. All policy is baked into the fetcher at construction time.

The silent-drop bug class from `REV-CMP-20260414T114515Z-002` (where v3's `jwkcache.Fetcher.Fetch` discarded `...jwk.FetchOption` values, letting a caller's whitelist silently no-op) is structurally impossible: there is no per-call option variadic on `jwk.Fetcher`, so there is no variadic to drop. Per-call policy lives on the `jwk.Fetcher` implementation that the caller constructed, and that implementation's behavior is entirely determined at construction time.

For `Cache`, there is no separate `Whitelist` concept. `Cache` is a cache — the set of URLs it will ever contact is exactly the set passed to `Register`, and `Fetch`/`Lookup` return an error for anything else. Passing `WithWhitelist` to `NewCache` is a compile-time error (the option type doesn't satisfy `CacheOption`), so the "Cache has its own allowlist concept you need to configure" footgun is structurally prevented.

## Why one companion instead of two

v3 had `jwkcache` separate from `jwk.Fetch`. v4 collapses both into `jwkfetch`. Reasons:

1. **Shared HTTP policy.** `jwk.Fetch` and `jwkcache.Cache` had overlapping config surfaces (`HTTPClient`, body-size cap, parse options) but expressed them differently — the former as jwk options, the latter as jwkcache `RegisterOption` values that silently ignored jwk options. One companion with one config idiom eliminates the split.
2. **One trust model.** One-shot fetch is whitelist-driven; cache is registration-driven. Having both in one module makes the boundary explicit: `Client` has a `Whitelist` field, `Cache` does not. A user who needs whitelist enforcement on cached URLs is unambiguously told to use `Client` instead.
3. **One dependency story.** A consumer pulling in jwkfetch gets everything they could possibly need for HTTP JWKS retrieval. No decision tree between "the basic one" and "the caching one."
4. **Rename over deprecation.** `jwkcache` under its v4 module path (`github.com/jwx-go/jwkcache/v4`) never had a tagged release — it lived at pre-release versions only. The rename to `jwkfetch` therefore doesn't break any tagged downstream and doesn't need a compatibility shim. v3 users see a single target for their migration.

## Non-goals

- **Not extending `jwk.Fetcher` with options.** The minimal `Fetch(ctx, url) (Set, error)` interface is load-bearing: it forces transport policy to live on the concrete type, which is where the bugs were. Re-adding a variadic would reintroduce the silent-drop bug class. jws/jwt hold a `jwk.Fetcher` via a normal interface reference; configuration is the caller's responsibility at construction time.
- **Not keeping a v3-style global `jwk.Configure(...WithHTTPClient...)`.** v4 `jwk.Configure` has only `StrictKeyUsage` left — the HTTP defaults are now a per-`Client` concern. Global state for HTTP transport was always a footgun (test isolation, pluggability, override ordering) and lint couldn't protect against it.
- **Not adding a `jwk.FetchFunc` adapter.** The original plan included one. `jwk.Fetcher` is a one-method interface; users who need a function can declare a tiny concrete type on their own. No adapter was deemed worth the API weight.
- **Not inlining `jwkfetch` into jwx proper.** Keeping it as a companion is what lets the core module stay `net/http`-free and `httprc`-free, which is the whole point of the extraction.

## Migration touchpoints

See `MIGRATION.md` Recipe 6 for the user-facing migration. The non-trivial surprises for existing code:

- `jwk.Fetch(ctx, url)` with no options becomes `jwkfetch.NewClient().Fetch(ctx, url)`. Both default to allow-all, so a trusted-URL call site migrates cleanly without adding a whitelist.
- `jws.WithVerifyAuto(nil, jwk.WithFetchWhitelist(wl))` → `jws.WithVerifyAuto(jwkfetch.NewClient(jwkfetch.WithWhitelist(wl)))`. No nil fetcher, no per-call fetch options. This is the one place v3's implicit safety is NOT carried forward: v3's `jws.WithVerifyAuto` prepended a deny-all in front of the caller's options, so a jku caller who forgot to set a whitelist got rejected URLs. v4 has no such wrapper — the whitelist has to be on the fetcher the caller built, or the fetch is permissive. Audit every jku-style call site accordingly.
- `jwk.Configure(jwk.WithHTTPClient(...))` is gone — no global HTTP client for jwk. Put your `*http.Client` on the `jwkfetch.Client` or `jwkfetch.Cache` that needs it.
- `github.com/jwx-go/jwkcache/v4` is superseded by `github.com/jwx-go/jwkfetch/v4`. Same conceptual model (httprc-backed, per-URL registration, background refresh), different module path, different construction (closed struct + functional options).

## Related

- Review finding: `REV-CMP-20260414T114515Z-002` (silent FetchOption drop in `jwkcache.Fetcher.Fetch`, high).
- Related finding NOT addressed here: `REV-CMP-20260414T114515Z-003` (medium, `Cache.Fetch` errors on unregistered URLs instead of falling back to ad-hoc fetch). Current `jwkfetch.Cache.Fetch` preserves the v3 "registered-only" semantics; adding ad-hoc fallback is a separate design.
