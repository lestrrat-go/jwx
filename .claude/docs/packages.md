<!-- Agent-consumed file. Keep terse, unambiguous, machine-parseable. -->

# Package Map

Module: `github.com/lestrrat-go/jwx/v3` — flat layout, no physical `v3/` directory.

## jwx (root)

Format detection and global JSON decoder settings.

- **GuessFormat(payload []byte) FormatKind** — heuristic detection of JWE/JWS/JWK/JWKS/JWT
- **DecoderSettings(options ...JSONOption)** — configure global JSON decoder
- Key types: `FormatKind` (InvalidFormat, UnknownFormat, JWE, JWS, JWK, JWKS, JWT)
- Files: `jwx.go`, `format.go`, `options.go`

## jwa/

Algorithm identifiers per RFC 7518. Registry pattern with thread-safe lookup.

- Algorithm types: `SignatureAlgorithm`, `KeyEncryptionAlgorithm`, `ContentEncryptionAlgorithm`, `EllipticCurveAlgorithm`, `KeyType`, `CompressionAlgorithm`
- **KeyAlgorithmFrom(v any) (KeyAlgorithm, error)** — convert string/typed algorithm to union interface
- Per-type API: `New{Type}()`, `Lookup{Type}(name) (T, bool)`, `Register{Type}()`, `Unregister{Type}()`, `{Type}s() []T`
  `Register{Type}()` is process-global; attempts to replace builtin identifiers such as `RS256` are ignored.
- Constructor functions: `ES256()`, `RS256()`, `A128GCM()`, `P256()`, `Ed25519()`, etc.
- Files: `jwa.go`, `secp2561k.go` + generated `*_gen.go`
- Imports: internal/tokens

## jwk/

JSON Web Keys per RFC 7517. Key representation, parsing, import/export, caching.

- **Configure(options ...GlobalOption)** — configure global jwk behavior (`WithStrictKeyUsage`, fetch defaults, RSA validation floors)
- **Parse(src []byte, ...ParseOption) (Set, error)** / **ParseKey(data []byte, ...ParseOption) (Key, error)** — parse JWK/JWKS
- **Fetch(ctx, url, ...FetchOption) (Set, error)** — HTTP fetch with optional whitelist, body size limit (default 10 MB via `WithMaxFetchBodySize`)
- **DefaultHTTPClient() \*http.Client** — returns a new http.Client with library defaults (30s timeout, redirect policy)
- **Import(raw any) (Key, error)** / **Export(key Key, dst any) error** — convert between Go crypto types and JWK
- **PublicKeyOf(v any) (Key, error)** / **PublicSetOf(v Set, ...PublicSetOption) (Set, error)** — extract public keys. `PublicSetOf` rejects sets containing symmetric (oct) keys by default (pass `WithAllowSymmetric(true)` for legacy pass-through) and rejects `UnsupportedKey` placeholders by default (pass `WithOmitUnsupportedKeys(true)` to drop them).
- **NewCache(ctx, client) (*Cache, error)** — auto-refreshing JWKS cache
- **AssignKeyID(key Key, ...AssignKeyIDOption) error** — compute and set kid via thumbprint
- **IsUnsupportedKey(key Key) bool** — reports whether a key is an `UnsupportedKey` placeholder retained for an unparseable JWK Set entry (opt-in via `WithStrictKeySetParsing(false)`; RFC 7517 §5). The `UnsupportedKey` interface adds `Reason() error` and is sealed (an unexported marker method means only this package's placeholder implements it); the placeholder preserves the entry's raw JSON (round-trips losslessly) and errors on all crypto/mutation ops. Default parsing stays fail-fast — the option only relaxes it.
- **Pem(v any) ([]byte, error)** — PEM encode
- Global options: `WithStrictKeyUsage(bool)`, `WithHTTPClient(HTTPClient)`, `WithMaxFetchBodySize(int64)`, `WithMinRSAModulusBits(int)`, `WithMinRSAPublicExponent(int)`, `WithMaxKeys(int)` (also accepted as a per-call `ParseOption`; caps `"keys"` array + PEM block count at 1000 by default), `WithStrictKeySetParsing(bool)` (GlobalParseOption; default true = fail-fast; false retains unparseable set entries as `UnsupportedKey` placeholders)
- Key interfaces: `Key`, `Set`, `RSAPublicKey`, `RSAPrivateKey`, `ECDSAPublicKey`, `ECDSAPrivateKey`, `OKPPublicKey`, `OKPPrivateKey`, `SymmetricKey`, `UnsupportedKey`
- Extension: `RegisterCustomField()`, `RegisterKeyParser()`, `RegisterKeyImporter()`, `RegisterKeyExporter()`
- Error sentinels: `ImportError()`, `ParseError()`, `WhitelistError()`, `ContinueError()`
- Files: `jwk.go`, `set.go`, `parser.go`, `convert.go`, `fetch.go`, `cache.go`, `interface.go`, `errors.go`, `x509.go`, `filter.go`, `rsa.go`, `ecdsa.go`, `okp.go`, `symmetric.go`, `unsupported.go`
- Sub-packages: `jwk/ecdsa` — elliptic curve registration (`RegisterCurve`, `CurveFromAlgorithm`, `AlgorithmFromCurve`); `jwk/jwkbb` — X.509/PEM encoding building blocks (`EncodeX509`, `DecodeX509`) plus a fastjson-backed `Header` (sealed) for fast field probing of JWK / JWKS bytes: `HeaderParse`, `HeaderHas`, `HeaderGetString`, `HeaderGetStringBytes`, sentinel `ErrHeaderNotFound()`. Mirrors the `jws/jwsbb` Header API; experimental.
- Imports: jwa, cert, transform, internal/{base64,json,ecutil}

## jws/

JSON Web Signatures per RFC 7515. Sign, verify, parse.

- **Sign(payload []byte, ...SignOption) ([]byte, error)** — sign payload
- **Verify(buf []byte, ...VerifyOption) ([]byte, error)** — verify and extract payload
- **VerifyCompactFast(key any, compact []byte, alg jwa.SignatureAlgorithm) ([]byte, error)** — fast-path verification
- **Parse(src []byte, ...ParseOption) (*Message, error)** — parse without verification
- **SplitCompact(src []byte) ([]byte, []byte, []byte, error)** — split compact JWS into parts
- Key types: `Message`, `Signature`, `Headers`, `KeyProvider`, `KeySink`, `Base64Encoder`, `Base64StreamEncoder`
- Options: `WithKey()`, `WithKeySet()`, `WithVerifyAuto()`, `WithJSON()`, `WithDetachedPayload()`, `WithDetachedPayloadReader()` (streaming variant; single-key verify, HMAC/RSA/ECDSA only; multi-sig JSON supported on sign)
- Global/per-call settings: `WithMaxSignatures()` (usable in both `Settings()` and `Parse()`/`ReadFile()`)
- Registration: `RegisterSigner()`, `RegisterVerifier()`, `AlgorithmsForKey()`, `RegisterAlgorithmForKeyType()`, `RegisterAlgorithmForCurve()`
- Error sentinels: `SignError()`, `VerifyError()`, `VerificationError()`, `ParseError()`
- Sub-package: `jws/jwsbb` — compact serialization, signing, verification building blocks
- Files: `jws.go`, `message.go`, `signer.go`, `verifier.go`, `streaming_detached.go`, `headers.go`, `interface.go`, `errors.go`, `options.go`, `key_provider.go`, `sign_context.go`, `verify_context.go`
- Imports: jwa, jwk, cert, internal/{base64,json,pool,tokens}

## jwe/

JSON Web Encryption per RFC 7516. Encrypt, decrypt, parse.

- **Encrypt(payload []byte, ...EncryptOption) ([]byte, error)** — encrypt payload
- **Decrypt(buf []byte, ...DecryptOption) ([]byte, error)** — decrypt message
- **Parse(buf []byte, ...ParseOption) (*Message, error)** — parse without decryption
- Key types: `Message`, `Recipient`, `Headers`, `KeyProvider`, `KeyEncrypter`, `KeyDecrypter`
- Options: `WithKey()`, `WithKeySet()`, `WithContentEncryption()`, `WithCompress()`, `WithJSON()`, `WithProtectedHeaders()`
- Global/per-call settings: `WithMaxPBES2Count()`, `WithMinPBES2Count()`, `WithMaxDecompressBufferSize()`, `WithMaxRecipients()` (usable in both `Settings()` and `Decrypt()`); `WithCBCBufferSize()`, `WithDisabledKeyAlgorithms(...jwa.KeyEncryptionAlgorithm)` (global only; the latter blocks listed key algorithms in both Encrypt and Decrypt)
- Error sentinels: `EncryptError()`, `DecryptError()`, `RecipientError()`, `ParseError()`
- Internal subpackages: `jwe/internal/{aescbc,cipher,concatkdf,content_crypt,keygen}`, `jwe/jwebb`
- Files: `jwe.go`, `message.go`, `interface.go`, `headers.go`, `errors.go`, `options.go`, `key_provider.go`, `compress.go`, `filter.go`
- Imports: jwa, jwk, cert, transform, internal/{base64,json,pool,tokens}

## jwt/

JSON Web Tokens per RFC 7519. Parse, sign, validate.

- **Parse(s []byte, ...ParseOption) (Token, error)** — parse and optionally verify JWT
- **ParseInsecure(s []byte, ...ParseOption) (Token, error)** — parse without verification/validation
- **Sign(t Token, ...SignOption) ([]byte, error)** — sign token to compact serialization
- **Validate(t Token, ...ValidateOption) error** — validate claims (exp, nbf, iat, iss, aud, etc.)
- **New() Token** — create empty token
- HTTP helpers: `ParseCookie()`, `ParseHeader()`, `ParseForm()`, `ParseRequest()`
- Validator factories: `IsExpirationValid()`, `IsIssuedAtValid()`, `IsNbfValid()`, `IsRequired()`, `ClaimValueIs()`, `ClaimContainsString()`
- Key types: `Token` (interface), `Validator`, `ValidatorFunc`, `Clock`, `ClockFunc`, `Serializer`, `TokenFilter`
- Token options: `FlattenAudience` per-token option
- Error sentinels: `TokenExpiredError()`, `TokenNotYetValidError()`, `InvalidIssuerError()`, `InvalidAudienceError()`, `ValidateError()`, `ParseError()`
- Files: `jwt.go`, `validate.go`, `serialize.go`, `http.go`, `filter.go`, `errors.go`, `options.go`, `fastpath.go`, `token_options.go`
- Imports: jwa, jws, jwe, jwk, transform, internal/json

## jwt/openid/

OpenID Connect ID Token per OIDC Core 1.0. Extends jwt.Token with OIDC claims.

- **New() Token** — create OpenID token with OIDC claim accessors
- OIDC claims: Address, Birthdate, Email, EmailVerified, FamilyName, Gender, GivenName, Locale, MiddleName, Name, Nickname, PhoneNumber, PhoneNumberVerified, Picture, PreferredUsername, Profile, UpdatedAt, Website, Zoneinfo
- Key types: `Token` (extends jwt.Token), `AddressClaim`, `BirthdateClaim`
- Files: `openid.go`, `address.go`, `birthdate.go`, `filter.go`, `interface.go`
- Imports: jwt, internal/{json,tokens,pool}

## transform/

Generic filtering utilities using Go generics.

- **Apply[T Filterable[T]](object T, logic FilterLogic) (T, error)** — include matching fields
- **Reject[T Filterable[T]](object T, logic FilterLogic) (T, error)** — exclude matching fields
- **AsMap(m Mappable, dst map[string]any) error** — convert to map; values are whatever `Get()` returns, so mutable values may be live aliases of source object (EXPERIMENTAL)
- Key types: `FilterLogic`, `FilterLogicFunc`, `Filterable[T]`, `NameBasedFilter[T]`, `Mappable`
- Files: `filter.go`, `map.go`
- Imports: (external only: blackmagic)

## cert/

X.509 certificate chain support for `x5c` JWK fields.

- **Settings(options ...GlobalOption)** — configure global certificate validation limits
- **Create(rand, template, parent, pub, priv) ([]byte, error)** — create base64-encoded certificate
- **Parse(src []byte) (*x509.Certificate, error)** — decode base64+DER certificate
- **EncodeBase64(der []byte) ([]byte, error)** — encode DER to base64
- Global options: `WithMaxChainLength(int)`, `WithMaxCertificateSize(int64)`
- Key types: `Chain` (Get, Len, Add, MarshalJSON, UnmarshalJSON), `GlobalOption`
- Files: `cert.go`, `chain.go`, `options.go`, `settings.go`
- Imports: internal/{base64, tokens}

## internal/

Shared utilities. Not public API.

| Subpackage | Purpose |
|------------|---------|
| `base64` | Pluggable base64 encoding (RawURL, URL, RawStd, Std) |
| `json` | Pluggable JSON (stdlib or goccy/go-json), custom field registry |
| `ecutil` | Elliptic curve point buffer management |
| `keyconv` | Key type conversions between jwk.Key and Go crypto types |
| `jose` | Test helper for jose CLI integration |
| `jwxtest` | Test key generation helpers (RSA, ECDSA, Ed25519, symmetric) |
| `tokens` | String constants for algorithm names and separators |
| `pool` | Generic object pool (`Pool[T]`, `SlicePool[T]`) |
