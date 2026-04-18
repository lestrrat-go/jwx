<!-- Agent-consumed file. Keep terse, unambiguous, machine-parseable. -->

# Package Map

Module: `github.com/lestrrat-go/jwx/v4` — flat layout, no physical `v3/` directory.

## jwx (root)

Format detection and process-global settings (JSON decoder + base64 backend).

- **GuessFormat(payload []byte) FormatKind** — heuristic detection of JWE/JWS/JWK/JWKS/JWT
- **Settings(options ...GlobalOption)** — configure global settings (JSON, base64)
- **WithUseNumber(v bool) GlobalOption** — decode JSON numbers as `json.Number` instead of `float64`
- **WithBase64Encoder(v Base64Encoder) GlobalOption** — replace the process-global base64 encoder (default: `encoding/base64.RawURLEncoding`)
- **WithBase64Decoder(v Base64Decoder) GlobalOption** — replace the process-global base64 decoder (default: variant-detecting decoder)
- Key types: `FormatKind` (InvalidFormat, UnknownFormat, JWE, JWS, JWK, JWKS, JWT), `GlobalOption`, `Base64Encoder` (alias of `internal/base64.Encoder`), `Base64Decoder` (alias of `internal/base64.Decoder`)
- Files: `jwx.go`, `format.go`, `options.go`, `base64.go`

## jwa/

Algorithm identifiers per RFC 7518. Registry pattern with thread-safe lookup.

- Algorithm types: `SignatureAlgorithm`, `KeyEncryptionAlgorithm`, `ContentEncryptionAlgorithm`, `EllipticCurveAlgorithm`, `KeyType`, `CompressionAlgorithm`
- **KeyAlgorithmFrom(v any) (KeyAlgorithm, error)** — convert string/typed algorithm to union interface
- Per-type API: `New{Type}()`, `Lookup{Type}(name) (T, bool)`, `Register{Type}()`, `Unregister{Type}()`, `{Type}s() []T`
  `Register{Type}()` is process-global; attempts to replace builtin identifiers such as `RS256` return an error.
- Constructor functions: `ES256()`, `RS256()`, `A128GCM()`, `P256()`, `Ed25519()`, etc.
- Files: `jwa.go` + generated `*_gen.go`
- Imports: internal/tokens

## jwk/

JSON Web Keys per RFC 7517. Key representation, parsing, import/export, caching.

- **Settings(options ...GlobalOption)** — configure global jwk behavior (`WithStrictKeyUsage`, RSA validation floors)
- **Parse(src []byte, ...ParseOption) (Set, error)** / **ParseKey(data []byte, ...ParseOption) (Key, error)** / **ParseKeyAs[T Key](data []byte, ...ParseOption) (T, error)** — parse JWK/JWKS; `ParseKeyAs` returns [`KeyTypeMismatchError`] on generic-type mismatch
- **Fetch(ctx, url, ...FetchOption) (Set, error)** — HTTP fetch with optional whitelist, body size limit (default 10 MB via `WithMaxFetchBodySize`)
- **DefaultHTTPClient() \*http.Client** — returns a new http.Client with library defaults (30s timeout, redirect policy)
- **Import[T Key](raw any) (T, error)** / **Export[T any](key Key) (T, error)** / **ExportAll[T any](set Set) ([]T, error)** — convert between Go crypto types and JWK (generic). `ExportAll` exports every key in a `Set`, preserving order; `T = any` handles heterogeneous sets.
- **PublicKeyOf(v any) (Key, error)** / **PublicSetOf(v Set, ...PublicSetOption) (Set, error)** — extract public keys. `PublicSetOf` rejects sets containing symmetric (oct) keys by default; pass `WithAllowSymmetric(true)` for legacy pass-through.
- **AssignKeyID(key Key, ...AssignKeyIDOption) error** — compute and set kid via thumbprint
- PEM output moved to `jwkbb.EncodePEM(keys ...any)`; unwrap via `jwk.Export[any]` / `jwk.ExportAll[any]` first
- Global options: `WithStrictKeyUsage(bool)`, `WithMinRSAModulusBits(int)`, `WithMinRSAPublicExponent(int)`
- JWKS caching moved to `github.com/jwx-go/jwkcache` — see [Extension Modules](../../docs/10-extensions.md)
- Key interfaces: `Key`, `Set`, `RSAPublicKey`, `RSAPrivateKey`, `ECDSAPublicKey`, `ECDSAPrivateKey`, `OKPPublicKey`, `OKPPrivateKey`, `SymmetricKey`, `AKPPublicKey`, `AKPPrivateKey` (post-quantum, used by mldsa/mlkem extensions)
- Extension: `RegisterCustomField[T]()`, `RegisterCustomDecoder[T]()`, `RegisterKeyParser()`, `RegisterKeyImporter()`, `RegisterKeyExporter()`
- Error sentinels: `ImportError()`, `ParseError()`, `WhitelistError()`, `ContinueError()`
- Files: `jwk.go`, `set.go`, `parser.go`, `convert.go`, `fetch.go`, `interface.go`, `errors.go`, `x509.go`, `filter.go`, `rsa.go`, `ecdsa.go`, `okp.go`, `symmetric.go`, `akp.go`, `accessors.go`, `io.go`
- Sub-packages: `jwk/ecdsa` — elliptic curve registration (`RegisterCurve(alg, curve, PointValidator)`, `CurveFromAlgorithm`, `AlgorithmFromCurve`, `ValidatorFromCurve`, `PointValidator` interface, `PointValidatorFunc` adapter); `jwk/jwkbb` — X.509/PEM encoding building blocks. Block-type-keyed decoder registry (`X509Decoder[T]` / `X509DecodeFunc[T]` / `RegisterX509Decoder[T](blockType, d) error` / `UnregisterX509Decoder(blockType)`) with `DecodeX509(block *pem.Block) (any, error)` as the dispatch entry point. Type-keyed encoder registry (`X509Encoder[T]` / `X509EncodeFunc[T]` / `RegisterX509Encoder[T](e) error` / `UnregisterX509Encoder[T]()`) with `EncodePEM(keys ...any) ([]byte, error)` as the dispatch entry point — dispatches each key by its runtime Go type and concatenates PEM blocks. Block type constants: `PrivateKeyBlockType`, `PublicKeyBlockType`, `ECPrivateKeyBlockType`, `RSAPublicKeyBlockType`, `RSAPrivateKeyBlockType`, `CertificateBlockType`. Decode from `jwk.ParseKey` with `jwk.WithX509(true)`. `jwk/jwkunsafe` — low-level key constructors (`NewKey`, `NewPublicKey`) for extension modules
- Imports: jwa, cert, transform, internal/{base64,json,ecutil}

## jws/

JSON Web Signatures per RFC 7515. Sign, verify, parse.

- **Sign(payload []byte, ...SignOption) ([]byte, error)** — sign payload
- **Verify(buf []byte, ...VerifyOption) ([]byte, error)** — verify and extract payload
- **VerifyCompactFast(key any, compact []byte, alg jwa.SignatureAlgorithm) ([]byte, error)** — fast-path verification
- **Parse(src []byte, ...ParseOption) (*Message, error)** — parse without verification
- **SplitCompact(src []byte) ([]byte, []byte, []byte, error)** — split compact JWS into parts
- Key types: `Message`, `Signature`, `Headers`, `KeyProvider`, `KeySink`
- Options: `WithKey()`, `WithKeySet()`, `WithVerifyAuto()`, `WithJSON()`, `WithDetachedPayload()`
- Global/per-call settings: `WithMaxParseInputSize()` (usable in both `Settings()` and `ParseReader()`/`ReadFile()`); `WithMaxSignatures()` (usable in both `Settings()` and `Parse()`/`ReadFile()`)
- Registration: `RegisterSigner()`, `RegisterVerifier()`, `AlgorithmsForKey()`, `RegisterAlgorithmForKeyType()`, `RegisterAlgorithmForCurve()`
- Error sentinels: `SignError()`, `VerifyError()`, `VerificationError()`, `ParseError()`
- Sub-package: `jws/jwsbb` — compact serialization, signing, verification building blocks
- Files: `jws.go`, `message.go`, `signer.go`, `verifier.go`, `headers.go`, `interface.go`, `errors.go`, `options.go`, `key_provider.go`, `sign_context.go`, `verify_context.go`
- Imports: jwa, jwk, cert, internal/{base64,json,jwxio,pool,tokens}

## jwe/

JSON Web Encryption per RFC 7516. Encrypt, decrypt, parse.

- **Encrypt(payload []byte, ...EncryptOption) ([]byte, error)** — encrypt payload
- **EncryptStatic(payload, cek []byte, ...EncryptOption) ([]byte, error)** — encrypt with caller-supplied content encryption key
- **Decrypt(buf []byte, ...DecryptOption) ([]byte, error)** — decrypt message
- **Parse(buf []byte, ...ParseOption) (*Message, error)** — parse without decryption
- **Settings(options ...GlobalOption)** — configure global jwe settings
- Key types: `Message`, `Recipient`, `Headers`, `KeyProvider`, `KeyEncrypter`, `KeyDecrypter`
- Options: `WithKey()`, `WithKeySet()`, `WithContentEncryption()`, `WithCompress()`, `WithJSON()`, `WithProtectedHeaders()`
- Global/per-call settings: `WithMaxPBES2Count()`, `WithMinPBES2Count()`, `WithMaxDecompressBufferSize()`, `WithMaxRecipients()` (usable in both `Settings()` and `Decrypt()`); `WithMaxParseInputSize()` (usable in both `Settings()` and `ParseReader()`/`ReadFile()`); `WithCBCBufferSize()` (global only)
- Error sentinels: `EncryptError()`, `DecryptError()`, `HPKEError()`, `RecipientError()`, `ParseError()`
- Internal subpackages: `jwe/internal/{aescbc,cipher,concatkdf,content_crypt,keygen}`, `jwe/jwebb` — building blocks including HPKE extension interfaces (`HPKEKeyEncrypter`, `HPKEKeyDecrypter`), custom HPKE encrypt/decrypt bridges (`KeyEncryptHPKECustom`, `KeyDecryptHPKECustom`), and dynamic algorithm registration (`RegisterHPKEAlgorithm`)
- Files: `jwe.go`, `message.go`, `interface.go`, `headers.go`, `errors.go`, `options.go`, `key_provider.go`, `compress.go`, `filter.go`
- Imports: jwa, jwk, cert, transform, internal/{base64,json,pool,tokens}

## jwt/

JSON Web Tokens per RFC 7519. Parse, sign, validate.

- **Parse(s []byte, ...ParseOption) (Token, error)** — parse and optionally verify JWT
- **ParseInsecure(s []byte, ...ParseOption) (Token, error)** — parse without verification/validation
- **Sign(t Token, ...SignOption) ([]byte, error)** — sign token to compact serialization
- **Validate(t Token, ...ValidateOption) error** — validate claims (exp, nbf, iat, iss, aud, etc.)
- **Equal(t1, t2 Token) bool** — deep-compare two tokens
- **New() Token** / **NewBuilder() *Builder** — create empty token or use fluent builder
- HTTP helpers: `ParseCookie()`, `ParseHeader()`, `ParseForm()`, `ParseRequest()`
- Validator factories: `IsExpirationValid()`, `IsIssuedAtValid()`, `IsNbfValid()`, `IsRequired()`, `ClaimValueIs()`, `ClaimContainsString()`
- Key types: `Token` (interface), `Validator`, `ValidatorFunc`, `Clock`, `ClockFunc`, `Serializer`, `TokenFilter`
- Token options: `FlattenAudience` per-token option
- Global/per-call settings: `WithMaxParseInputSize()` (usable in both `Settings()` and `ParseReader()`/`ReadFile()`)
- Error types (use zero-value for `errors.Is`, `errors.AsType[T]` for structured fields): `TokenExpiredError`, `TokenNotYetValidError`, `InvalidIssuedAtError`, `InvalidIssuerError`, `InvalidAudienceError`, `ValidationError`, `ParseError`, `MissingRequiredClaimError`, `ClaimNotFoundError`, `ClaimAssignmentFailedError`, `ClaimValidationError`, `TimeDeltaError`
- Options: `WithCollectErrors(bool)` — collect all validation errors instead of first-error-only
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
- **AsMap(m Mappable, dst map[string]any) error** — convert to map; values are whatever `Field()` returns, so mutable values may be live aliases of source object (EXPERIMENTAL)
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
| `jwxio` | Safe IO: `ReadAllFromFiniteSource(rdr, maxBytes)` |
| `tokens` | String constants for algorithm names and separators |
| `pool` | Generic object pool (`Pool[T]`, `SlicePool[T]`) |
