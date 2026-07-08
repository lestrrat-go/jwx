// Package jwk implements JWK as described in https://tools.ietf.org/html/rfc7517
//
// This package implements jwk.Key to represent a single JWK, and jwk.Set to represent
// a set of JWKs.
//
// The `jwk.Key` type is an interface, which hides the underlying implementation for
// each key type. Each key type can further be converted to interfaces for known
// types, such as `jwk.ECDSAPrivateKey`, `jwk.RSAPublicKey`, etc. This may not necessarily
// work for third party key types (see section on "Registering a key type" below).
//
// Users can create a JWK in two ways. One is to unmarshal a JSON representation of a
// key. The second one is to use `jwk.Import()` to import a raw key, validate it,
// and convert it to a jwk.Key.
//
// # Simple Usage
//
// You can parse a JWK from a JSON payload:
//
//	jwk.ParseKey([]byte(`{"kty":"EC",...}`))
//
// You can go back and forth between raw key types and JWKs:
//
//	jwkKey, _ := jwk.Import[jwk.Key](rsaPrivateKey)
//	rawKey, _ := jwk.Export[*rsa.PrivateKey](jwkKey)
//
// When you know the expected key type, use a concrete type parameter:
//
//	rsaKey, _ := jwk.Import[jwk.RSAPrivateKey](rsaPrivateKey)
//	ecKey, _ := jwk.ParseKeyAs[jwk.ECDSAPublicKey](jsonData)
//
// You can use them to sign/verify/encrypt/decrypt:
//
//	jws.Sign([]byte(`...`), jws.WithKey(jwa.RS256, jwkKey))
//	jwe.Encrypt([]byte(`...`), jwe.WithKey(jwa.RSA_OAEP, jwkKey))
//
// See examples/jwk_parse_example_test.go and other files in the examples/ directory for more.
//
// # Registering a custom key type
//
// The library supports adding new key types not implemented out of the
// box (vendor-specific algorithms, post-quantum work, etc.) via four
// registration points:
//
//   - KeyProbe — partial JSON unmarshaling that picks out hint fields
//     used to decide what concrete key type to construct.
//     Add fields with [RegisterProbeField].
//   - KeyParser — converts a JSON payload into a jwk.Key using the
//     probe's hints. Register with [RegisterKeyParser].
//   - KeyImporter — converts a raw Go crypto value into a jwk.Key.
//     Register with [RegisterKeyImporter] (generic, one importer per
//     Go type).
//   - KeyExporter — converts a jwk.Key back into a raw Go value.
//     Register with [RegisterKeyExporter], keyed by [KeyKind].
//
// The whole extension surface is **experimental**: the API may change
// in backward-incompatible ways even between minor versions.
//
// See the "Registering a custom key type" section in
// docs/04-jwk.md for the full walkthrough including a worked example.
package jwk
