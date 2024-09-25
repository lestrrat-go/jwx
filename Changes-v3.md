# Incompatible Changes from v2 to v3

These are changes that are incompatible with the v2.x.x version.

* [Detailed List of Changes](#detailed-list-of-changes) - A comprehensive list of changes from v2 to v3

# Detailed list of changes

## Module

* This module now requires Go 1.21

* All `xxx.Get()` methods have been changed from `Get(string) (interface{}, error)` to
  `Get(string, interface{}) error`, where the second argument should be a pointer
  to the storage destination of the field.

## JWS

* Iterators have been completely removed.
* As a side effect of removing iterators, some methods such as `Copy()` lost the
  `context.Context` argument

## JWE

* Iterators have been completely removed.
* As a side effect of removing iterators, some methods such as `Copy()` lost the
  `context.Context` argument

## JWK

* Experimental secp256k1 encoding/decoding for PEM encoded ASN.1 DER Format 
  has been removed. Instead, `jwk.PEMDecoder` and `jwk.PEMEncoder` have been
  added to support those who want to perform non-standard PEM encoding/decoding

* Iterators have been completely removed.

* `jwk/x25519` has been removed. To use X25519 keys, use `(crypto/ecdh).PrivateKey` and
  `(crypto/ecdh).PublicKey`. Similarly, internals have been reworked to use `crypto/ecdh`

* Parsing has completely been reworked. It is now possible to add your own `jwk.KeyParser`
  to generate a custom `jwk.Key` that this library may not natively support. Also see
  `jwk.RegisterKeyParser()`

* `jwk.KeyProbe` has been added to aid probing the JSON message. This is used to
  guess the type of key described in the JSON message before deciding which concrete
  type to instantiate, and aids implementing your own `jwk.KeyParser`. Also see
  `jwk.RegisterKeyProbe()`

* Conversion between raw keys and `jwk.Key` can be customized using `jwk.KeyImporter` and `jwk.KeyExporter`.
  Also see `jwk.RegisterKeyImporter()` and `jwk.RegisterKeyExporter()`

* Added `jwk/ecdsa` to keep track of which curves are available for ECDSA keys.

* `(jwk.Key).Raw()` has been deprecated. Use `jwk.Export()` instead.

* `jwk.SetGlobalFetcher` has been deprecated. The required version for `github.com/lestrrat-go/httprc`
  has been upgraded, and thus we no longer have a pool of workers that need to be controlled.

* `jwk.Fetcher` has been clearly marked as something that has limited
  usage for `jws.WithVerifyAuto`
