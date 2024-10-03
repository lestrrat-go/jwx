# Incompatible Changes from v2 to v3

These are changes that are incompatible with the v2.x.x version.

* [Detailed List of Changes](#detailed-list-of-changes) - A comprehensive list of changes from v2 to v3

# Detailed list of changes

## Module

* This module now requires Go 1.22

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

* `jwk.KeyUsageType` can now be configured so that it's possible to assign values
  other than "sig" and "enc" via `jwk.RegisterKeyUsage()`. Furthermore, strict
  checks can be turned on/off against these registered values

* `jwk.Cache` has been completely re-worked based on github.com/lestrrat-go/httprc/v3.
  In particular, the default whitelist mode has changed from "block everything" to
  "allow everything".

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

* `(jwk.Key).Raw()` has been deprecated. Use `jwk.Export()` instead to convert `jwk.Key`
  objects into their "raw" versions (e.g. `*rsa.PrivateKey`, `*ecdsa.PrivateKey`, etc).
  This is to allow third parties to register custom key types that this library does not
  natively support: Whereas a method must be bound to an object, and thus does not necessarily
  have a way to hook into a global settings (i.e. custom exporter/importer) for arbitrary
  key types, if the entrypoint is a function it's much easier and cleaner to for third-parties
  to take advantage and hook into the mechanisms.

* `jwk.FromRaw()` has been derepcated. Use `jwk.Import()` instead to convert "raw"
  keys (e.g. `*rsa.PrivateKEy`, `*Ecdsa.PrivateKey`, etc) int `jwk.Key`s.

* `(jwk.Key).FromRaw()` has been deprecated. The method `(jwk.Key).Import()` still exist for
  built-in types, but it is no longer part of any public API (`interface{}`).

* `jwk.Fetch` is marked as a simple wrapper around `net/http` and `jwk.Parse`.

* `jwk.SetGlobalFetcher` has been deprecated.

* `jwk.Fetcher` has been clearly marked as something that has limited
  usage for `jws.WithVerifyAuto`
