# Incompatible Changes from v2 to v3

These are changes that are incompatible with the v2.x.x version.

* [Detailed List of Changes](#detailed-list-of-changes) - A comprehensive list of changes from v2 to v3

# Detailed list of changes

## Module

* This module now requires Go 1.20.x

* All `xxx.Get()` methods have been changed from `Get(string) (interface{}, error)` to
  `Get(string, interface{}) error`, where the second argument should be a pointer
  to the storage destination of the field.

* Iterator related methods such as, `Iterate()`, `AsMAp()`, `Walk()`, `Visit()`, etc have all been
  removed. Use `Keys()` to iterate through elements. Also, methods such as `Copy()` and `Merge()`
  no longer takes `context.Context` as its first argument.

* Method `Has()` to query the presence of a field has been added

* `PrivateParams()` has been removed.

## JWS

* Iterators have been completely removed.
* As a side effect of removing iterators, some methods such as `Copy()` lost the
  `context.Context` argument

## JWE

* Iterators have been completely removed.
* As a side effect of removing iterators, some methods such as `Copy()` lost the
  `context.Context` argument

## JWK

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

* Conversion between raw keys and `jwk.Key` can be customized using `jwk.KeyConverter`.
  Also see `jwk.RegisterKeyConverter()`

* Added `jwk/ecdsa` to keep track of which curves are available for ECDSA keys.