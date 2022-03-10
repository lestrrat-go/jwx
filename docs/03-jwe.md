# Working with JWE

In this document we describe how to work with JWK using `github.com/lestrrat-go/jwx/v2/jwe`

* [Parsing](#parsing)
  * [Parse a JWE message stored in memory](#parse-a-jwe-message-stored-in-memory)
  * [Parse a JWE message stored in a file](#parse-a-jwe-message-stored-in-a-file)
* [Encrypting](#encrypting)
  * [Generating a JWE message in compact serialization format](#generating-a-jwe-message-in-compact-serialization-format)
  * [Generating a JWE message in JSON serialization format](#generating-a-jwe-message-in-json-serialization-format)
  * [Generating a JWE message with detached payload](#generating-a-jwe-message-with-detached-payload)
  * [Including arbitrary headers](#including-arbitrary-headers)
* [Decrypting](#decryptingG)
  * [Decrypting using a single key](#decrypting-using-a-single-key)
  * [Decrypting using a JWKS](#decrypting-using-a-jwks)

# Parsing

Parsing a JWE message means taking either a JWE message serialized in JSON or Compact form and loading it into a `jwe.Message` object. No decryption is performed, and therefore you cannot access the raw payload as when you use `jwe.Decrypt()` to decrypt the message.

Also, be aware that a `jwe.Message` is not meant to be used for either decryption nor encryption. It is only provided so that it can be inspected -- there is no way to decrypt or sign using an already parsed `jwe.Message`.

## Parse a JWE message stored in memory

You can parse a JWE message in memory stored as `[]byte` into a [`jwe.Message`](https://pkg.go.dev/github.com/lestrrat-go/jwx/v2/jwe#Message) object. In this mode, there is no decryption performed.

<!-- INCLUDE(examples/jwe_parse_example_test.go) -->
<!-- END INCLUDE -->

## Parse a JWE message stored in a file

To parse a JWE stored in a file, use [`jwe.ReadFile()`](https://pkg.go.dev/github.com/lestrrat-go/jwx/v2/jwe#ReadFile). [`jwe.ReadFile()`](https://pkg.go.dev/github.com/lestrrat-go/jwx/v2/jwe#ReadFile) accepts the same options as [`jwe.Parse()`](https://pkg.go.dev/github.com/lestrrat-go/jwx/v2/jwe#Parse).

<!-- INCLUDE(examples/jwe_readfile_example_test.go) -->
<!-- END INCLUDE -->

# Encrypting

## Generating a JWE message in compact serialization format

To encrypt an arbitrary payload as a JWE message in compact serialization format, use `jwt.Encrypt()`.

Note that this would be [slightly different if you are encrypting JWTs](01-jwt.md#serialize-using-jws), as you would be
using functions from the `jwt` package instead of `jws`.

<!-- INCLUDE(examples/jwe_encrypt_example_test.go) -->
<!-- END INCLUDE -->

## Generating a JWE message in JSON serialization format

Generally the only time you need to use a JSON serialization format is when you have to generate multiple recipients (encrypted keys) for a given payload using multiple encryption algorithms and keys.

When this need arises, use the [`jwe.Encrypt()`](https://pkg.go.dev/github.com/lestrrat-go/jwx/v2/jws#Encrypt) function with the `jwe.WithJSON()` option and multiple `jwe.WithKey()` options:

<!-- INCLUDE(examples/jwe_encrypt_json_example_test.go) -->
<!-- END INCLUDE -->

## Including arbitrary headers

By default, only some header fields are included in the result from `jwe.Encrypt()`.

For protected headers, you can use the jws.

In order to provide extra headers to the encrypted message, you will need to use
`jwe.WithKey()` option with the `jwe.WithPerRecipientHeaders()` suboption.


<!-- INCLUDE(examples/jwe_encrypt_with_headers_example_Test.go) -->
<!-- END INCLUDE -->

# Decrypting

## Decrypting using a single key

To decrypt a JWE message using a single key, use `jwe.Decrypt()` with the `jwe.WithKey()` option.
It will automatically do the right thing whether it's serialized in compact form or JSON form.

The `alg` must be explicitly specified.

<!-- INCLUDE(examples/jwe_decrypt_with_key_example_test.go) -->
<!-- END INCLUDE -->

## Decrypting using a JWKS

To decrypt a payload using JWKS, by default you will need your payload and JWKS to have matching `alg` field.

The `alg` field's requirement is the same for using a single key. See "[Why don't you automatically infer the algorithm for `jwe.Decrypt`?](99-faq.md#why-dont-you-automatically-infer-the-algorithm-for-jwsdecrypt-)"

Note that unlike in JWT, the `kid` is not required by default, although you _can_ make it so
by passing `jwe.WithRequireKid(true)`.

For more discussion on why/how `alg`/`kid` values work, please read the [relevant section in the JWT documentation](01-jwt.md#parse-and-decrypt-a-jwt-with-a-key-set-matching-kid)

<!-- INCLUDE(examples/jwe_decrypt_with_keyset_example_test.go) -->
<!-- END INCLUDE -->
