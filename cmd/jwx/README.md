# The `jwx` command line tool

`jwx` command line tool performs set of common operations involving JSON Object Signing and Encryption (JOSE).
This is provided as a sample application of sorts, and thus does not get much updates. As of this writing
it is not possible to install this command using `go install`. Instead, install it by executing the following
commands:

```sh
git clone https://github.com/lestrrat-go/jwx.git
cd jwx
make jwx
```

This will install the `jwx` tool in $GOBIN (or $GOPATH/bin, if $GOBIN is not available).

If you do a lot of JOSE related work on the command line, we highly recommend [github.com/latchset/jose](https://github.com/latchset/jose) for the same purpose, unless you might prefer to use `jwx` for its pure-Go implementation.

# Usage

All examples use the "full" name for command names and option names, but you can use the short forms interchangeably.

# jwx jwk

Work with JWKs

## jwx jwk generate

Full form:

```
jwx jwk generate [options]
```

Short form:

```
jwx jwk gen [options]
```

### Options

| Name          | Aliases  | Description |
|:--------------|:---------|:-------------|
| --type        | -t       | Type of JWK |
| --keysize     | -s       | Number of bits for RSA keys. Number of bytes for oct keys |
| --curve       | -c       | Elliptic curve type for EC or OKP keys |
| --template    | (none)   | Template to use to generate JWK. Must be a JSON object |
| --set         | (none)   | Always output as JWK set |
| --publick-key | -p       | Generate a public key |
| --output      | -o       | Write output to file ("-" for STDOUT) |

### Usage

You can generate random JWKs for RSA/EC/oct/OKP key types:

```shell
# output truncated for brevity
% jwx jwk generate --type RSA --keysize 4096
{
  "d": "TGGiBzGzFEWQQPE32m...",
  "dp": "LjsdUBxJhshSa7FEBP...",
  "dq": "G4SPP5e5sp-k8iCEAa...",
  "e": "AQAB",
  "kty": "RSA",
  "n": "lgy17ssrTVUFKxFq5gO...",
  "p": "wEXZYzjrSbAn1bDpQpN...",
  "q": "x8hEaDhNND9mOqHD_xH...",
  "qi": "BVDWmgMEZ7QBC8ZSL9..."
}

% jwx jwk generate --type EC --curve P-521
% jwx jwk generate --type oct --keysize 128
% jwx jwk generate --type OKP --curve Ed25519
```

To include extra information in the key such as a key ID, use the `--template` option

```shell
# output truncated for brevity
% jwx jwk generate --type EC --curve P-384 --template '{"kid":"myawesomekey"}'
{
  "crv": "P-384",
  "d": "Q4JFCjI81uYC2T...",
  "kid": "myawesomekey",
  "kty": "EC",
  "x": "cm6GYmhtjYLr_B...",
  "y": "4_dIgUa68wytgg..."
}
```

## jwx jwk format

Full form

```
jwx jwk format [options] [FILE]
```

Short form

```
jwx jwk fmt [options] [FILE]
```

You may specify "-" as `FILE` to tell the command to read from STDIN.

### Options

| Name            | Aliases | Description |
|-----------------|---------|-------------|
| --input-format  | -I      | JWK input format (json/pem) |
| --output-format | -O      | JWK output format (json/pem) |
| --set           | (none)  | Always output as JWK set |
| --publick-key   | -p      | Display the public key version of the input |
| --output        | -o      | Write output to file ("-" for STDOUT) |

### Usage (Produce public key of a private key)

Given a private key in file `ec.jwk`

```json
{"kty":"EC","crv":"P-256","x":"SVqB4JcUD6lsfvqMr-OKUNUphdNn64Eay60978ZlL74","y":"lf0u0pMj4lGAzZix5u4Cm5CMQIgMNpkwy163wtKYVKI","d":"0g5vAEKzugrXaRbgKG0Tj2qJ5lMP4Bezds1_sTybkfk"}
```

You can issue the following command to produce the public key of the above key:

```
% jwx jwk fmt --public-key ec.jwk
{
  "crv": "P-256",
  "kty": "EC",
  "x": "SVqB4JcUD6lsfvqMr-OKUNUphdNn64Eay60978ZlL74",
  "y": "lf0u0pMj4lGAzZix5u4Cm5CMQIgMNpkwy163wtKYVKI"
}
```

### Usage (Parse JSON)

You can parse and make sure that the a given JWK is well-formatted.

Given an unformatted key in file `ec.jwk`

```json
{"kty":"EC","crv":"P-256","x":"SVqB4JcUD6lsfvqMr-OKUNUphdNn64Eay60978ZlL74","y":"lf0u0pMj4lGAzZix5u4Cm5CMQIgMNpkwy163wtKYVKI","d":"0g5vAEKzugrXaRbgKG0Tj2qJ5lMP4Bezds1_sTybkfk"}
```

You can produce a pretty formatted key:

```shell
% jwx jwk format --input-format pem ec.jwk
{
  "crv": "P-256",
  "d": "0g5vAEKzugrXaRbgKG0Tj2qJ5lMP4Bezds1_sTybkfk",
  "kty": "EC",
  "x": "SVqB4JcUD6lsfvqMr-OKUNUphdNn64Eay60978ZlL74",
  "y": "lf0u0pMj4lGAzZix5u4Cm5CMQIgMNpkwy163wtKYVKI"
}
```

### Usage (Parse PEM)

You can parse a ASN.1 DER format key, encoded in PEM.

Given a PEM encoded ASN.1 DER format key in a file `ec.pem`:

```
-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDMYfnvWtC8Id5bPKae5yXSxQTt
+Zpul6AnnZWfI2TtIarvjHBFUtXRo96y7hoL4VWOPKGCsRqMFDkrbeUjRrx8iL91
4/srnyf6sh9c8Zk04xEOpK1ypvBz+Ks4uZObtjnnitf0NBGdjMKxveTq+VE7BWUI
yQjtQ8mbDOsiLLvh7wIDAQAB
-----END PUBLIC KEY-----
```

You can get the JSON representation by:

```shell
% jwx jwk parse --input-format pem ec.pem
{
  "crv": "P-256",
  "d": "0g5vAEKzugrXaRbgKG0Tj2qJ5lMP4Bezds1_sTybkfk",
  "kty": "EC",
  "x": "SVqB4JcUD6lsfvqMr-OKUNUphdNn64Eay60978ZlL74",
  "y": "lf0u0pMj4lGAzZix5u4Cm5CMQIgMNpkwy163wtKYVKI"
}
```
## Usage (Format JSON to PEM)

Formatting a JWK is equivalent to parsing, if the output format is `json`.
However, if you specify the output format as `pem`, you can create PEM encoded ASN.1 DER format keys.

Given the following key in file `rsa.jwk`

```json
{
  "e": "AQAB",
  "kty": "RSA",
  "n": "zGH571rQvCHeWzymnucl0sUE7fmabpegJ52VnyNk7SGq74xwRVLV0aPesu4aC-FVjjyhgrEajBQ5K23lI0a8fIi_deP7K58n-rIfXPGZNOMRDqStcqbwc_irOLmTm7Y554rX9DQRnYzCsb3k6vlROwVlCMkI7UPJmwzrIiy74e8"
}
```

You can produce a PEM encoded key:

```shell
% jwx jwk format --format pem rsa.jwk
-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDMYfnvWtC8Id5bPKae5yXSxQTt
+Zpul6AnnZWfI2TtIarvjHBFUtXRo96y7hoL4VWOPKGCsRqMFDkrbeUjRrx8iL91
4/srnyf6sh9c8Zk04xEOpK1ypvBz+Ks4uZObtjnnitf0NBGdjMKxveTq+VE7BWUI
yQjtQ8mbDOsiLLvh7wIDAQAB
-----END PUBLIC KEY-----
```

# jwx jws

## jwx jws parse

```
jwx jws parse FILE
```

Parses the given JWS message, and prints out the content in a human-redable format.

### Usage (Parse and inspect a JWS message)

Given a JWS message stored in `foo.jws` as follows:

```
eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk
```

You can inspect the contents of the JWS message by issuing the following command

```
% jwx jws parse foo.jws
Signature:                 "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
Protected Headers:         "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9"
Decoded Protected Headers: {
                             "alg": "HS256",
                             "typ": "JWT"
                           }
Payload:                   {"iss":"joe",
                            "exp":1300819380,
                            "http://example.com/is_root":true}
```

## jwx jws verify

```
jwx jws verify [options] FILE
```

You may specify "-" as `FILE` to tell the command to read from STDIN.

### Options

| Name         | Aliases  | Description  |
|:-------------|:---------|:-------------|
| --alg        | -a       | Algorithm to use in single key mode |
| --key        | -k       | File name that contains the key to use. May be a single JWK or JWK set |
| --key-format | (none)   | Format of the store key (json/pem) |
| --match-kid  | (none)   | If specified, attempts to verify using a key with a matching key ID ("kid") as the JWS |
| --output     | -o      | Write output to file ("-" for STDOUT) |

### Usage (Verify using specific algorithm)

```
jwx jws verify --alg [algorithm] --key [keyfile] FILE
```

Suppose we have `symmetric.jwk` containing the following:

```json
{
  "kty":"oct",
  "k":"AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow"
}
```

And suppose we would like to verify the contents of the file `signed.jws`, with this message which has been signed using `HS256`.

```
eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk
```

Then the following command will verify the JWS message and display the decoded payload.

```shell
% jwx jws verify --key symmetric.jwk --alg HS256 signed.jws
{"iss":"joe",
 "exp":1300819380,
 "http://example.com/is_root":true}
```

### Usage (Verify with matching key IDs)

```
jwx jws verify --key [keyfile] --match-kid FILE
```

Suppose we have `set.jwk` containing the following JWK set:

```json
{
  "keys": [
    {
      "kty": "EC",
      "kid": "otherkey",
      "crv": "P-256",
      "x": "SVqB4JcUD6lsfvqMr-OKUNUphdNn64Eay60978ZlL74",
      "y": "lf0u0pMj4lGAzZix5u4Cm5CMQIgMNpkwy163wtKYVKI",
      "d": "0g5vAEKzugrXaRbgKG0Tj2qJ5lMP4Bezds1_sTybkfk"
    },
    {
      "kty": "oct",
      "kid": "mykey",
      "alg": "HS256",
      "k": "AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow"
    }
  ]
}
```

Notice that the second key contains *both* "kid" and "alg" fields set to a proper values.

Then the following command will verify the JWS message and display the decoded payload.

```shell
% jwx jws verify --key set.jwk --match-kid signed.jws
```

## jwx jws sign

Creates a signed JWS message in compact format from a key and payload.

```
jwx jws sign [command options] FILE
```

You may specify "-" as `FILE` to tell the command to read from STDIN.

### Options

| Name         | Aliases  | Description  |
|:-------------|:---------|:-------------|
| --alg        | -a       | Algorithm to use in single key mode |
| --key        | -k       | File name that contains the key to use. May be a single JWK or JWK set |
| --key-format | (none)   | Format of the store key (json/pem) |
| --header     | (none)   | A string containing a template for additional header values. This must be a valid JSON object |
| --output     | -o       | Write output to file ("-" for STDOUT) |

### Usage (Signing a payload)

Given a file `payload.txt` containing the following payload:

```
Hello, World!
```

And JWK stored in `ec.jwk` as follows:

```
{"kty":"EC","crv":"P-256","x":"SVqB4JcUD6lsfvqMr-OKUNUphdNn64Eay60978ZlL74","y":"lf0u0pMj4lGAzZix5u4Cm5CMQIgMNpkwy163wtKYVKI","d":"0g5vAEKzugrXaRbgKG0Tj2qJ5lMP4Bezds1_sTybkfk"}
```

You can create a signed JWS in compact format by issuing the following command:

```
% jwx jws sign --key ec.jwk --alg ES256 payload.txt
eyJhbGciOiJFUzI1NiJ9.SGVsbG8sIFdvcmxkIQo.SuzTiJ0yJmDkte-SyHQidvhKyHxXdQTM5iCOmURzB0pi4ySM8A303tcAZTa2TLnf9LUZ3yzPpQIyRMF2d8_5Lg
```

# jwx jwe

Work with JWE messages.

## jwx jwe encrypt 

Full form:

```
jwx jwe encrypt [options] FILE
```

Short form:

```
jwx jwe enc [options] FILE
```

### Options

| Name                 | Aliases  | Description  |
|:---------------------|:---------|:-------------|
| --key                | -k       | JWK to encrypt with |
| --key-format         | (none)   | JWK format: json or pem |
| --key-encryption     | -K       | Key encryption algorithm name |
| --content-encryption | -C       | Content encryption algorithm name |
| --compress           | (none)   | Enable compression |
| --output             | -o       | Write output to file ("-" for STDOUT) |

### Usage (Encrypt a payload)

Given a file `payload.txt` containing the following payload:

```
Hello, World!
```

And JWK stored in `ec.jwk` as follows (Note: a private key may be used as well):

```
{"kty":"EC","crv":"P-256","x":"SVqB4JcUD6lsfvqMr-OKUNUphdNn64Eay60978ZlL74","y":"lf0u0pMj4lGAzZix5u4Cm5CMQIgMNpkwy163wtKYVKI"}
```

You can generate an encrypted JWE message with ECDH-ES key encryption and A256CBC-HS512 content encryption by issuing the following command:

```
% jwx jwe encrypt --key ec.jwk --key-encryption ECDH-ES --content-encryption A256CBC-HS512 payload.txt
eyJhbGciOiJFQ0RILUVTIiwiZW5jIjoiQTI1NkNCQy1IUzUxMiIsImVwayI6eyJjcnYiOiJQLTI1NiIsImt0eSI6IkVDIiwieCI6IllGeFZmTUZXQl9kcjhvUGgzWTdRMF9pYzllMjR5XzlleklPbG9WcjdHWVkiLCJ5Ijoiei1QZFB2cXdGU3A0ODYzbzRTWmQwSDdiVXhYUUJqckJ4bkxpaHduRVNKYyJ9fQ..MJFgvx7zMBzM47Is-brKXw.9UL2iAFuL4rjegaLhf3wPA.KGWzX-cmmGG1CQMMpQzyEncu64pkb6217HCFZfIynlE
```

## jwx jwe decrypt 

Full form:

```
jwx jwe decrypt [options] FILE
```

Short form:

```
jwx jwe dec [options] FILE
```

### Options

| Name                 | Aliases  | Description  |
|:---------------------|:---------|:-------------|
| --key                | -k       | JWK to encrypt with |
| --key-format         | (none)   | JWK format: json or pem |
| --key-encryption     | -K       | Key encryption algorithm name. If unspecified, we will try the algorithms in the message|
| --output             | -o       | Write output to file ("-" for STDOUT) |

### Usage (Decrypt a JWE message)

Given a file `message.jwe` containing the following JWE message:

```
eyJhbGciOiJFQ0RILUVTIiwiZW5jIjoiQTI1NkNCQy1IUzUxMiIsImVwayI6eyJjcnYiOiJQLTI1NiIsImt0eSI6IkVDIiwieCI6IllGeFZmTUZXQl9kcjhvUGgzWTdRMF9pYzllMjR5XzlleklPbG9WcjdHWVkiLCJ5Ijoiei1QZFB2cXdGU3A0ODYzbzRTWmQwSDdiVXhYUUJqckJ4bkxpaHduRVNKYyJ9fQ..MJFgvx7zMBzM47Is-brKXw.9UL2iAFuL4rjegaLhf3wPA.KGWzX-cmmGG1CQMMpQzyEncu64pkb6217HCFZfIynl
```

And a private key in `ec.jwk`:

```
{"kty":"EC","crv":"P-256","x":"SVqB4JcUD6lsfvqMr-OKUNUphdNn64Eay60978ZlL74","y":"lf0u0pMj4lGAzZix5u4Cm5CMQIgMNpkwy163wtKYVKI","d":"0g5vAEKzugrXaRbgKG0Tj2qJ5lMP4Bezds1_sTybkfk"}
```

You can get the decrypted contents by issuing the following command:

```
% jwx jwe decrypt -k ec.jwk message.jwk
Hello, World!
```

# jwx jwa

List supported algorithms.

### Options 

| Name                 | Aliases  | Description  |
|:---------------------|:---------|:-------------|
| --key-type           | -k       | JWK key types |
| --elliptic-curve     | -E       | Elliptic curve types |
| --key-encryption     | -K       | Key encryption algorithms |
| --content-encryption | -C       | Content encryption algorithms |
| --signature          | -S       | Signature algorithms |
