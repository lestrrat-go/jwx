# The `jwx` command line tool

# jwx jwk

## Parsing a JWK (JSON)

You can parse and make sure that the a given JWK is well-formatted.

Given an unformatted key in file `ec.jwk`

```json
{"kty":"EC","crv":"P-256","x":"SVqB4JcUD6lsfvqMr-OKUNUphdNn64Eay60978ZlL74","y":"lf0u0pMj4lGAzZix5u4Cm5CMQIgMNpkwy163wtKYVKI","d":"0g5vAEKzugrXaRbgKG0Tj2qJ5lMP4Bezds1_sTybkfk"}
```

You can produce a pretty formatted key:

```shell
% jwx jwk parse ec.jwk
{
  "crv": "P-256",
  "d": "0g5vAEKzugrXaRbgKG0Tj2qJ5lMP4Bezds1_sTybkfk",
  "kty": "EC",
  "x": "SVqB4JcUD6lsfvqMr-OKUNUphdNn64Eay60978ZlL74",
  "y": "lf0u0pMj4lGAzZix5u4Cm5CMQIgMNpkwy163wtKYVKI"
}
```

## Parsing a JWK (PEM)

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
% jwx jwk parse --format pem ec.pem
{
  "crv": "P-256",
  "d": "0g5vAEKzugrXaRbgKG0Tj2qJ5lMP4Bezds1_sTybkfk",
  "kty": "EC",
  "x": "SVqB4JcUD6lsfvqMr-OKUNUphdNn64Eay60978ZlL74",
  "y": "lf0u0pMj4lGAzZix5u4Cm5CMQIgMNpkwy163wtKYVKI"
}
```

## Formatting a JWK

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

## Verifying a JWS message (single key)

```
jwx jws verify --alg [algorithm] --key [keyfile] <filename>
jwx jws verify --alg [algorithm] --key [keyfile] --stdin
```

### Example

Suppose we have symmetric.jwk containing the following

```json
{
  "kty":"oct",
  "k":"AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow"
}
```

And suppose we would like to verify the contents of the file `signed.jws`, whith this message which has been signed using `HS256`.

```
eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk
```

```shell
% jwx jws verify --file signed.jws --key symmetric.jwk --alg HS256
{"iss":"joe",
 "exp":1300819380,
 "http://example.com/is_root":true}
```
