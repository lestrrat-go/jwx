# Frequently asked questions

## "Why can't I create my jwk.Key?"

### 1. You are passing the wrong parameter to `jwk.New()`.

As stated in the documentation, `jwk.New()` creates different types of keys depending on the type of the input.

Use `jwk.New()` to construct a JWK from the [*raw* key](./04-jwk.md#raw-key). Use `jwk.Parse()` or `jwk.ParseKey()` to parse a piece of data (`[]byte` and the like) and create the appropriate key type from its contents.

See ["Using jwk.New()"](./04-jwk.md#using-jwknew) for more details.

### 2. You are not decoding PEM.

When you read from a PEM encoded file (e.g. `key.pem`), you cannot just parse it using `jwk.Parse()` as by default we do not expect the data to be PEM encoded. Use `jwk.WithPEM(true)` for this.

See ["Parse a key or set in PEM format"](./04-jwk.md#parse-a-key-or-set-in-pem-format) for more details.

## "Why is my code to call `jwt.Sign()`/`jws.Verify()` failing?"

### 1. Your algorithm and key type do not match.

Any given signature algorithm requires a particular type of key. If the pair is not setup correctly, the operation will fail. Below is a table of general algorithm to key type pair. Note that this table may not be updated regularly. Use common sense and search online to find out if one of the algorithms/key types we support is not listed in the table.

| Algorithm Family | Key Type  |
|------------------|-----------|
| jwa.HS\*\*\*     | Symmetric |
| jwa.RS\*\*\*     | RSA       |
| jwa.ES\*\*\*     | Elliptic  |

### 2. You are mixing up when to use private/public keys.

You sign using a private key. You verify using a public key (although, it is possible to verify using the private key, but is not really a common operation).

So, for example, a service like Google will sign their JWTs using their private keys which are not publicly available, but will provide the public keys somewhere so that you can verify their JWTs using those public keys.

### 3. You are parsing the wrong token.

Often times we have people asking us about github.com/lestrrat-go/jwx/jwt not being able to parse a token... except, they are not JWTs.

For example, when a provider says they will give you an "access token" ... well, it *may* be a JWT, but often times they are just some sort of string key (which will definitely parse if you pass it to `jwt.Parse`). Sometimes what you really want is stored in a different token, and it may be called an "ID token". Who knows, these things vary between implementation to implemention.

After all, the only thing we can say is that you should check that you are parsing. 
