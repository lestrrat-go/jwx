# Working with JWK

In this document we describe how to work with JWK using `github.com/lestrrat-go/jwx/jwk`

---

# Terminology

## JWK / Key

Used to describe a JWK key, possibly of typeRSA, ECDSA, OKP, or Symmetric.

## JWK Set / Set

A "jwk" resource on the web can either contain a single JWK or an array of multiple JWKs.
The latter is called a JWK Set.

It is impossible to know what the resource contains beforehand, so functions like `jwk.Parse()`
and `jwk.ReadFile()` returns a `jwk.Set` by default.

## Raw Key

Used to describe the underlying raw key that a JWK represents. For example, an RSA JWK can
represent rsa.PrivateKey/rsa.PublicKey, ECDSA JWK can represent ecdsa.PrivateKey/ecdsa.PublicKey,
and so forth

# Parsing

## Parse a set

If you have a key set, or are unsure if the source is a set or a single key, you should use `jwk.Parse()`

```go
keyset, _ := jwk.Parse(src)
```

## Parse a key

If you are sure that the source only contains a single key, you can use `jwk.ParseKey()`

```go
key, _ := jwk.ParseKey(src)
```

## Parse a key or a set in PEM format

Sometimes keys come in ASN.1 DER PEM format.  To parse these files, use the `jwk.WithPEM()` option.

```go
keyset, _ := jwk.Parse(srcSet, jwk.WithPEM(true))

key, _ := jwk.ParseKey(src, jwk.WithPEM(true))
```

## Parse a key from a file

To parse keys stored in a file, `jwk.ReadFile()` can be used. It accepts the same options as `jwk.Parse()`

```go
keyset, _ := jwk.ReadFile(filename)
```

## Parse a key from a remote resource

To parse keys stored in a remote location pointed by a HTTP(s) URL, use `jwk.Fetch()`

```go
keyset, _ := jwk.Fetch(ctx, url)
```

If you are going to be using this key repeatedly in a long running process, consider using `jwk.AutoRefresh` described elsewhere in this document.

# Using jwk.New()

Users can create a new key from scratch using `jwk.New()`.

`jwk.New()` requires the raw key as its argument.
There are other ways to creating keys from a raw key, but they require knowing its type in advance.
Use `jwk.New()` when you have a key type which you do not know its underlying type in advance.

It automatically creates the appropriate underlying key based on the given argument type.

| Argument Type | Key Type | Note |
|---------------|----------|------|
| []byte        | Symmetric Key | |
| ecdsa.PrivateKey | ECDSA Private Key | Argument may also be a pointer |
| ecdsa.PubliKey | ECDSA Public Key | Argument may also be a pointer |
| rsa.PrivateKey | RSA Private Key | Argument may also be a pointer |
| rsa.PubliKey | RSA Public Key | Argument may also be a pointer |
| x25519.PrivateKey | OKP Private Key | |
| x25519.PubliKey | OKP Public Key | |

One common mistake we see is users using `jwk.New()` to construct a key from a []byte variable containing the raw JSON format JWK.

```
// THIS IS WRONG!
buf, _ := ioutil.ReadFile(`key.json`) // os.ReadFile in go 1.16+
key, _ := jwk.New(buf) // ALWAYS creates a symmetric key
```

`jwk.New()` is used to create a new key from a known, *raw key* type. To process a yet-to-be-parsed
JWK, use `jwk.Parse()` or `jwk.ReadFile()`

```
// Parse a buffer containing a JSON JWK
buf, _ := ioutil.ReadFile(`key.json`) // os.ReadFile in go 1.16+
key, _ := jwk.Parse(buf)
```

```
// Read a file, parse it as JSON
key, _ := jwk.ParseFile(`key.json`)
```

# Generate a specific key type from scratch

Each of Symmetric, RSA, ECDSA, OKP key types have corresponding constructors to create an empty instance.
These keys are completely empty, so if you tried using them without initialization, it will not work.

```go
key := jwk.NewSymmetricKey()
key := jwk.NewECDSAPrivateKey()
key := jwk.NewECDSAPublicKey()
key := jwk.NewRSAPrivateKey()
key := jwk.NewRSAPublicKey()
key := jwk.NewOKPPrivateKey()
key := jwk.NewOKPPublicKey()
```

# Generate a specific key type from a raw key

If you have a raw key that you know the type of, you can create an empty instance, and then import values using the `FromRaw()` method.

```go
privkey, err := rsa.GenerateKey(...)

key := jwk.NewRSAPrivateKey()
err := key.FromRaw(privkey)
```

# Setting other fields

Using `jwk.New()` or `FromRaw()` allows you to populate the fields that are required to do perform the computations, but there are other fields that you may want to populate in a key. These fields can all be set using the `Set()` method.

The `Set()` method takes the name of the key, and a value to be associated with it. Some predefined keys have specific types (in which type checks are enforced), and others not.

`Set()` may not alter the Key Type (`kty`) field of a key.

the `jwk` package defines field key names for predefined keys as constants so you won't ever have to bang your head againt the wall after finding out that you have a typo.

```go
key.Set(jwk.KeyIDKey, `my-awesome-key`)
key.Set(`my-custom-field`, `unbelievable-value`)
```

# Auto-refreshing a JWK

Sometimes you need to fetch a remote JWK, and use it mltiple times in a long-running process.
For example, you may act as an itermediary to some other service, and you may need to verify incoming JWT tokens against the tokens in said other service.

Normally, you should be able to simply fetch the JWK using `jwk.Fetch()`, but keys are usually expired and rotated due to security reasons.
In such cases you would need to refetch the JWK periodically, which is a pain.

`github.com/lestrrat-go/jwx/jwk` provides the `jwk.AutoRefresh` tool to do this for you.

First, set up the `jwk.AutoRefresh` object.
You need to pass it a `context.Context` object to control the lifecycle of the background fetching goroutine.

```
ar := jwk.NewAutoRefresh(ctx)
```

Next you need to tell `jwk.AutoRefresh` which URLs to keep updating. For this, we use the `Configure()` method. `jwk.AutoRefresh` will use the information found in the HTTP headers (`Cache-Control` and `Expires`) or the default interval to determine when to fetch the key next time.

```
ar.Configure(`https://example.com/certs/pubkeys.json`)
```

And lastly, when you are about to use the key, load it from the `jwk.AutoRefresh` object.

```
keyset, _ := ar.Configure(ctx, `https://example.com/certs/pubkeys.json`)
```

Now keyset will always be "reasonably" new.
By "reasonably" we mean that we cannot guarantee that the keys will be refreshed immediately after it has been rotated in the remote source. But it should be close enough, and should you need to forcefully refresh the token using the `(jwk.AutoRefresh).Refresh()` method.

If re-fetching the keyset fails, a cached version will be returned from the previous successful fetch upon calling `(jwk.AutoRefresh).Fetch()`.
