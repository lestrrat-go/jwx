# Working with JWK

In this document we describe how to work with JWK using `github.com/lestrrat-go/jwx/jwk`

* [Terminology](#terminology)
  * [JWK / Key](#jwk--key)
  * [JWK Set / Set](#jwk-set--set)
  * [Raw Key](#raw-key)
* [Parsing](#parsing)
  * [Parse a set](#parse-a-set)
  * [Parse a key](#parse-a-key)
  * [Parse a key or set in PEM format](#parse-a-key-or-a-set-in-pem-format)
  * [Parse a key from a file](#parse-a-key-from-a-file)
  * [Parse a key from a remote resource](#parse-a-key-from-a-remote-resource)
* [Construction](#construction)
  * [Using jwk.New()](#using-jwknew)
  * [Construct a specific key type from scratch](#construct-a-specific-key-type-from-scratch)
  * [Construct a specific key type from a raw key](#construct-a-specific-key-type-from-a-raw-key)
* [Setting values to fields](#setting-values-to-fields)
* [Fetching JWK Sets](#fetching-jwk-sets)
  * [Fetching a JWK Set once](#fetching-a-jwk-set-once)
  * [Auto-refreshing remote keys](#auto-refreshing-remote-keys)
  * [Using Whitelists](#using-whitelists)
* [Converting a jwk.Key to a raw key](#converting-a-jwkkey-to-a-raw-key)

---

# Terminology

## JWK / Key

Used to describe a JWK key, possibly of typeRSA, ECDSA, OKP, or Symmetric.

## JWK Set / Set

A "jwk" resource on the web can either contain a single JWK or an array of multiple JWKs.
The latter is called a JWK Set.

It is impossible to know what the resource contains beforehand, so functions like [`jwk.Parse()`](https://pkg.go.dev/github.com/lestrrat-go/jwx/jwk#Parse)
and [`jwk.ReadFile()`](https://pkg.go.dev/github.com/lestrrat-go/jwx/jwk#ReadFile) returns a [`jwk.Set`](https://pkg.go.dev/github.com/lestrrat-go/jwx/jwk#Set) by default.

## Raw Key

Used to describe the underlying raw key that a JWK represents. For example, an RSA JWK can
represent rsa.PrivateKey/rsa.PublicKey, ECDSA JWK can represent ecdsa.PrivateKey/ecdsa.PublicKey,
and so forth

# Parsing

## Parse a set

If you have a key set, or are unsure if the source is a set or a single key, you should use [`jwk.Parse()`](https://pkg.go.dev/github.com/lestrrat-go/jwx/jwk#Parse)

```go
keyset, _ := jwk.Parse(src)
```

## Parse a key

If you are sure that the source only contains a single key, you can use [`jwk.ParseKey()`](https://pkg.go.dev/github.com/lestrrat-go/jwx/jwk#ParseKey)

```go
key, _ := jwk.ParseKey(src)
```

## Parse a key or a set in PEM format

Sometimes keys come in ASN.1 DER PEM format.  To parse these files, use the [`jwk.WithPEM()`](https://pkg.go.dev/github.com/lestrrat-go/jwx/jwk#WithPEM) option.

```go
keyset, _ := jwk.Parse(srcSet, jwk.WithPEM(true))

key, _ := jwk.ParseKey(src, jwk.WithPEM(true))
```

## Parse a key from a file

To parse keys stored in a file, [`jwk.ReadFile()`](https://pkg.go.dev/github.com/lestrrat-go/jwx/jwk#ReadFile) can be used. 

```go
keyset, _ := jwk.ReadFile(filename)
```

`jwk.ReadFile()` accepts the same options as [`jwk.Parse()`](https://pkg.go.dev/github.com/lestrrat-go/jwx/jwk#Parse), therefore you can read a PEM-encoded file via the following incantation:

```go
keyset, _ := jwk.ReadFile(filename, jwk.WithPEM(true))
```

## Parse a key from a remote resource

To parse keys stored in a remote location pointed by a HTTP(s) URL, use [`jwk.Fetch()`](https://pkg.go.dev/github.com/lestrrat-go/jwx/jwk#Fetch)

```go
keyset, _ := jwk.Fetch(ctx, url)
```

If you are going to be using this key repeatedly in a long running process, consider using [`jwk.AutoRefresh`](https://pkg.go.dev/github.com/lestrrat-go/jwx/jwk#AutoRefresh) described elsewhere in this document.

# Construction

## Using jwk.New()

Users can create a new key from scratch using [`jwk.New()`](https://pkg.go.dev/github.com/lestrrat-go/jwx/jwk#New).

[`jwk.New()`](https://pkg.go.dev/github.com/lestrrat-go/jwx/jwk#New) requires the raw key as its argument.
There are other ways to creating keys from a raw key, but they require knowing its type in advance.
Use [`jwk.New()`](https://pkg.go.dev/github.com/lestrrat-go/jwx/jwk#New) when you have a key type which you do not know its underlying type in advance.

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

One common mistake we see is users using [`jwk.New()`](https://pkg.go.dev/github.com/lestrrat-go/jwx/jwk#New) to construct a key from a []byte variable containing the raw JSON format JWK.

```go
// THIS IS WRONG!
buf, _ := ioutil.ReadFile(`key.json`) // os.ReadFile in go 1.16+
key, _ := jwk.New(buf) // ALWAYS creates a symmetric key
```

[`jwk.New()`](https://pkg.go.dev/github.com/lestrrat-go/jwx/jwk#New) is used to create a new key from a known, *raw key* type. To process a yet-to-be-parsed
JWK, use [`jwk.Parse()`](https://pkg.go.dev/github.com/lestrrat-go/jwx/jwk#Parse) or [`jwk.ReadFile()`](https://pkg.go.dev/github.com/lestrrat-go/jwx/jwk#ReadFile)

```go
// Parse a buffer containing a JSON JWK
buf, _ := ioutil.ReadFile(`key.json`) // os.ReadFile in go 1.16+
key, _ := jwk.Parse(buf)
```

```go
// Read a file, parse it as JSON
key, _ := jwk.ParseFile(`key.json`)
```

## Construct a specific key type from scratch

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

For advanced users: Once you obtain these "empty" objects, you *can* use `json.Unmarshal()` to parse the JWK.

```
// OK
key := jwk.NewRSAPrivateKey()
if err := json.Unmarshal(src, key); err != nil {
  return errors.New(`failed to unmarshal RSA key`)
}

// NOT OK
var key jwk.Key // we can't do this because we don't know where to store the data
if err := json.Unmarshal(src, &key); err !+ nil {
  ...
}
```

## Construct a specific key type from a raw key

[`jwk.New()`](https://pkg.go.dev/github.com/lestrrat-go/jwx/jwk#New) already does this, but if for some reason you would like to initialize an already existing [`jwk.Key`](https://pkg.go.dev/github.com/lestrrat-go/jwx/jwk#Key), you can use the [`jwk.FromRaw()`](https://pkg.go.dev/github.com/lestrrat-go/jwx/jwk#FromRaw) method.

```go
privkey, err := rsa.GenerateKey(...)

key := jwk.NewRSAPrivateKey()
err := key.FromRaw(privkey)
```

## Setting values to fields

Using [`jwk.New()`](https://pkg.go.dev/github.com/lestrrat-go/jwx/jwk#New) or [`jwk.FromRaw()`](https://pkg.go.dev/github.com/lestrrat-go/jwx/jwk#FromRaw) allows you to populate the fields that are required to do perform the computations, but there are other fields that you may want to populate in a key. These fields can all be set using the [`jwk.Set()`](https://pkg.go.dev/github.com/lestrrat-go/jwx/jwk#Set) method.

The [`jwk.Set()`](https://pkg.go.dev/github.com/lestrrat-go/jwx/jwk#Set) method takes the name of the key, and a value to be associated with it. Some predefined keys have specific types (in which type checks are enforced), and others not.

[`jwk.Set()`](https://pkg.go.dev/github.com/lestrrat-go/jwx/jwk#Set) may not alter the Key Type (`kty`) field of a key.

the `jwk` package defines field key names for predefined keys as constants so you won't ever have to bang your head againt the wall after finding out that you have a typo.

```go
key.Set(jwk.KeyIDKey, `my-awesome-key`)
key.Set(`my-custom-field`, `unbelievable-value`)
```
# Fetching JWK Sets

## Fetching a JWK Set once

To fetch a JWK Set once, use `jwk.Fetch()`.

```go
set, err := jwk.Fetch(ctx, url, options...)
```

## Auto-refreshing remote keys

Sometimes you need to fetch a remote JWK, and use it mltiple times in a long-running process.
For example, you may act as an itermediary to some other service, and you may need to verify incoming JWT tokens against the tokens in said other service.

Normally, you should be able to simply fetch the JWK using [`jwk.Fetch()`](https://pkg.go.dev/github.com/lestrrat-go/jwx/jwk#Fetch), but keys are usually expired and rotated due to security reasons.
In such cases you would need to refetch the JWK periodically, which is a pain.

`github.com/lestrrat-go/jwx/jwk` provides the [`jwk.AutoRefresh`](https://pkg.go.dev/github.com/lestrrat-go/jwx/jwk#AutoRefresh) tool to do this for you.

First, set up the [`jwk.AutoRefresh`](https://pkg.go.dev/github.com/lestrrat-go/jwx/jwk#AutoRefresh) object.
You need to pass it a `context.Context` object to control the lifecycle of the background fetching goroutine.

```go
ar := jwk.NewAutoRefresh(ctx)
```

Next you need to tell [`jwk.AutoRefresh`](https://pkg.go.dev/github.com/lestrrat-go/jwx/jwk#AutoRefresh) which URLs to keep updating. For this, we use the `Configure()` method. [`jwk.AutoRefresh`](https://pkg.go.dev/github.com/lestrrat-go/jwx/jwk#AutoRefresh) will use the information found in the HTTP headers (`Cache-Control` and `Expires`) or the default interval to determine when to fetch the key next time.

```go
ar.Configure(`https://example.com/certs/pubkeys.json`)
```

And lastly, each time you are about to use the key, load it from the [`jwk.AutoRefresh`](https://pkg.go.dev/github.com/lestrrat-go/jwx/jwk#AutoRefresh) object.

```go
keyset, _ := ar.Fetch(ctx, `https://example.com/certs/pubkeys.json`)
```

The returned `keyset` will always be "reasonably" new. It is important that you always call `ar.Fetch()` before using the `keyset` as this is where the refreshing occurs.

By "reasonably" we mean that we cannot guarantee that the keys will be refreshed immediately after it has been rotated in the remote source. But it should be close enough, and should you need to forcefully refresh the token using the `(jwk.AutoRefresh).Refresh()` method.

If re-fetching the keyset fails, a cached version will be returned from the previous successful fetch upon calling `(jwk.AutoRefresh).Fetch()`.

## Using Whitelists

If you are fetching JWK Sets from a possibly untrusted source such as the `"jku"` field of a JWS message, you may have to perform some sort of
whitelist checking. You can provide a `jwk.Whitelist` object to either `jwk.Fetch()` or `(*jwk.AutoRefresh).Configure()` methods to specify the
use of a whitelist.

Currently the package provides `jwk.MapWhitelist` and `jwk.RegexpWhitelist` types for simpler cases.

```go
wl := jwk.NewMapWhitelist().
  Add(url1).
  Add(url2).
  Add(url3

wl := jwk.NewRegexpWhitelist().
  Add(regexp1).
  Add(regexp2).
  Add(regexp3)

jwk.Fetch(ctx, url, jwk.WithWhitelist(wl))

// or in a jwk.AutoRefresh object:
ar.Configure(url, jwk.WithWhitelist(wl))
```

If you would like to implement something more complex, you can provide a function via `jwk.WhitelistFunc` or implement you own type of `jwk.Whitelist`.

# Converting a jwk.Key to a raw key

As discussed in [Terminology](#terminology), this package calls the "original" keys (e.g. `rsa.PublicKey`, `ecdsa.PrivateKey`, etc) as "raw" keys. To obtain a raw key from a  [`jwk.Key`](https://pkg.go.dev/github.com/lestrrat-go/jwx/jwk#Key) object, use the [`Raw()`](https://github.com/github.com/lestrrat-go/jwx/jwk#Raw) method.

```go
key, _ := jwk.ParseKey(src)

var raw interface{}
if err := key.Raw(&raw); err != nil {
  ...
}
```

In the above example, `raw` contains whatever the [`jwk.Key`](https://pkg.go.dev/github.com/lestrrat-go/jwx/jwk#Key) represents.
If `key` represents an RSA key, it will contain either a `rsa.PublicKey` or `rsa.PrivateKey`. If it represents an ECDSA key, an `ecdsa.PublicKey`, or `ecdsa.PrivateKey`, etc.

If the only operation that you are performing is to grab the raw key out of a JSON JWK, use [`jwk.ParseRawKey`](https://pkg.go.dev/github.com/lestrrat-go/jwx/jwk#ParseRawKey)

```go
var raw interface{}
if err := jwk.ParseRawKey(src, &raw); err != nil {
  ...
}
```
