## JWT with net/http

Integrating this library with net/http is simple. In this example, we will assume that you are using a `Server` object that is defined as follows:

```go
type Server struct {
  alg       jwa.SignatureAlgorithm
  signKey   jwk.Key
  verifyKey jwk.Key
}
```

The first step is to decide on the signature algorithm. Here we will show examples for using `jwa.HS256` and `jwa.RS256`. Choose the appropriate signature for your particular use case. You can find the full list of supported signature algorithms in the documentation or the source code for the [`jwa`](../jwa) package (remember tha there are some [optional algorithms](./global-settings.md#enabling-pptional-signature-methods).


### Using HS256

`jwa.HS256` is a symmetric algorithm, therefore the signing key should be exactly the same as the verifying key.

```go
s.alg = jwa.HS256
s.signKey = jwk.New([]byte("Hello, World!"))
s.verifyKey = s.signKey
```

### Using RS256

In this example we assume that your keys are stored in PEM-encoded files `private-key.pem` and `public-key.pem.

```go
s.alg = jwa.RS256

{
  v, err := jwk.ReadFile(`private-key.pem`, jwk.WithPEM(true))
  if err != nil {
    // handle error
  }
  s.signKey = v
}

{
  v, err := jwk.ReadFile(`public-key.pem`, jwk.WithPEM(true))
  if err != nil {
    // handle error
  }
  s.verifyKey = v
}
```

### Reading JWT

JWTs can be stored in HTTP headers, form values, etc, and you need to decide where to fetch the JWT payload from.

The `jwt` package provides several ways to retrieve JWT data from an HTTP request.
`jwt.ParseRequest` is the most generic front end, and the user will be able to dynamically change where to fetch the data from. By default the "Authorization" header is checked. If you want to check for more places, you can specify it as additional options. Please read the manual for `jwt.ParseRequest` for more details.

The option `jwt.WithKey` is added to validate the JWS message. You will need to execute `jwt.Validate` to validate the content of the JWT message. You can control what gets validated by passing options to `jwt.Validate`. Please read the manual for `jwt.Validate` for more details.

```go
func (s *Server) HandleFoo(w http.ResponseWriter, req *http.Request) {
  token, err := jwt.ParseRequest(req, jwt.WithKey(s.alg, s.verifyKey))
  if err != nil {
    // handle error
  }

  if err := jwt.Validate(token); err != nil {
    // handle error
  }

  // ... additional code ...
}
```

### Writing JWT

In this example we are writing the token to the response body of the response.

```go
func (s *Server) HandleBar(w http.ResponseWriter, req *http.Request) {
  var token jwt.Token

  signed, err := jwt.Sign(token, jwt.WithKey(s.alg, s.signKey))
  if err != nil {
    // handle errors
  }

  w.WriteHeader(http.StatusOK)
  w.Write(signed)
}
```

## JWT with Echo

There is no official middleware, but [a simple port can be found here](https://github.com/lestrrat-go/echo-middleware-jwx)
