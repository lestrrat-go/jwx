package examples_test

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

func ExampleJWT_ParseWithJKU() {
	set := jwk.NewSet()

	var signingKey jwk.Key

	// for _, alg := range algorithms {
	for i := 0; i < 3; i++ {
		pk, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			fmt.Printf("failed to generate private key: %s\n", err)
			return
		}
		// too lazy to write a proper algorithm. just assign every
		// time, and signingKey will end up being the last key generated
		privkey, err := jwk.New(pk)
		if err != nil {
			fmt.Printf("failed to create jwk.Key: %s\n", err)
			return
		}
		privkey.Set(jwk.KeyIDKey, fmt.Sprintf(`key-%d`, i))

		// It is important that we are using jwk.Key here instead of
		// rsa.PrivateKey, because this way `kid` is automatically
		// assigned when we sign the token
		signingKey = privkey

		pubkey, err := privkey.PublicKey()
		if err != nil {
			fmt.Printf("failed to create public key: %s\n", err)
			return
		}
		set.Add(pubkey)
	}

	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(set)
	}))
	defer srv.Close()

	// Create a JWT
	token := jwt.New()
	token.Set(`foo`, `bar`)

	hdrs := jws.NewHeaders()
	hdrs.Set(jws.JWKSetURLKey, srv.URL)

	serialized, err := jwt.Sign(token, jwt.WithKey(jwa.RS256, signingKey, jws.WithProtectedHeaders(hdrs)))
	if err != nil {
		fmt.Printf("failed to seign token: %s\n", err)
		return
	}

	// We need to pass jwk.WithHTTPClient because we are using HTTPS,
	// and we need the certificates setup
	// We also need to explicitly setup the whitelist, this is required
	tok, err := jwt.Parse(serialized, jwt.WithVerifyAuto(nil, jwk.WithHTTPClient(srv.Client()), jwk.WithFetchWhitelist(jwk.InsecureWhitelist{})))
	if err != nil {
		fmt.Printf("failed to verify token: %s\n", err)
		return
	}
	_ = tok
	// OUTPUT:
}
