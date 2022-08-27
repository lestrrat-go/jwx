package examples_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"

	"github.com/lestrrat-go/jwx/v2/jwk"
)

func ExampleJWK_Whitelist() {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, `{
  		"keys": [
        {"kty":"EC",
         "crv":"P-256",
         "x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
         "y":"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM",
         "use":"enc",
         "kid":"1"},
        {"kty":"RSA",
         "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
         "e":"AQAB",
         "alg":"RS256",
         "kid":"2011-04-29"}
      ]
    }`)
	}))
	defer srv.Close()

	testcases := []struct {
		Whitelist jwk.Whitelist
		Error     bool
	}{
		// The first two whitelists are meant to prevent access to any other
		// URLs other than www.google.com
		{
			Whitelist: jwk.NewMapWhitelist().Add(`https://www.googleapis.com/oauth2/v3/certs`),
			Error:     true,
		},
		{
			Whitelist: jwk.NewRegexpWhitelist().Add(regexp.MustCompile(`^https://www\.googleapis\.com/`)),
			Error:     true,
		},
		// This whitelist allows anything
		{
			Whitelist: jwk.InsecureWhitelist{},
		},
	}

	for _, tc := range testcases {
		set, err := jwk.Fetch(
			context.Background(),
			srv.URL,
			// This is necessary because httptest.Server is using a custom certificate
			jwk.WithHTTPClient(srv.Client()),
			// Pass the whitelist!
			jwk.WithFetchWhitelist(tc.Whitelist),
		)
		if tc.Error {
			if err == nil {
				fmt.Printf("expected fetch to fail, but got no error\n")
				return
			}
		} else {
			if err != nil {
				fmt.Printf("failed to fetch JWKS: %s\n", err)
				return
			}
			json.NewEncoder(os.Stdout).Encode(set)
		}
	}

	// OUTPUT:
	// {"keys":[{"crv":"P-256","kid":"1","kty":"EC","use":"enc","x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4","y":"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM"},{"alg":"RS256","e":"AQAB","kid":"2011-04-29","kty":"RSA","n":"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw"}]}
}
