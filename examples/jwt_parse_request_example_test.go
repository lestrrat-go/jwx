package examples_test

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/lestrrat-go/jwx/v2/jwt"
)

func ExampleJWT_ParseRequest_Authorization() {
	values := url.Values{
		`access_token`: []string{exampleJWTSignedHMAC},
	}

	req, err := http.NewRequest(http.MethodGet, `https://github.com/lestrrat-go/jwx`, strings.NewReader(values.Encode()))
	if err != nil {
		fmt.Printf("failed to create request: %s\n", err)
		return
	}

	req.Header.Set(`Authorization`, fmt.Sprintf(`Bearer %s`, exampleJWTSignedECDSA))
	req.Header.Set(`X-JWT-Token`, exampleJWTSignedRSA)

	testcases := []struct {
		options []jwt.ParseOption
	}{
		// No options - looks under "Authorization" header
		{},
		// Looks under "X-JWT-Token" header only
		{
			options: []jwt.ParseOption{jwt.WithHeaderKey(`X-JWT-Token`)},
		},
		// Looks under "Authorization" and "X-JWT-Token" headers
		{
			options: []jwt.ParseOption{jwt.WithHeaderKey(`Authorization`), jwt.WithHeaderKey(`X-JWT-Token`)},
		},
		// Looks under "Authorization" header and "access_token" form field
		{
			options: []jwt.ParseOption{jwt.WithFormKey(`access_token`)},
		},
	}

	for _, tc := range testcases {
		// Note: this JWT has NOT been verified because we have not
		// passed jwt.WithKey() et al. You need to pass these values
		// if you want the token to be parsed and verified in one go
		tok, err := jwt.ParseRequest(req, tc.options...)
		if err != nil {
			fmt.Printf("jwt.ParseRequest with options %#v failed: %s\n", tc.options, err)
			return
		}
		_ = tok
	}
	// OUTPUT:
}
