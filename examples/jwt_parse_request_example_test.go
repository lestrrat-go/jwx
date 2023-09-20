package examples_test

import (
	"fmt"
	"net/http"
	"net/url"

	"github.com/lestrrat-go/jwx/v3/jwt"
)

func ExampleJWT_ParseRequest_Authorization() {
	req, err := http.NewRequest(http.MethodGet, `https://github.com/lestrrat-go/jwx`, nil)
	if err != nil {
		fmt.Printf("failed to create request: %s\n", err)
		return
	}
	req.Form = url.Values{}
	req.Form.Add("access_token", exampleJWTSignedHMAC)

	req.Header.Set(`Authorization`, fmt.Sprintf(`Bearer %s`, exampleJWTSignedECDSA))
	req.Header.Set(`X-JWT-Token`, exampleJWTSignedRSA)

	req.AddCookie(&http.Cookie{Name: "accessToken", Value: exampleJWTSignedHMAC})

	var dst *http.Cookie

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
		// Looks under "accessToken" cookie, and assigns the http.Cookie object
		// where the token came from to the variable `dst`
		{
			options: []jwt.ParseOption{jwt.WithCookieKey(`accessToken`), jwt.WithCookie(&dst)},
		},
	}

	for _, tc := range testcases {
		options := append(tc.options, []jwt.ParseOption{jwt.WithVerify(false), jwt.WithValidate(false)}...)
		tok, err := jwt.ParseRequest(req, options...)
		if err != nil {
			fmt.Print("jwt.ParseRequest with options [")
			for i, option := range tc.options {
				if i > 0 {
					fmt.Print(", ")
				}
				fmt.Printf("%s", option)
			}
			fmt.Printf("]: %s\n", err)
			return
		}
		_ = tok
	}

	if dst == nil {
		fmt.Printf("failed to assign cookie to dst\n")
		return
	}
	// OUTPUT:
}
