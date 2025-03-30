package examples_test

import (
	"bytes"
	"encoding/base64"
	"fmt"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jws"
)

func Example_jws_sign_with_custom_base64() {
	const payload = "Lorem ipsum"
	const symmetricKey = "0123456789abcdef0123456789abcdef"

	signed, err := jws.Sign([]byte(payload), jws.WithKey(jwa.HS256(), []byte(symmetricKey)), jws.WithBase64Encoder(base64.URLEncoding))
	if err != nil {
		fmt.Printf("failed to sign payload: %s\n", err)
	}

	fmt.Println(string(signed))

	// This should fail because we're using a different base64 encoder
	if _, err := jws.Verify(signed, jws.WithKey(jwa.HS256(), []byte(symmetricKey))); err == nil {
		fmt.Printf("verification should have failed, but succeeded\n")
		return
	}

	verified, err := jws.Verify(signed, jws.WithKey(jwa.HS256(), []byte(symmetricKey)), jws.WithBase64Encoder(base64.URLEncoding))
	if err != nil {
		fmt.Printf("failed to verify payload: %s\n", err)
		return
	}

	if !bytes.Equal([]byte(payload), verified) {
		fmt.Printf("verified content do not match: %s\n", err)
		return
	}
	// OUTPUT:
	// eyJhbGciOiJIUzI1NiJ9.TG9yZW0gaXBzdW0=.DahnsWNiVXmt23d2nUx_ePAZLy2nodC-Oh0bIB88cck=
}
