package examples_test

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"log"

	"github.com/lestrrat-go/jwx/v2/internal/base64"
	"github.com/lestrrat-go/jwx/v2/internal/json"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jws"
)

func ExampleJWS_VerifyWithJWKSet() {
	// Setup payload first...
	privkey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Printf("failed to create private key: %s", err)
		return
	}
	const payload = "Lorem ipsum"
	signed, err := jws.Sign([]byte(payload), jws.WithKey(jwa.RS256, privkey))
	if err != nil {
		log.Printf("failed to sign payload: %s", err)
		return
	}

	// Create a JWK Set
	set := jwk.NewSet()
	// Add some bogus keys
	k1, _ := jwk.New([]byte("abracadavra"))
	set.Add(k1)
	k2, _ := jwk.New([]byte("opensasame"))
	set.Add(k2)
	// Add the real thing
	pubkey, _ := jwk.PublicRawKeyOf(privkey)
	k3, _ := jwk.New(pubkey)
	k3.Set(jwk.AlgorithmKey, jwa.RS256)
	set.Add(k3)

	// Up to this point, you probably will replace with a simple jwk.Fetch()

	// Now verify using the set.
	if _, err := jws.Verify(signed, jws.WithKeySet(set)); err != nil {
		fmt.Printf("Failed to verify using jwk.Set!: %s", err)
	}

	// OUTPUT:
}

func ExampleJWS_Message() {
	const payload = `eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ`
	const encodedSig1 = `cC4hiUPoj9Eetdgtv3hF80EGrhuB__dzERat0XF9g2VtQgr9PJbu3XOiZj5RZmh7AAuHIm4Bh-0Qc_lF5YKt_O8W2Fp5jujGbds9uJdbF9CUAr7t1dnZcAcQjbKBYNX4BAynRFdiuB--f_nZLgrnbyTyWzO75vRK5h6xBArLIARNPvkSjtQBMHlb1L07Qe7K0GarZRmB_eSN9383LcOLn6_dO--xi12jzDwusC-eOkHWEsqtFZESc6BfI7noOPqvhJ1phCnvWh6IeYI2w9QOYEUipUTI8np6LbgGY9Fs98rqVt5AXLIhWkWywlVmtVrBp0igcN_IoypGlUPQGe77Rw`
	const encodedSig2 = "DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8ISlSApmWQxfKTUJqPP3-Kg6NU1Q"

	decodedPayload, err := base64.DecodeString(payload)
	if err != nil {
		fmt.Printf("%s\n", err)
		return
	}

	decodedSig1, err := base64.DecodeString(encodedSig1)
	if err != nil {
		fmt.Printf("%s\n", err)
		return
	}

	decodedSig2, err := base64.DecodeString(encodedSig2)
	if err != nil {
		fmt.Printf("%s\n", err)
		return
	}

	public1 := jws.NewHeaders()
	_ = public1.Set(jws.AlgorithmKey, jwa.RS256)
	protected1 := jws.NewHeaders()
	_ = protected1.Set(jws.KeyIDKey, "2010-12-29")

	public2 := jws.NewHeaders()
	_ = public2.Set(jws.AlgorithmKey, jwa.ES256)
	protected2 := jws.NewHeaders()
	_ = protected2.Set(jws.KeyIDKey, "e9bc097a-ce51-4036-9562-d2ade882db0d")

	// Construct a message. DO NOT use values that are base64 encoded
	m := jws.NewMessage().
		SetPayload(decodedPayload).
		AppendSignature(
			jws.NewSignature().
				SetSignature(decodedSig1).
				SetProtectedHeaders(public1).
				SetPublicHeaders(protected1),
		).
		AppendSignature(
			jws.NewSignature().
				SetSignature(decodedSig2).
				SetProtectedHeaders(public2).
				SetPublicHeaders(protected2),
		)

	buf, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		fmt.Printf("%s\n", err)
		return
	}

	fmt.Printf("%s", buf)
	// OUTPUT:
	// {
	//   "payload": "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ",
	//   "signatures": [
	//     {
	//       "header": {
	//         "kid": "2010-12-29"
	//       },
	//       "protected": "eyJhbGciOiJSUzI1NiJ9",
	//       "signature": "cC4hiUPoj9Eetdgtv3hF80EGrhuB__dzERat0XF9g2VtQgr9PJbu3XOiZj5RZmh7AAuHIm4Bh-0Qc_lF5YKt_O8W2Fp5jujGbds9uJdbF9CUAr7t1dnZcAcQjbKBYNX4BAynRFdiuB--f_nZLgrnbyTyWzO75vRK5h6xBArLIARNPvkSjtQBMHlb1L07Qe7K0GarZRmB_eSN9383LcOLn6_dO--xi12jzDwusC-eOkHWEsqtFZESc6BfI7noOPqvhJ1phCnvWh6IeYI2w9QOYEUipUTI8np6LbgGY9Fs98rqVt5AXLIhWkWywlVmtVrBp0igcN_IoypGlUPQGe77Rw"
	//     },
	//     {
	//       "header": {
	//         "kid": "e9bc097a-ce51-4036-9562-d2ade882db0d"
	//       },
	//       "protected": "eyJhbGciOiJFUzI1NiJ9",
	//       "signature": "DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8ISlSApmWQxfKTUJqPP3-Kg6NU1Q"
	//     }
	//   ]
	// }
}
