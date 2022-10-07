package examples_test

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"log"
	"time"

	"github.com/lestrrat-go/jwx/v2/internal/json"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/lestrrat-go/jwx/v2/jwt/openid"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

const aLongLongTimeAgo = 233431200

const exampleJWTSignedHMAC = `eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk`
const exampleJWTSignedRSA = `eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.cC4hiUPoj9Eetdgtv3hF80EGrhuB__dzERat0XF9g2VtQgr9PJbu3XOiZj5RZmh7AAuHIm4Bh-0Qc_lF5YKt_O8W2Fp5jujGbds9uJdbF9CUAr7t1dnZcAcQjbKBYNX4BAynRFdiuB--f_nZLgrnbyTyWzO75vRK5h6xBArLIARNPvkSjtQBMHlb1L07Qe7K0GarZRmB_eSN9383LcOLn6_dO--xi12jzDwusC-eOkHWEsqtFZESc6BfI7noOPqvhJ1phCnvWh6IeYI2w9QOYEUipUTI8np6LbgGY9Fs98rqVt5AXLIhWkWywlVmtVrBp0igcN_IoypGlUPQGe77Rw`
const exampleJWTSignedECDSA = `eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8ISlSA`

//nolint:govet
func ExampleJWT_ParseWithJWKS() {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		fmt.Printf("failed to generate private key: %s\n", err)
		return
	}

	{
		// Case 2: For whatever reason, we don't have a "kid" specified.
		//   Normally, this is an error, because we don't know how to select a key.
		//   But if we have only one key in the KeySet, you can explicitly ask
		//   jwt.Parse to "trust" the KeySet, and use the single key in the
		//   key set. It would be an error if you have multiple keys in the KeySet.

		var payload []byte
		var keyset jwk.Set
		{ // Preparation:
			// Unlike our previous example, we DO NOT want to sign the payload.
			// Therefore we do NOT set the "kid" value
			realKey, err := jwk.FromRaw(privKey)
			if err != nil {
				fmt.Printf("failed to create JWK: %s\n", err)
				return
			}

			// Create the token
			token := jwt.New()
			token.Set(`foo`, `bar`)

			// Sign the token and generate a payload
			signed, err := jwt.Sign(token, jwt.WithKey(jwa.RS256, realKey))
			if err != nil {
				fmt.Printf("failed to generate signed payload: %s\n", err)
				return
			}

			// This is what you typically get as a signed JWT from a server
			payload = signed

			// Now create a key set that users will use to verity the signed payload against
			// Normally these keys are available somewhere like https://www.googleapis.com/oauth2/v3/certs
			pubKey, err := jwk.FromRaw(privKey.PublicKey)
			if err != nil {
				fmt.Printf("failed to create JWK: %s\n", err)
				return
			}
			pubKey.Set(jwk.AlgorithmKey, jwa.RS256)

			// This JWKS can *only* have 1 key.
			keyset = jwk.NewSet()
			keyset.AddKey(pubKey)
		}

		{
			token, err := jwt.Parse(
				payload,
				// Tell the parser that you want to use this keyset
				jwt.WithKeySet(keyset,
					// Tell the parser that you can trust this KeySet, and that
					// you want to use the sole key in it
					jws.WithUseDefault(true),
				),
			)
			if err != nil {
				fmt.Printf("failed to parse payload: %s\n", err)
			}
			_ = token
		}
	}

	// OUTPUT:
}

// This example return a signed jwt
func ExampleJWT_Sign_WithImportJWK() {

	// your JWK
	jwkStr := `{
		"kty": "RSA",
		"n": "mmO0OvOPQ53HRxV4eHOkTTxLVfk6zcq8KAD86gbnydYBNO_Si4Q1twyvefd58-BaO4N4NCEA97QrYm57ThKCe8agLGwWPHhxgbu_SAuYQehXxkf4sWy7Q17kGFG5k5AfQGZBqTY-YaawQqLlF6ILVbWab_AoEF4yB7pI3AnNnXs",
		"e": "AQAB",
		"d": "RzsrI2vONJcuIyjPzVslehEQfRkhPWOFTjuudNc8yA25vs_LZ11XXx42M-KvXIqtdvngUsTLan2w6pgowcuecX3t_2wUx0GJJgARfkN7gsWIS3CyXZBEEMjLGVU4vHt5zNE3GJKo3hb1TwEiulpL_Ix6hfcTSJpEaBWrBxjxV-E",
		"p": "5EA0bi6ui1H1wsG85oc7i9O7UH58WPIK_ytzBWXFIwcaSFFBqqNYNnZaHFsMe4cbHSBgShWHO3UueGVgOKmB8Q",
		"q": "rSi7CosQZmj_RFIYW10ef7XTZsdpIdOXV9-1dThAJUvkslKiTfdU7T0IYYsJ2K58ekJqdpcoKAVLB2SZVvdqKw",
		"dp": "S9yjEHPng1qsShzGQgB0ZBbtTOWdQpq_2OuCAStACFJWA-8t2h8MNJ3FeWMxlOTkuBuIpVbeaX6bAV0ATBTaoQ",
		"dq": "ZssMJhkh1jm0d-FoVix0Y4oUAiqUzaDnciH6faiz47AnBnkporEV-HPH2ugII1qJyKZOvzHCg-eIf84HfWoI2w",
		"qi": "lyVz1HI2b1IjzOMENkmUTaVEO6DM6usZi3c3_MobUUM05yyBhnHtPjWzqWn1uJ_Gt5bkJDdcpfvmkPAhKWEU9Q"
	}`

	// create a new jwt
	t := jwt.New()
	t.Set(jwt.SubjectKey, `https://github.com/lestrrat-go/jwx/v2/jwt`)
	t.Set(jwt.AudienceKey, `Golang Users`)
	t.Set(jwt.IssuedAtKey, time.Unix(500, 0))
	t.Set(`privateClaimKey`, `foobar`)

	buf, err := json.MarshalIndent(t, "", "  ")
	if err != nil {
		fmt.Printf("failed to generate JSON: %s\n", err)
		return
	}

	fmt.Printf("%s\n", buf)

	var pc string
	if err := t.Get(`privateClaimKey`, &pc); err == nil {
		fmt.Printf("privateClaimKey -> '%s'\n", pc)
	}

	//convert jwk in bytes and return a new key
	jwkey, err := jwk.ParseKey([]byte(jwkStr))

	if err != nil {
		log.Fatal("erro")
	}

	// signed and return a jwt
	signed, _ := jwt.Sign(t, jwt.WithKey(jwa.RS256, jwkey))

	fmt.Println(string(signed[:]))

	// output
	// a signed jwt based on jwk
}

func ExampleJWT_Sign() {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		fmt.Printf("failed to generate private key: %s\n", err)
		return
	}

	var payload []byte
	{ // Create signed payload
		token := jwt.New()
		token.Set(`foo`, `bar`)
		payload, err = jwt.Sign(token, jwt.WithKey(jwa.RS256, privKey))
		if err != nil {
			fmt.Printf("failed to generate signed payload: %s\n", err)
			return
		}
	}

	{ // Parse signed payload, and perform (1) verification of the signature
		// and (2) validation of the JWT token
		// Validation can be performed in a separate step using `jwt.Validate`
		token, err := jwt.Parse(
			payload,
			jwt.WithValidate(true),
			jwt.WithKey(jwa.RS256, &privKey.PublicKey),
		)
		if err != nil {
			fmt.Printf("failed to parse JWT token: %s\n", err)
			return
		}
		buf, err := json.MarshalIndent(token, "", "  ")
		if err != nil {
			fmt.Printf("failed to generate JSON: %s\n", err)
			return
		}
		fmt.Printf("%s\n", buf)
	}
	// OUTPUT:
	// {
	//   "foo": "bar"
	// }
}

func ExampleJWT_Token() {
	t := jwt.New()
	t.Set(jwt.SubjectKey, `https://github.com/lestrrat-go/jwx/v2/jwt`)
	t.Set(jwt.AudienceKey, `Golang Users`)
	t.Set(jwt.IssuedAtKey, time.Unix(aLongLongTimeAgo, 0))
	t.Set(`privateClaimKey`, `Hello, World!`)

	buf, err := json.MarshalIndent(t, "", "  ")
	if err != nil {
		fmt.Printf("failed to generate JSON: %s\n", err)
		return
	}

	fmt.Printf("%s\n", buf)
	fmt.Printf("aud -> '%s'\n", t.Audience())
	fmt.Printf("iat -> '%s'\n", t.IssuedAt().Format(time.RFC3339))
	var pc string
	if err := t.Get(`privateClaimKey`, &pc); err == nil {
		fmt.Printf("privateClaimKey -> '%s'\n", pc)
	}
	fmt.Printf("sub -> '%s'\n", t.Subject())

	// OUTPUT:
	// {
	//   "aud": [
	//     "Golang Users"
	//   ],
	//   "iat": 233431200,
	//   "privateClaimKey": "Hello, World!",
	//   "sub": "https://github.com/lestrrat-go/jwx/v2/jwt"
	// }
	// aud -> '[Golang Users]'
	// iat -> '1977-05-25T18:00:00Z'
	// privateClaimKey -> 'Hello, World!'
	// sub -> 'https://github.com/lestrrat-go/jwx/v2/jwt'
}

func ExampleJWT_SignToken() {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Printf("failed to generate private key: %s", err)
		return
	}

	t := jwt.New()

	{
		// Signing a token (using raw rsa.PrivateKey)
		signed, err := jwt.Sign(t, jwt.WithKey(jwa.RS256, key))
		if err != nil {
			log.Printf("failed to sign token: %s", err)
			return
		}
		_ = signed
	}

	{
		// Signing a token (using JWK)
		jwkKey, err := jwk.FromRaw(key)
		if err != nil {
			log.Printf("failed to create JWK key: %s", err)
			return
		}

		signed, err := jwt.Sign(t, jwt.WithKey(jwa.RS256, jwkKey))
		if err != nil {
			log.Printf("failed to sign token: %s", err)
			return
		}
		_ = signed
	}

	// OUTPUT:
}

func ExampleJWT_OpenIDToken() {
	t := openid.New()
	t.Set(jwt.SubjectKey, `https://github.com/lestrrat-go/jwx/v2/jwt`)
	t.Set(jwt.AudienceKey, `Golang Users`)
	t.Set(jwt.IssuedAtKey, time.Unix(aLongLongTimeAgo, 0))
	t.Set(`privateClaimKey`, `Hello, World!`)

	addr := openid.NewAddress()
	addr.Set(openid.AddressPostalCodeKey, `105-0011`)
	addr.Set(openid.AddressCountryKey, `日本`)
	addr.Set(openid.AddressRegionKey, `東京都`)
	addr.Set(openid.AddressLocalityKey, `港区`)
	addr.Set(openid.AddressStreetAddressKey, `芝公園 4-2-8`)
	if err := t.Set(openid.AddressKey, addr); err != nil {
		fmt.Printf("failed to set address: %s\n", err)
		return
	}

	buf, err := json.MarshalIndent(t, "", "  ")
	if err != nil {
		fmt.Printf("failed to generate JSON: %s\n", err)
		return
	}
	fmt.Printf("%s\n", buf)

	t2, err := jwt.Parse(buf, jwt.WithToken(openid.New()), jwt.WithVerify(false), jwt.WithValidate(false))
	if err != nil {
		fmt.Printf("failed to parse JSON: %s\n", err)
		return
	}
	if _, ok := t2.(openid.Token); !ok {
		fmt.Printf("using jwt.WithToken(openid.New()) creates an openid.Token instance")
		return
	}
	// OUTPUT:
	// {
	//   "address": {
	//     "country": "日本",
	//     "locality": "港区",
	//     "postal_code": "105-0011",
	//     "region": "東京都",
	//     "street_address": "芝公園 4-2-8"
	//   },
	//   "aud": [
	//     "Golang Users"
	//   ],
	//   "iat": 233431200,
	//   "privateClaimKey": "Hello, World!",
	//   "sub": "https://github.com/lestrrat-go/jwx/v2/jwt"
	// }
}
