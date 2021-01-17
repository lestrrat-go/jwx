package jwx_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"log"
	"time"

	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jwe"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/lestrrat-go/jwx/jws"
	"github.com/lestrrat-go/jwx/jwt"
	"github.com/lestrrat-go/jwx/jwt/openid"
)

func ExampleDecoderSettings() {
	// This has not been enabled in this example, but if you want to
	// parse numbers in the incoming JSON objects as json.Number
	// instead of floats, you can use the following call to globally
	// affect the behavior of JSON parsing.

	// func init() {
	//   jwx.DecoderSettings(jwx.WithUseNumber(true))
	// }
}

func Example_jwt() {
	const aLongLongTimeAgo = 233431200

	t := jwt.New()
	t.Set(jwt.SubjectKey, `https://github.com/lestrrat-go/jwx/jwt`)
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
	if v, ok := t.Get(`privateClaimKey`); ok {
		fmt.Printf("privateClaimKey -> '%s'\n", v)
	}
	fmt.Printf("sub -> '%s'\n", t.Subject())

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Printf("failed to generate private key: %s", err)
		return
	}

	{
		// Signing a token (using raw rsa.PrivateKey)
		signed, err := jwt.Sign(t, jwa.RS256, key)
		if err != nil {
			log.Printf("failed to sign token: %s", err)
			return
		}
		_ = signed
	}

	{
		// Signing a token (using JWK)
		jwkKey, err := jwk.New(key)
		if err != nil {
			log.Printf("failed to create JWK key: %s", err)
			return
		}

		signed, err := jwt.Sign(t, jwa.RS256, jwkKey)
		if err != nil {
			log.Printf("failed to sign token: %s", err)
			return
		}
		_ = signed
	}
	// OUTPUT:
	// {
	//   "aud": [
	//     "Golang Users"
	//   ],
	//   "iat": 233431200,
	//   "privateClaimKey": "Hello, World!",
	//   "sub": "https://github.com/lestrrat-go/jwx/jwt"
	// }
	// aud -> '[Golang Users]'
	// iat -> '1977-05-25T18:00:00Z'
	// privateClaimKey -> 'Hello, World!'
	// sub -> 'https://github.com/lestrrat-go/jwx/jwt'
}

func Example_openid() {
	const aLongLongTimeAgo = 233431200

	t := openid.New()
	t.Set(jwt.SubjectKey, `https://github.com/lestrrat-go/jwx/jwt`)
	t.Set(jwt.AudienceKey, `Golang Users`)
	t.Set(jwt.IssuedAtKey, time.Unix(aLongLongTimeAgo, 0))
	t.Set(`privateClaimKey`, `Hello, World!`)

	addr := openid.NewAddress()
	addr.Set(openid.AddressPostalCodeKey, `105-0011`)
	addr.Set(openid.AddressCountryKey, `日本`)
	addr.Set(openid.AddressRegionKey, `東京都`)
	addr.Set(openid.AddressLocalityKey, `港区`)
	addr.Set(openid.AddressStreetAddressKey, `芝公園 4-2-8`)
	t.Set(openid.AddressKey, addr)

	buf, err := json.MarshalIndent(t, "", "  ")
	if err != nil {
		fmt.Printf("failed to generate JSON: %s\n", err)
		return
	}
	fmt.Printf("%s\n", buf)

	t2, err := jwt.ParseBytes(buf, jwt.WithOpenIDClaims())
	if err != nil {
		fmt.Printf("failed to parse JSON: %s\n", err)
		return
	}
	if _, ok := t2.(openid.Token); !ok {
		fmt.Printf("using jwt.WithOpenIDClaims() creates an openid.Token instance")
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
	//   "sub": "https://github.com/lestrrat-go/jwx/jwt"
	// }
}

func Example_jwk() {
	set, err := jwk.FetchHTTP("https://www.googleapis.com/oauth2/v3/certs")
	if err != nil {
		log.Printf("failed to parse JWK: %s", err)
		return
	}

	// Key sets can be serialized back to JSON
	{
		jsonbuf, err := json.Marshal(set)
		if err != nil {
			log.Printf("failed to marshal key set into JSON: %s", err)
			return
		}
		log.Printf("%s", jsonbuf)
	}

	for it := set.Iterate(context.Background()); it.Next(context.Background()); {
		pair := it.Pair()
		key := pair.Value.(jwk.Key)

		var rawkey interface{} // This is the raw key, like *rsa.PrivateKey or *ecdsa.PrivateKey
		if err := key.Raw(&rawkey); err != nil {
			log.Printf("failed to create public key: %s", err)
			return
		}
		// Use rawkey for jws.Verify() or whatever.
		_ = rawkey

		// You can create jwk.Key from a raw key, too
		fromRawKey, err := jwk.New(rawkey)
		if err != nil {
			log.Printf("failed to acquire raw key from jwk.Key: %s", err)
			return
		}

		// Keys can be serialized back to JSON
		jsonbuf, err := json.Marshal(key)
		if err != nil {
			log.Printf("failed to marshal key into JSON: %s", err)
			return
		}
		log.Printf("%s", jsonbuf)

		// If you know the underlying Key type (RSA, EC, Symmetric), you can
		// create an empty instance first
		//    key := jwk.NewRSAPrivateKey()
		// ..and then use json.Unmarshal
		//    json.Unmarshal(key, jsonbuf)
		//
		// but if you don't know the type first, you have an abstract type
		// jwk.Key, which can't be used as the first argument to json.Unmarshal
		//
		// In this case, use jwk.Parse()
		fromJSONKey, err := jwk.ParseBytes(jsonbuf)
		if err != nil {
			log.Printf("failed to parse json: %s", err)
			return
		}
		_ = fromJSONKey
		_ = fromRawKey
	}
}

func Example_jws() {
	privkey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Printf("failed to generate private key: %s", err)
		return
	}

	buf, err := jws.Sign([]byte("Lorem ipsum"), jwa.RS256, privkey)
	if err != nil {
		log.Printf("failed to created JWS message: %s", err)
		return
	}

	// When you received a JWS message, you can verify the signature
	// and grab the payload sent in the message in one go:
	verified, err := jws.Verify(buf, jwa.RS256, &privkey.PublicKey)
	if err != nil {
		log.Printf("failed to verify message: %s", err)
		return
	}

	log.Printf("signed message verified! -> %s", verified)
}

func Example_jwe() {
	privkey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Printf("failed to generate private key: %s", err)
		return
	}

	payload := []byte("Lorem Ipsum")

	encrypted, err := jwe.Encrypt(payload, jwa.RSA1_5, &privkey.PublicKey, jwa.A128CBC_HS256, jwa.NoCompress)
	if err != nil {
		log.Printf("failed to encrypt payload: %s", err)
		return
	}

	decrypted, err := jwe.Decrypt(encrypted, jwa.RSA1_5, privkey)
	if err != nil {
		log.Printf("failed to decrypt: %s", err)
		return
	}

	if string(decrypted) != "Lorem Ipsum" {
		log.Printf("WHAT?!")
		return
	}
}
