package examples_test

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"time"

	"github.com/lestrrat-go/jwx/v2/internal/json"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

var payloadLoremIpsum []byte
var jwtSignedWithHS256 []byte
var rawRSAPrivateKey *rsa.PrivateKey
var rawRSAPublicKey *rsa.PublicKey
var jwkRSAPrivateKey jwk.Key
var jwkRSAPublicKey jwk.Key
var jwkSymmetricKey jwk.Key
var jsonRSAPrivateKey []byte
var jsonRSAPublicKey []byte

func init() {
	if err := Setup(); err != nil {
		panic(err.Error())
	}
}

// Create some variables that would be repeatedly used in the examples
func Setup() error {
	payloadLoremIpsum = []byte(`Lorem ipsum`)

	tok, err := jwt.NewBuilder().
		Issuer(`github.com/lestrrat-go/jwx`).
		IssuedAt(time.Now().Add(-5 * time.Minute)).
		Expiration(time.Now().Add(time.Hour)).
		Build()
	if err != nil {
		return fmt.Errorf(`failed to build token: %w`, err)
	}

	{
		v, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return fmt.Errorf(`failed to create RSA private key: %w`, err)
		}

		rawRSAPrivateKey = v
		rawRSAPublicKey = &v.PublicKey
	}

	{
		v, err := jwk.FromRaw(rawRSAPrivateKey)
		if err != nil {
			return fmt.Errorf(`failed to create jwk.Key from RSA private key: %w`, err)
		}
		jwkRSAPrivateKey = v
	}

	{
		v, err := json.Marshal(jwkRSAPrivateKey)
		if err != nil {
			return fmt.Errorf(`failed to marshal RSA private jwk.Key: %w`, err)
		}
		jsonRSAPrivateKey = v
	}

	{
		v, err := jwk.FromRaw(rawRSAPublicKey)
		if err != nil {
			return fmt.Errorf(`failed to create jwk.Key from RSA public key: %w`, err)
		}
		jwkRSAPublicKey = v
	}

	{
		v, err := json.Marshal(jwkRSAPublicKey)
		if err != nil {
			return fmt.Errorf(`failed to marshal RSA public jwk.Key: %w`, err)
		}
		jsonRSAPublicKey = v
	}

	{
		v, err := jwk.FromRaw([]byte(`abracadabra`))
		if err != nil {
			return fmt.Errorf(`failed to create jwk.Key from symmetric key: %w`, err)
		}
		jwkSymmetricKey = v
	}

	{
		v, err := jwt.Sign(tok, jwt.WithKey(jwa.HS256, jwkSymmetricKey))
		if err != nil {
			return fmt.Errorf(`failed to sign token with HS256: %w`, err)
		}
		jwtSignedWithHS256 = v
	}

	return nil
}
