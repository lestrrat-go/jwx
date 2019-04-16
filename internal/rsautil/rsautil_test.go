package rsautil

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"reflect"
	"testing"
)

func TestRSAUtil(t *testing.T) {

	t.Run("RoundTripNewRawKeyFromPrivateKey", func(t *testing.T) {

		privateKey, err := rsa.GenerateKey(rand.Reader, 512)
		if err != nil {
			t.Fatalf("Error generating private key: %s", err.Error())
		}
		rawKey := NewRawKeyFromPrivateKey(privateKey)
		keyBytes, err := json.Marshal(rawKey)
		realizedPrivateKey, err := PrivateKeyFromJSON(keyBytes)
		if !reflect.DeepEqual(realizedPrivateKey, privateKey) {
			t.Fatalf("Mismatched private keys")
		}
	})

	t.Run("PublicKeyFromJSON", func(t *testing.T) {
		const jwkPublicKey = `{
      "e":"AQAB",
			"kty":"RSA",
      "n":"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw"
		}`

		const expectedPEM = `-----BEGIN PUBLIC KEY-----
MIIBCgKCAQEA0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4
cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc/BJECPebWKRXjBZCiFV4n3oknjhMst
n64tZ/2W+5JsGY4Hc5n9yBXArwl93lqt7/RN5w6Cf0h4QyQ5v+65YGjQR0/FDW2Q
vzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbIS
D08qNLyrdkt+bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ+G/xBniIqbw
0Ls1jF44+csFCur+kEgU8awapJzKnqDKgwIDAQAB
-----END PUBLIC KEY-----
`

		publicKey := []byte(jwkPublicKey)
		rsaPublicKey, err := PublicKeyFromJSON(publicKey)
		if err != nil {
			t.Fatalf("Failed to construct RSA public key from JSON: %s", err.Error())
		}
		publicKeyBytes := x509.MarshalPKCS1PublicKey(rsaPublicKey)
		pemBlock := &pem.Block{Type: "PUBLIC KEY", Bytes: publicKeyBytes}
		realizedPublicKeyPem := pem.EncodeToMemory(pemBlock)
		if !reflect.DeepEqual(realizedPublicKeyPem, []byte(expectedPEM)) {
			t.Fatal("Mismatched public keys")
		}
	})

}
