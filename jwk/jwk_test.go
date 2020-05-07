package jwk_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"reflect"
	"testing"

	"github.com/lestrrat-go/jwx/jwk"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
)

func TestNew(t *testing.T) {
	k, err := jwk.New(nil)
	if !assert.Nil(t, k, "key should be nil") {
		return
	}
	if !assert.Error(t, err, "nil key should cause an error") {
		return
	}
}

func TestParse(t *testing.T) {
	verify := func(t *testing.T, src string, expected reflect.Type) {
		t.Helper()
		t.Run("json.Unmarshal", func(t *testing.T) {
			var set jwk.Set
			if err := json.Unmarshal([]byte(src), &set); !assert.NoError(t, err, `json.Unmarshal should succeed`) {
				return
			}

			if !assert.True(t, len(set.Keys) > 0, "set.Keys should be greater than 0") {
				return
			}
			for _, key := range set.Keys {
				if !assert.True(t, reflect.TypeOf(key).AssignableTo(expected), "key should be a %s", expected) {
					return
				}
			}
		})
		t.Run("jwk.Parse", func(t *testing.T) {
			t.Helper()
			set, err := jwk.ParseBytes([]byte(`{"keys":[` + src + `]}`))
			if !assert.NoError(t, err, `jwk.Parse should succeed`) {
				return
			}

			if !assert.True(t, set.Len() > 0, "set.Len should be greater than 0") {
				return
			}

			for iter := set.Iterate(context.TODO()); iter.Next(context.TODO()); {
				pair := iter.Pair()
				key := pair.Value.(jwk.Key)

				switch key := key.(type) {
				case jwk.RSAPrivateKey, jwk.ECDSAPrivateKey, jwk.RSAPublicKey, jwk.ECDSAPublicKey, jwk.SymmetricKey:
				default:
					assert.Fail(t, fmt.Sprintf("invalid type: %T", key))
				}
			}
		})
	}

	t.Run("RSA Public Key", func(t *testing.T) {
		const src = `{
      "e":"AQAB",
			"kty":"RSA",
      "n":"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw"
		}`
		verify(t, src, reflect.TypeOf((*jwk.RSAPublicKey)(nil)).Elem())
	})
	t.Run("RSA Private Key", func(t *testing.T) {
		const src = `{
      "kty":"RSA",
      "n":"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
      "e":"AQAB",
      "d":"X4cTteJY_gn4FYPsXB8rdXix5vwsg1FLN5E3EaG6RJoVH-HLLKD9M7dx5oo7GURknchnrRweUkC7hT5fJLM0WbFAKNLWY2vv7B6NqXSzUvxT0_YSfqijwp3RTzlBaCxWp4doFk5N2o8Gy_nHNKroADIkJ46pRUohsXywbReAdYaMwFs9tv8d_cPVY3i07a3t8MN6TNwm0dSawm9v47UiCl3Sk5ZiG7xojPLu4sbg1U2jx4IBTNBznbJSzFHK66jT8bgkuqsk0GjskDJk19Z4qwjwbsnn4j2WBii3RL-Us2lGVkY8fkFzme1z0HbIkfz0Y6mqnOYtqc0X4jfcKoAC8Q",
      "p":"83i-7IvMGXoMXCskv73TKr8637FiO7Z27zv8oj6pbWUQyLPQBQxtPVnwD20R-60eTDmD2ujnMt5PoqMrm8RfmNhVWDtjjMmCMjOpSXicFHj7XOuVIYQyqVWlWEh6dN36GVZYk93N8Bc9vY41xy8B9RzzOGVQzXvNEvn7O0nVbfs",
      "q":"3dfOR9cuYq-0S-mkFLzgItgMEfFzB2q3hWehMuG0oCuqnb3vobLyumqjVZQO1dIrdwgTnCdpYzBcOfW5r370AFXjiWft_NGEiovonizhKpo9VVS78TzFgxkIdrecRezsZ-1kYd_s1qDbxtkDEgfAITAG9LUnADun4vIcb6yelxk",
      "dp":"G4sPXkc6Ya9y8oJW9_ILj4xuppu0lzi_H7VTkS8xj5SdX3coE0oimYwxIi2emTAue0UOa5dpgFGyBJ4c8tQ2VF402XRugKDTP8akYhFo5tAA77Qe_NmtuYZc3C3m3I24G2GvR5sSDxUyAN2zq8Lfn9EUms6rY3Ob8YeiKkTiBj0",
      "dq":"s9lAH9fggBsoFR8Oac2R_E2gw282rT2kGOAhvIllETE1efrA6huUUvMfBcMpn8lqeW6vzznYY5SSQF7pMdC_agI3nG8Ibp1BUb0JUiraRNqUfLhcQb_d9GF4Dh7e74WbRsobRonujTYN1xCaP6TO61jvWrX-L18txXw494Q_cgk",
      "qi":"GyM_p6JrXySiz1toFgKbWV-JdI3jQ4ypu9rbMWx3rQJBfmt0FoYzgUIZEVFEcOqwemRN81zoDAaa-Bk0KWNGDjJHZDdDmFhW3AN7lI-puxk_mHZGJ11rxyR8O55XLSe3SPmRfKwZI6yU24ZxvQKFYItdldUKGzO6Ia6zTKhAVRU",
      "alg":"RS256",
      "kid":"2011-04-29"
     }`
		verify(t, src, reflect.TypeOf((*jwk.RSAPrivateKey)(nil)).Elem())
	})
	t.Run("ECDSA Private Key", func(t *testing.T) {
		const src = `{
		  "kty" : "EC",
		  "crv" : "P-256",
		  "x"   : "SVqB4JcUD6lsfvqMr-OKUNUphdNn64Eay60978ZlL74",
		  "y"   : "lf0u0pMj4lGAzZix5u4Cm5CMQIgMNpkwy163wtKYVKI",
		  "d"   : "0g5vAEKzugrXaRbgKG0Tj2qJ5lMP4Bezds1_sTybkfk"
		}`
		verify(t, src, reflect.TypeOf((*jwk.ECDSAPrivateKey)(nil)).Elem())
	})
	t.Run("Invalid ECDSA Private Key", func(t *testing.T) {
		const src = `{
		  "kty" : "EC",
		  "crv" : "P-256",
		  "y"   : "lf0u0pMj4lGAzZix5u4Cm5CMQIgMNpkwy163wtKYVKI",
		  "d"   : "0g5vAEKzugrXaRbgKG0Tj2qJ5lMP4Bezds1_sTybkfk"
		}`
		_, err := jwk.ParseString(src)
		if !assert.Error(t, err, `jwk.ParseString should fail`) {
			return
		}
	})
}

func generateRawRSAPrivateKey() (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(rand.Reader, 2048)
}

func generateRSAPrivateKey() (jwk.Key, error) {
	key, err := generateRawRSAPrivateKey()

	if err != nil {
		return nil, errors.Wrap(err, `failed to generate RSA private key`)
	}

	k, err := jwk.New(key)
	if err != nil {
		return nil, errors.Wrap(err, `failed to generate jwk.RSAPrivateKey`)
	}

	return k, nil
}

func generateRSAPublicKey() (jwk.Key, error) {
	k, err := generateRSAPrivateKey()
	if err != nil {
		return nil, err
	}

	return k.(jwk.RSAPrivateKey).PublicKey()
}

func generateRawECDSAPrivateKey() (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
}

func generateECDSAPrivateKey() (jwk.Key, error) {
	key, err := generateRawECDSAPrivateKey()
	if err != nil {
		return nil, errors.Wrap(err, `failed to generate ECDSA private key`)
	}

	k, err := jwk.New(key)
	if err != nil {
		return nil, errors.Wrap(err, `failed to generate jwk.ECDSAPrivateKey`)
	}

	return k, nil
}

func generateECDSAPublicKey() (jwk.Key, error) {
	k, err := generateECDSAPrivateKey()
	if err != nil {
		return nil, err
	}

	return k.(jwk.ECDSAPrivateKey).PublicKey()
}

func generateRawSymmetricKey() []byte {
	sharedKey := make([]byte, 64)
	rand.Read(sharedKey)
	return sharedKey
}

func generateSymmetricKey() (jwk.Key, error) {
	key, err := jwk.New(generateRawSymmetricKey())
	if err != nil {
		return nil, errors.Wrap(err, `failed to generate jwk.SymmetricKey`)
	}

	return key, nil
}

func TestRoundtrip(t *testing.T) {
	generateRSA := func(use string, keyID string) (jwk.Key, error) {
		k, err := generateRSAPrivateKey()
		if err != nil {
			return nil, err
		}

		k.Set(jwk.KeyUsageKey, use)
		k.Set(jwk.KeyIDKey, keyID)
		return k, nil
	}

	generateECDSA := func(use, keyID string) (jwk.Key, error) {
		k, err := generateECDSAPrivateKey()
		if err != nil {
			return nil, err
		}

		k.Set(jwk.KeyUsageKey, use)
		k.Set(jwk.KeyIDKey, keyID)
		return k, nil
	}

	generateSymmetric := func(use, keyID string) (jwk.Key, error) {
		k, err := generateSymmetricKey()
		if err != nil {
			return nil, err
		}

		k.Set(jwk.KeyUsageKey, use)
		k.Set(jwk.KeyIDKey, keyID)
		return k, nil
	}

	tests := []struct {
		use      string
		keyID    string
		generate func(string, string) (jwk.Key, error)
	}{
		{
			use:      "enc",
			keyID:    "enc1",
			generate: generateRSA,
		},
		{
			use:      "enc",
			keyID:    "enc2",
			generate: generateRSA,
		},
		{
			use:      "sig",
			keyID:    "sig1",
			generate: generateRSA,
		},
		{
			use:      "sig",
			keyID:    "sig2",
			generate: generateRSA,
		},
		{
			use:      "sig",
			keyID:    "sig3",
			generate: generateSymmetric,
		},
		{
			use:      "enc",
			keyID:    "enc4",
			generate: generateECDSA,
		},
		{
			use:      "enc",
			keyID:    "enc5",
			generate: generateECDSA,
		},
		{
			use:      "sig",
			keyID:    "sig4",
			generate: generateECDSA,
		},
		{
			use:      "sig",
			keyID:    "sig5",
			generate: generateECDSA,
		},
	}

	var ks1 jwk.Set
	for _, tc := range tests {
		key, err := tc.generate(tc.use, tc.keyID)
		if !assert.NoError(t, err, `tc.generate should succeed`) {
			return
		}
		ks1.Keys = append(ks1.Keys, key)
	}

	buf, err := json.MarshalIndent(ks1, "", "  ")
	if !assert.NoError(t, err, "JSON marshal succeeded") {
		return
	}

	ks2, err := jwk.ParseBytes(buf)
	if !assert.NoError(t, err, "JSON unmarshal succeeded") {
		t.Logf("%s", buf)
		return
	}

	for _, tc := range tests {
		keys := ks2.LookupKeyID(tc.keyID)
		if !assert.Len(t, keys, 1, "Should be 1 key") {
			return
		}
		key1 := keys[0]

		keys = ks1.LookupKeyID(tc.keyID)
		if !assert.Len(t, keys, 1, "Should be 1 key") {
			return
		}

		key2 := keys[0]

		pk1json, _ := json.Marshal(key1)
		pk2json, _ := json.Marshal(key2)
		if !assert.Equal(t, pk1json, pk2json, "Keys should match (kid = %s)", tc.keyID) {
			return
		}
	}
}

func TestKeyOperation(t *testing.T) {
	testcases := []struct {
		Args  interface{}
		Error bool
	}{
		{
			Args: "sign",
		},
		{
			Args: []jwk.KeyOperation{jwk.KeyOpSign, jwk.KeyOpVerify, jwk.KeyOpEncrypt, jwk.KeyOpDecrypt, jwk.KeyOpWrapKey, jwk.KeyOpUnwrapKey},
		},
		{
			Args: jwk.KeyOperationList{jwk.KeyOpSign, jwk.KeyOpVerify, jwk.KeyOpEncrypt, jwk.KeyOpDecrypt, jwk.KeyOpWrapKey, jwk.KeyOpUnwrapKey},
		},
		{
			Args: []interface{}{"sign", "verify", "encrypt", "decrypt", "wrapKey", "unwrapKey"},
		},
		{
			Args: []string{"sign", "verify", "encrypt", "decrypt", "wrapKey", "unwrapKey"},
		},
		{
			Args:  []string{"sigh"},
			Error: true,
		},
	}

	for _, test := range testcases {
		var ops jwk.KeyOperationList
		if test.Error {
			if !assert.Error(t, ops.Accept(test.Args), `KeyOperationList.Accept should fail`) {
				return
			}
		} else {
			if !assert.NoError(t, ops.Accept(test.Args), `KeyOperationList.Accept should succeed`) {
				return
			}
		}
	}
}

func TestAssignKeyID(t *testing.T) {
	generators := []func() (jwk.Key, error){
		generateRSAPrivateKey,
		generateRSAPublicKey,
		generateECDSAPrivateKey,
		generateECDSAPublicKey,
		generateSymmetricKey,
	}

	for _, generator := range generators {
		k, err := generator()
		if !assert.NoError(t, err, `jwk generation should be successful`) {
			return
		}

		if !assert.Empty(t, k.KeyID(), `k.KeyID should be non-empty`) {
			return
		}
		if !assert.NoError(t, jwk.AssignKeyID(k), `AssignKeyID shuld be successful`) {
			return
		}

		if !assert.NotEmpty(t, k.KeyID(), `k.KeyID should be non-empty`) {
			return
		}
	}
}

func TestPublicKeyOf(t *testing.T) {
	rsakey, err := generateRawRSAPrivateKey()
	if !assert.NoError(t, err, `generating raw RSA key should succeed`) {
		return
	}

	ecdsakey, err := generateRawECDSAPrivateKey()
	if !assert.NoError(t, err, `generating raw ECDSA key should succeed`) {
		return
	}

	octets := generateRawSymmetricKey()

	keys := []struct {
		Key           interface{}
		PublicKeyType reflect.Type
	}{
		{
			Key:           rsakey,
			PublicKeyType: reflect.PtrTo(reflect.TypeOf(rsakey.PublicKey)),
		},
		{
			Key:           *rsakey,
			PublicKeyType: reflect.PtrTo(reflect.TypeOf(rsakey.PublicKey)),
		},
		{
			Key:           rsakey.PublicKey,
			PublicKeyType: reflect.PtrTo(reflect.TypeOf(rsakey.PublicKey)),
		},
		{
			Key:           &rsakey.PublicKey,
			PublicKeyType: reflect.PtrTo(reflect.TypeOf(rsakey.PublicKey)),
		},
		{
			Key:           ecdsakey,
			PublicKeyType: reflect.PtrTo(reflect.TypeOf(ecdsakey.PublicKey)),
		},
		{
			Key:           *ecdsakey,
			PublicKeyType: reflect.PtrTo(reflect.TypeOf(ecdsakey.PublicKey)),
		},
		{
			Key:           ecdsakey.PublicKey,
			PublicKeyType: reflect.PtrTo(reflect.TypeOf(ecdsakey.PublicKey)),
		},
		{
			Key:           &ecdsakey.PublicKey,
			PublicKeyType: reflect.PtrTo(reflect.TypeOf(ecdsakey.PublicKey)),
		},
		{
			Key:           octets,
			PublicKeyType: reflect.TypeOf(octets),
		},
	}

	for _, key := range keys {
		key := key
		t.Run(fmt.Sprintf("%T", key.Key), func(t *testing.T) {
			t.Parallel()

			pubkey, err := jwk.PublicKeyOf(key.Key)
			if !assert.NoError(t, err, `jwk.PublicKeyOf(%T) should succeed`) {
				return
			}

			if !assert.Equal(t, key.PublicKeyType, reflect.TypeOf(pubkey), `public key types should match`) {
				return
			}
		})
	}
}
