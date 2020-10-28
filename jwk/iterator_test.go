package jwk_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/lestrrat-go/jwx/internal/json"

	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/stretchr/testify/assert"
)

func TestIterator(t *testing.T) {
	commonValues := map[string]interface{}{
		jwk.AlgorithmKey: "dummy",
		jwk.KeyIDKey:     "dummy-kid",
		jwk.KeyUsageKey:  "dummy-usage",
		jwk.KeyOpsKey:    jwk.KeyOperationList{jwk.KeyOpSign, jwk.KeyOpVerify, jwk.KeyOpEncrypt, jwk.KeyOpDecrypt, jwk.KeyOpWrapKey, jwk.KeyOpUnwrapKey, jwk.KeyOpDeriveKey, jwk.KeyOpDeriveBits},
		"private":        "dummy-private",
	}

	verifyIterators := func(t *testing.T, v jwk.Key, expected map[string]interface{}) {
		t.Helper()
		t.Run("Iterate", func(t *testing.T) {
			seen := make(map[string]interface{})
			for iter := v.Iterate(context.TODO()); iter.Next(context.TODO()); {
				pair := iter.Pair()
				seen[pair.Key.(string)] = pair.Value

				getV, ok := v.Get(pair.Key.(string))
				if !assert.True(t, ok, `v.Get should succeed for key %#v`, pair.Key) {
					return
				}
				if !assert.Equal(t, pair.Value, getV, `pair.Value should match value from v.Get()`) {
					return
				}
			}
			if !assert.Equal(t, expected, seen, `values should match`) {
				return
			}
		})
		t.Run("Walk", func(t *testing.T) {
			seen := make(map[string]interface{})
			v.Walk(context.TODO(), jwk.HeaderVisitorFunc(func(key string, value interface{}) error {
				seen[key] = value
				return nil
			}))
			if !assert.Equal(t, expected, seen, `values should match`) {
				return
			}
		})
		t.Run("AsMap", func(t *testing.T) {
			seen, err := v.AsMap(context.TODO())
			if !assert.NoError(t, err, `v.AsMap should succeed`) {
				return
			}
			if !assert.Equal(t, expected, seen, `values should match`) {
				return
			}
		})
	}

	type iterTestCase struct {
		Extras map[string]interface{}
		Func   func() jwk.Key
	}

	testcases := []iterTestCase{
		{
			Extras: map[string]interface{}{
				jwk.RSANKey:  []byte("0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw"),
				jwk.RSAEKey:  []byte("AQAB"),
				jwk.RSADKey:  []byte("X4cTteJY_gn4FYPsXB8rdXix5vwsg1FLN5E3EaG6RJoVH-HLLKD9M7dx5oo7GURknchnrRweUkC7hT5fJLM0WbFAKNLWY2vv7B6NqXSzUvxT0_YSfqijwp3RTzlBaCxWp4doFk5N2o8Gy_nHNKroADIkJ46pRUohsXywbReAdYaMwFs9tv8d_cPVY3i07a3t8MN6TNwm0dSawm9v47UiCl3Sk5ZiG7xojPLu4sbg1U2jx4IBTNBznbJSzFHK66jT8bgkuqsk0GjskDJk19Z4qwjwbsnn4j2WBii3RL-Us2lGVkY8fkFzme1z0HbIkfz0Y6mqnOYtqc0X4jfcKoAC8Q"),
				jwk.RSAPKey:  []byte("83i-7IvMGXoMXCskv73TKr8637FiO7Z27zv8oj6pbWUQyLPQBQxtPVnwD20R-60eTDmD2ujnMt5PoqMrm8RfmNhVWDtjjMmCMjOpSXicFHj7XOuVIYQyqVWlWEh6dN36GVZYk93N8Bc9vY41xy8B9RzzOGVQzXvNEvn7O0nVbfs"),
				jwk.RSAQKey:  []byte("3dfOR9cuYq-0S-mkFLzgItgMEfFzB2q3hWehMuG0oCuqnb3vobLyumqjVZQO1dIrdwgTnCdpYzBcOfW5r370AFXjiWft_NGEiovonizhKpo9VVS78TzFgxkIdrecRezsZ-1kYd_s1qDbxtkDEgfAITAG9LUnADun4vIcb6yelxk"),
				jwk.RSADPKey: []byte("G4sPXkc6Ya9y8oJW9_ILj4xuppu0lzi_H7VTkS8xj5SdX3coE0oimYwxIi2emTAue0UOa5dpgFGyBJ4c8tQ2VF402XRugKDTP8akYhFo5tAA77Qe_NmtuYZc3C3m3I24G2GvR5sSDxUyAN2zq8Lfn9EUms6rY3Ob8YeiKkTiBj0"),
				jwk.RSADQKey: []byte("s9lAH9fggBsoFR8Oac2R_E2gw282rT2kGOAhvIllETE1efrA6huUUvMfBcMpn8lqeW6vzznYY5SSQF7pMdC_agI3nG8Ibp1BUb0JUiraRNqUfLhcQb_d9GF4Dh7e74WbRsobRonujTYN1xCaP6TO61jvWrX-L18txXw494Q_cgk"),
				jwk.RSAQIKey: []byte("GyM_p6JrXySiz1toFgKbWV-JdI3jQ4ypu9rbMWx3rQJBfmt0FoYzgUIZEVFEcOqwemRN81zoDAaa-Bk0KWNGDjJHZDdDmFhW3AN7lI-puxk_mHZGJ11rxyR8O55XLSe3SPmRfKwZI6yU24ZxvQKFYItdldUKGzO6Ia6zTKhAVRU"),
			},
			Func: func() jwk.Key {
				return jwk.NewRSAPrivateKey()
			},
		},
		{
			Extras: map[string]interface{}{
				jwk.RSANKey: []byte("0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw"),
				jwk.RSAEKey: []byte("AQAB"),
			},
			Func: func() jwk.Key {
				return jwk.NewRSAPublicKey()
			},
		},
		{
			Extras: map[string]interface{}{
				jwk.ECDSACrvKey: jwa.P256,
				jwk.ECDSAXKey:   []byte("MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4"),
				jwk.ECDSAYKey:   []byte("4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM"),
				jwk.ECDSADKey:   []byte("870MB6gfuTJ4HtUnUvYMyJpr5eUZNP4Bk43bVdj3eAE"),
			},
			Func: func() jwk.Key {
				return jwk.NewECDSAPrivateKey()
			},
		},
		{
			Extras: map[string]interface{}{
				jwk.ECDSACrvKey: jwa.P256,
				jwk.ECDSAXKey:   []byte("MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4"),
				jwk.ECDSAYKey:   []byte("4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM"),
			},
			Func: func() jwk.Key {
				return jwk.NewECDSAPublicKey()
			},
		},
		{
			Extras: map[string]interface{}{
				jwk.SymmetricOctetsKey: []byte("abcd"),
			},
			Func: func() jwk.Key {
				return jwk.NewSymmetricKey()
			},
		},
	}
	for _, test := range testcases {
		key := test.Func()
		key2 := test.Func()
		expected := make(map[string]interface{})
		expected[jwk.KeyTypeKey] = key.KeyType()
		for k, v := range commonValues {
			if !assert.NoError(t, key.Set(k, v), `key.Set %#v should succeed`, k) {
				return
			}
			expected[k] = v
		}
		for k, v := range test.Extras {
			if !assert.NoError(t, key.Set(k, v), `key.Set %#v should succeed`, k) {
				return
			}
			expected[k] = v
		}

		t.Run(fmt.Sprintf("%T", key), func(t *testing.T) {
			verifyIterators(t, key, expected)
		})
		t.Run(fmt.Sprintf("%T (after json roundtripping)", key), func(t *testing.T) {
			buf, err := json.Marshal(key)
			if !assert.NoError(t, err, `json.Marshal should succeed`) {
				return
			}

			if !assert.NoError(t, json.Unmarshal(buf, key2), `json.Unmarshal should succeed`) {
				return
			}

			verifyIterators(t, key2, expected)
		})
	}
}
