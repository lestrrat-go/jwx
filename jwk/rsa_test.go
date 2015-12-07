package jwk

import (
	"crypto"
	"crypto/rsa"
	"testing"

	"github.com/lestrrat/go-jwx/buffer"
	"github.com/stretchr/testify/assert"
)

func TestParse_RsaPrivateKey(t *testing.T) {
	/* TODO: implement "EC"
	   {"kty":"EC",
	    "crv":"P-256",
	    "x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
	    "y":"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM",
	    "d":"870MB6gfuTJ4HtUnUvYMyJpr5eUZNP4Bk43bVdj3eAE",
	    "use":"enc",
	    "kid":"1"},
	*/

	s := `{"keys":
       [
         {"kty":"RSA",
          "n":"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
          "e":"AQAB",
          "d":"X4cTteJY_gn4FYPsXB8rdXix5vwsg1FLN5E3EaG6RJoVH-HLLKD9M7dx5oo7GURknchnrRweUkC7hT5fJLM0WbFAKNLWY2vv7B6NqXSzUvxT0_YSfqijwp3RTzlBaCxWp4doFk5N2o8Gy_nHNKroADIkJ46pRUohsXywbReAdYaMwFs9tv8d_cPVY3i07a3t8MN6TNwm0dSawm9v47UiCl3Sk5ZiG7xojPLu4sbg1U2jx4IBTNBznbJSzFHK66jT8bgkuqsk0GjskDJk19Z4qwjwbsnn4j2WBii3RL-Us2lGVkY8fkFzme1z0HbIkfz0Y6mqnOYtqc0X4jfcKoAC8Q",
          "p":"83i-7IvMGXoMXCskv73TKr8637FiO7Z27zv8oj6pbWUQyLPQBQxtPVnwD20R-60eTDmD2ujnMt5PoqMrm8RfmNhVWDtjjMmCMjOpSXicFHj7XOuVIYQyqVWlWEh6dN36GVZYk93N8Bc9vY41xy8B9RzzOGVQzXvNEvn7O0nVbfs",
          "q":"3dfOR9cuYq-0S-mkFLzgItgMEfFzB2q3hWehMuG0oCuqnb3vobLyumqjVZQO1dIrdwgTnCdpYzBcOfW5r370AFXjiWft_NGEiovonizhKpo9VVS78TzFgxkIdrecRezsZ-1kYd_s1qDbxtkDEgfAITAG9LUnADun4vIcb6yelxk",
          "dp":"G4sPXkc6Ya9y8oJW9_ILj4xuppu0lzi_H7VTkS8xj5SdX3coE0oimYwxIi2emTAue0UOa5dpgFGyBJ4c8tQ2VF402XRugKDTP8akYhFo5tAA77Qe_NmtuYZc3C3m3I24G2GvR5sSDxUyAN2zq8Lfn9EUms6rY3Ob8YeiKkTiBj0",
          "dq":"s9lAH9fggBsoFR8Oac2R_E2gw282rT2kGOAhvIllETE1efrA6huUUvMfBcMpn8lqeW6vzznYY5SSQF7pMdC_agI3nG8Ibp1BUb0JUiraRNqUfLhcQb_d9GF4Dh7e74WbRsobRonujTYN1xCaP6TO61jvWrX-L18txXw494Q_cgk",
          "qi":"GyM_p6JrXySiz1toFgKbWV-JdI3jQ4ypu9rbMWx3rQJBfmt0FoYzgUIZEVFEcOqwemRN81zoDAaa-Bk0KWNGDjJHZDdDmFhW3AN7lI-puxk_mHZGJ11rxyR8O55XLSe3SPmRfKwZI6yU24ZxvQKFYItdldUKGzO6Ia6zTKhAVRU",
          "alg":"RS256",
          "kid":"2011-04-29"}
       ]
     }`
	set, err := ParseString(s)
	if !assert.NoError(t, err, "Parsing private key is successful") {
		return
	}

	rsakey, ok := set.Keys[0].(*RsaPrivateKey)
	if !assert.True(t, ok, "Type assertion for RsaPrivateKey is successful") {
		return
	}

	var privkey *rsa.PrivateKey
	var pubkey *rsa.PublicKey

	{
		mkey, err := rsakey.RsaPublicKey.Materialize()
		if !assert.NoError(t, err, "RsaPublickKey.Materialize is successful") {
			return
		}
		var ok bool
		pubkey, ok = mkey.(*rsa.PublicKey)
		if !assert.True(t, ok, "Materialized key is a *rsa.PublicKey") {
			return
		}
	}

	if !assert.NotEmpty(t, pubkey.N, "N exists") {
		return
	}

	if !assert.NotEmpty(t, pubkey.E, "E exists") {
		return
	}

	{
		mkey, err := rsakey.Materialize()
		if !assert.NoError(t, err, "RsaPrivateKey.Materialize is successful") {
			return
		}
		var ok bool
		privkey, ok = mkey.(*rsa.PrivateKey)
		if !assert.True(t, ok, "Materialized key is a *rsa.PrivateKey") {
			return
		}
	}

	if !assert.NotEmpty(t, privkey.Precomputed.Dp, "Dp exists") {
		return
	}

	if !assert.NotEmpty(t, privkey.Precomputed.Dq, "Dq exists") {
		return
	}

	if !assert.NotEmpty(t, privkey.Precomputed.Qinv, "Qinv exists") {
		return
	}
}

func TestThumbprint(t *testing.T) {
	expected := []byte{55, 54, 203, 177, 120, 124, 184, 48, 156, 119, 238,
		140, 55, 5, 197, 225, 111, 251, 158, 133, 151, 21, 144, 31, 30, 76, 89,
		177, 17, 130, 245, 123,
	}
	n, err := buffer.FromBase64([]byte("0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw"))
	if !assert.NoError(t, err, "decode N succeeds") {
		return
	}
	e, err := buffer.FromBase64([]byte("AQAB"))
	if !assert.NoError(t, err, "decode E succeeds") {
		return
	}
	key := RsaPublicKey{
		EssentialHeader: &EssentialHeader{KeyType: "RSA"},
		N:               n,
		E:               e,
	}

	tp, err := key.Thumbprint(crypto.SHA256)
	if !assert.NoError(t, err, "Thumbprint should succeed") {
		return
	}

	if !assert.Equal(t, expected, tp, "Thumbprint should match") {
		return
	}
}
