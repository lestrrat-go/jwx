package openid_test

import (
	"context"
	"fmt"
	"strconv"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v2/internal/json"
	"github.com/lestrrat-go/jwx/v2/internal/jwxtest"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/lestrrat-go/jwx/v2/jwt/internal/types"
	"github.com/lestrrat-go/jwx/v2/jwt/openid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const aLongLongTimeAgo = 233431200
const aLongLongTimeAgoString = "233431200"
const (
	tokenTime = 233431200
)

var expectedTokenTime = time.Unix(tokenTime, 0).UTC()

func testStockAddressClaim(t *testing.T, x *openid.AddressClaim) {
	t.Helper()
	if !assert.NotNil(t, x) {
		return
	}

	tests := []struct {
		Accessor func() string
		KeyName  string
		Value    string
	}{
		{
			Accessor: x.Formatted,
			KeyName:  openid.AddressFormattedKey,
			Value:    "〒105-0011 東京都港区芝公園４丁目２−８",
		},
		{
			Accessor: x.Country,
			KeyName:  openid.AddressCountryKey,
			Value:    "日本",
		},
		{
			Accessor: x.Region,
			KeyName:  openid.AddressRegionKey,
			Value:    "東京都",
		},
		{
			Accessor: x.Locality,
			KeyName:  openid.AddressLocalityKey,
			Value:    "港区",
		},
		{
			Accessor: x.StreetAddress,
			KeyName:  openid.AddressStreetAddressKey,
			Value:    "芝公園４丁目２−８",
		},
		{
			Accessor: x.PostalCode,
			KeyName:  openid.AddressPostalCodeKey,
			Value:    "105-0011",
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.KeyName, func(t *testing.T) {
			t.Run("Accessor", func(t *testing.T) {
				if !assert.Equal(t, tc.Value, tc.Accessor(), "values should match") {
					return
				}
			})
			t.Run("Get", func(t *testing.T) {
				v, ok := x.Get(tc.KeyName)
				if !assert.True(t, ok, `x.Get should succeed`) {
					return
				}
				if !assert.Equal(t, tc.Value, v, `values should match`) {
					return
				}
			})
		})
	}
}

func TestAdressClaim(t *testing.T) {
	const src = `{
    "formatted": "〒105-0011 東京都港区芝公園４丁目２−８",
		"street_address": "芝公園４丁目２−８",
		"locality": "港区",
		"region": "東京都",
		"postal_code": "105-0011",
		"country": "日本"
	}`

	var address openid.AddressClaim
	if !assert.NoError(t, json.Unmarshal([]byte(src), &address), "json.Unmarshal should succeed") {
		return
	}

	var roundtrip openid.AddressClaim
	buf, err := json.Marshal(address)
	if !assert.NoError(t, err, `json.Marshal(address) should succeed`) {
		return
	}

	if !assert.NoError(t, json.Unmarshal(buf, &roundtrip), "json.Unmarshal should succeed") {
		return
	}

	for _, x := range []*openid.AddressClaim{&address, &roundtrip} {
		testStockAddressClaim(t, x)
	}
}

func TestOpenIDClaims(t *testing.T) {
	getVerify := func(token openid.Token, key string, expected interface{}) bool {
		v, ok := token.Get(key)
		if !assert.True(t, ok, `token.Get %#v should succeed`, key) {
			return false
		}
		return assert.Equal(t, v, expected)
	}

	var base = []struct {
		Value    interface{}
		Expected func(interface{}) interface{}
		Check    func(openid.Token)
		Key      string
	}{
		{
			Key:   openid.AudienceKey,
			Value: []string{"developers", "secops", "tac"},
			Check: func(token openid.Token) {
				assert.Equal(t, token.Audience(), []string{"developers", "secops", "tac"})
			},
		},
		{
			Key:   openid.ExpirationKey,
			Value: tokenTime,
			Expected: func(v interface{}) interface{} {
				var n types.NumericDate
				if err := n.Accept(v); err != nil {
					panic(err)
				}
				return n.Get()
			},
			Check: func(token openid.Token) {
				assert.Equal(t, token.Expiration(), expectedTokenTime)
			},
		},
		{
			Key:   openid.IssuedAtKey,
			Value: tokenTime,
			Expected: func(v interface{}) interface{} {
				var n types.NumericDate
				if err := n.Accept(v); err != nil {
					panic(err)
				}
				return n.Get()
			},
			Check: func(token openid.Token) {
				assert.Equal(t, token.Expiration(), expectedTokenTime)
			},
		},
		{
			Key:   openid.IssuerKey,
			Value: "http://www.example.com",
			Check: func(token openid.Token) {
				assert.Equal(t, token.Issuer(), "http://www.example.com")
			},
		},
		{
			Key:   openid.JwtIDKey,
			Value: "e9bc097a-ce51-4036-9562-d2ade882db0d",
			Check: func(token openid.Token) {
				assert.Equal(t, token.JwtID(), "e9bc097a-ce51-4036-9562-d2ade882db0d")
			},
		},
		{
			Key:   openid.NotBeforeKey,
			Value: tokenTime,
			Expected: func(v interface{}) interface{} {
				var n types.NumericDate
				if err := n.Accept(v); err != nil {
					panic(err)
				}
				return n.Get()
			},
			Check: func(token openid.Token) {
				assert.Equal(t, token.NotBefore(), expectedTokenTime)
			},
		},
		{
			Key:   openid.SubjectKey,
			Value: "unit test",
			Check: func(token openid.Token) {
				assert.Equal(t, token.Subject(), "unit test")
			},
		},
		{
			Value: "jwx",
			Key:   openid.NameKey,
			Check: func(token openid.Token) {
				assert.Equal(t, token.Name(), "jwx")
			},
		},
		{
			Value: "jay",
			Key:   openid.GivenNameKey,
			Check: func(token openid.Token) {
				assert.Equal(t, token.GivenName(), "jay")
			},
		},
		{
			Value: "weee",
			Key:   openid.MiddleNameKey,
			Check: func(token openid.Token) {
				assert.Equal(t, token.MiddleName(), "weee")
			},
		},
		{
			Value: "xi",
			Key:   openid.FamilyNameKey,
			Check: func(token openid.Token) {
				assert.Equal(t, token.FamilyName(), "xi")
			},
		},
		{
			Value: "jayweexi",
			Key:   openid.NicknameKey,
			Check: func(token openid.Token) {
				assert.Equal(t, token.Nickname(), "jayweexi")
			},
		},
		{
			Value: "jwx",
			Key:   openid.PreferredUsernameKey,
			Check: func(token openid.Token) {
				assert.Equal(t, token.PreferredUsername(), "jwx")
			},
		},
		{
			Value: "https://github.com/lestrrat-go/jwx/v2",
			Key:   openid.ProfileKey,
			Check: func(token openid.Token) {
				assert.Equal(t, token.Profile(), "https://github.com/lestrrat-go/jwx/v2")
			},
		},
		{
			Value: "https://avatars1.githubusercontent.com/u/36653903?s=400&amp;v=4",
			Key:   openid.PictureKey,
			Check: func(token openid.Token) {
				assert.Equal(t, token.Picture(), "https://avatars1.githubusercontent.com/u/36653903?s=400&amp;v=4")
			},
		},
		{
			Value: "https://github.com/lestrrat-go/jwx/v2",
			Key:   openid.WebsiteKey,
			Check: func(token openid.Token) {
				assert.Equal(t, token.Website(), "https://github.com/lestrrat-go/jwx/v2")
			},
		},
		{
			Value: "lestrrat+github@gmail.com",
			Key:   openid.EmailKey,
			Check: func(token openid.Token) {
				assert.Equal(t, token.Email(), "lestrrat+github@gmail.com")
			},
		},
		{
			Value: true,
			Key:   openid.EmailVerifiedKey,
			Check: func(token openid.Token) {
				assert.True(t, token.EmailVerified())
			},
		},
		{
			Value: "n/a",
			Key:   openid.GenderKey,
			Check: func(token openid.Token) {
				assert.Equal(t, token.Gender(), "n/a")
			},
		},
		{
			Value: "2015-11-04",
			Key:   openid.BirthdateKey,
			Expected: func(v interface{}) interface{} {
				var b openid.BirthdateClaim
				if err := b.Accept(v); err != nil {
					panic(err)
				}
				return &b
			},
			Check: func(token openid.Token) {
				var b openid.BirthdateClaim
				b.Accept("2015-11-04")
				assert.Equal(t, token.Birthdate(), &b)
			},
		},
		{
			Value: "Asia/Tokyo",
			Key:   openid.ZoneinfoKey,
			Check: func(token openid.Token) {
				assert.Equal(t, token.Zoneinfo(), "Asia/Tokyo")
			},
		},
		{
			Value: "ja_JP",
			Key:   openid.LocaleKey,
			Check: func(token openid.Token) {
				assert.Equal(t, token.Locale(), "ja_JP")
			},
		},
		{
			Value: "819012345678",
			Key:   openid.PhoneNumberKey,
			Check: func(token openid.Token) {
				assert.Equal(t, token.PhoneNumber(), "819012345678")
			},
		},
		{
			Value: true,
			Key:   openid.PhoneNumberVerifiedKey,
			Check: func(token openid.Token) {
				assert.True(t, token.PhoneNumberVerified())
			},
		},
		{
			Value: map[string]interface{}{
				"formatted":      "〒105-0011 東京都港区芝公園４丁目２−８",
				"street_address": "芝公園４丁目２−８",
				"locality":       "港区",
				"region":         "東京都",
				"country":        "日本",
				"postal_code":    "105-0011",
			},
			Key: openid.AddressKey,
			Expected: func(v interface{}) interface{} {
				address := openid.NewAddress()
				m, ok := v.(map[string]interface{})
				if !ok {
					panic(fmt.Sprintf("expected map[string]interface{}, got %T", v))
				}
				for name, val := range m {
					if !assert.NoError(t, address.Set(name, val), `address.Set should succeed`) {
						return nil
					}
				}
				return address
			},
			Check: func(token openid.Token) {
				testStockAddressClaim(t, token.Address())
			},
		},
		{
			Value: aLongLongTimeAgoString,
			Key:   openid.UpdatedAtKey,
			Expected: func(v interface{}) interface{} {
				var n types.NumericDate
				if err := n.Accept(v); err != nil {
					panic(err)
				}
				return n.Get()
			},
			Check: func(token openid.Token) {
				assert.Equal(t, time.Unix(aLongLongTimeAgo, 0).UTC(), token.UpdatedAt())
			},
		},
		{
			Value: `dummy`,
			Key:   `dummy`,
			Check: func(token openid.Token) {
				v, ok := token.Get(`dummy`)
				if !assert.True(t, ok, `token.Get should return valid value`) {
					return
				}
				if !assert.Equal(t, `dummy`, v, `values should match`) {
					return
				}
			},
		},
	}

	var data = map[string]interface{}{}
	var expected = map[string]interface{}{}
	for _, value := range base {
		data[value.Key] = value.Value
		if expf := value.Expected; expf != nil {
			expected[value.Key] = expf(value.Value)
		} else {
			expected[value.Key] = value.Value
		}
	}

	type openidTokTestCase struct {
		Token openid.Token
		Name  string
	}
	var tokens []openidTokTestCase

	{ // one with Set()
		b := openid.NewBuilder()
		for name, value := range data {
			b.Claim(name, value)
		}
		token, err := b.Build()
		if !assert.NoError(t, err, `b.Build() should succeed`) {
			return
		}
		tokens = append(tokens, openidTokTestCase{Name: `token constructed by calling Set()`, Token: token})
	}

	{ // two with json.Marshal / json.Unmarshal
		src, err := json.MarshalIndent(data, "", "  ")
		if !assert.NoError(t, err, `failed to marshal base map`) {
			return
		}

		t.Logf("Using source JSON: %s", src)

		token := openid.New()
		if !assert.NoError(t, json.Unmarshal(src, &token), `json.Unmarshal should succeed`) {
			return
		}
		tokens = append(tokens, openidTokTestCase{Name: `token constructed by Marshal(map)+Unmashal`, Token: token})

		// One more... Marshal the token, _and_ re-unmarshal
		buf, err := json.Marshal(token)
		if !assert.NoError(t, err, `json.Marshal should succeed`) {
			return
		}

		token2 := openid.New()
		if !assert.NoError(t, json.Unmarshal(buf, &token2), `json.Unmarshal should succeed`) {
			return
		}
		tokens = append(tokens, openidTokTestCase{Name: `token constructed by Marshal(openid.Token)+Unmashal`, Token: token2})

		// Sign it, and use jwt.Parse

		var token3 openid.Token
		{
			alg := jwa.RS256
			key, err := jwxtest.GenerateRsaKey()
			if !assert.NoError(t, err, `rsa.GeneraKey should succeed`) {
				return
			}
			signed, err := jwt.Sign(token, jwt.WithKey(alg, key))
			if !assert.NoError(t, err, `jwt.Sign should succeed`) {
				return
			}

			tokenTmp, err := jwt.Parse(signed, jwt.WithToken(openid.New()), jwt.WithKey(alg, &key.PublicKey), jwt.WithValidate(false))
			if !assert.NoError(t, err, `parsing the token via jwt.Parse should succeed`) {
				return
			}

			// Check if token is an OpenID token
			if _, ok := tokenTmp.(openid.Token); !assert.True(t, ok, `token should be a openid.Token (%T)`, tokenTmp) {
				return
			}
			token3 = tokenTmp.(openid.Token)
		}

		tokens = append(tokens, openidTokTestCase{Name: `token constructed by jwt.Parse`, Token: token3})
	}

	for _, token := range tokens {
		token := token
		t.Run(token.Name, func(t *testing.T) {
			for _, value := range base {
				value := value
				t.Run(value.Key, func(t *testing.T) {
					value.Check(token.Token)
				})
				t.Run(value.Key+" via Get()", func(t *testing.T) {
					expected := value.Value
					if expf := value.Expected; expf != nil {
						expected = expf(value.Value)
					}
					getVerify(token.Token, value.Key, expected)
				})
			}
		})
	}

	t.Run("Iterator", func(t *testing.T) {
		v := tokens[0].Token
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
			v.Walk(context.TODO(), openid.VisitorFunc(func(key string, value interface{}) error {
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
		t.Run("Clone", func(t *testing.T) {
			cloned, err := v.Clone()
			if !assert.NoError(t, err, `v.Clone should succeed`) {
				return
			}

			if !assert.True(t, jwt.Equal(v, cloned), `values should match`) {
				return
			}
		})
	})
}

func TestBirthdateClaim(t *testing.T) {
	t.Parallel()
	t.Run("regular date", func(t *testing.T) {
		t.Parallel()
		testcases := []struct {
			Source string
			Year   int
			Month  int
			Day    int
			Error  bool
		}{
			{
				Source: `"2015-11-04"`,
				Year:   2015,
				Month:  11,
				Day:    4,
			},
			{
				Source: `"0009-09-09"`,
				Year:   9,
				Month:  9,
				Day:    9,
			},
			{
				Source: `{}`,
				Error:  true,
			},
			{
				Source: `"202X-01-01"`,
				Error:  true,
			},
			{
				Source: `"0000-01-01"`,
				Error:  true,
			},
			{
				Source: `"0001-00-01"`,
				Error:  true,
			},
			{
				Source: `"0001-01-00"`,
				Error:  true,
			},
		}

		for _, tc := range testcases {
			tc := tc
			t.Run(tc.Source, func(t *testing.T) {
				var b openid.BirthdateClaim
				if tc.Error {
					assert.Error(t, json.Unmarshal([]byte(tc.Source), &b), `json.Unmarshal should fail`)
					return
				}

				if !assert.NoError(t, json.Unmarshal([]byte(tc.Source), &b), `json.Unmarshal should succeed`) {
					return
				}

				if !assert.Equal(t, b.Year(), tc.Year, "year should match") {
					return
				}
				if !assert.Equal(t, b.Month(), tc.Month, "month should match") {
					return
				}
				if !assert.Equal(t, b.Day(), tc.Day, "day should match") {
					return
				}
				serialized, err := json.Marshal(b)
				if !assert.NoError(t, err, `json.Marshal should succeed`) {
					return
				}
				if !assert.Equal(t, string(serialized), tc.Source, `serialized format should be the same`) {
					return
				}
				stringified := b.String()
				expectedString, _ := strconv.Unquote(tc.Source)
				if !assert.Equal(t, stringified, expectedString, `stringified format should be the same`) {
					return
				}
			})
		}
	})
	t.Run("empty date", func(t *testing.T) {
		t.Parallel()
		var b openid.BirthdateClaim
		if !assert.Equal(t, b.Year(), 0, "year should match") {
			return
		}
		if !assert.Equal(t, b.Month(), 0, "month should match") {
			return
		}
		if !assert.Equal(t, b.Day(), 0, "day should match") {
			return
		}
	})
	t.Run("invalid accept", func(t *testing.T) {
		t.Parallel()
		var b openid.BirthdateClaim
		if !assert.Error(t, b.Accept(nil)) {
			return
		}
	})
}

func TestKeys(t *testing.T) {
	at := assert.New(t)
	at.Equal(`address`, openid.AddressKey)
	at.Equal(`aud`, openid.AudienceKey)
	at.Equal(`birthdate`, openid.BirthdateKey)
	at.Equal(`email`, openid.EmailKey)
	at.Equal(`email_verified`, openid.EmailVerifiedKey)
	at.Equal(`exp`, openid.ExpirationKey)
	at.Equal(`family_name`, openid.FamilyNameKey)
	at.Equal(`gender`, openid.GenderKey)
	at.Equal(`given_name`, openid.GivenNameKey)
	at.Equal(`iat`, openid.IssuedAtKey)
	at.Equal(`iss`, openid.IssuerKey)
	at.Equal(`jti`, openid.JwtIDKey)
	at.Equal(`locale`, openid.LocaleKey)
	at.Equal(`middle_name`, openid.MiddleNameKey)
	at.Equal(`name`, openid.NameKey)
	at.Equal(`nickname`, openid.NicknameKey)
	at.Equal(`nbf`, openid.NotBeforeKey)
	at.Equal(`phone_number`, openid.PhoneNumberKey)
	at.Equal(`phone_number_verified`, openid.PhoneNumberVerifiedKey)
	at.Equal(`picture`, openid.PictureKey)
	at.Equal(`preferred_username`, openid.PreferredUsernameKey)
	at.Equal(`profile`, openid.ProfileKey)
	at.Equal(`sub`, openid.SubjectKey)
	at.Equal(`updated_at`, openid.UpdatedAtKey)
	at.Equal(`website`, openid.WebsiteKey)
	at.Equal(`zoneinfo`, openid.ZoneinfoKey)
}

func TestGH734(t *testing.T) {
	const src = `{
    "nickname": "miniscruff",
    "updated_at": "2022-05-06T04:57:24.367Z",
    "email_verified": true
  }`

	expected, _ := time.Parse(time.RFC3339, "2022-05-06T04:57:24.367Z")
	for _, pedantic := range []bool{true, false} {
		t.Run(fmt.Sprintf("pedantic=%t", pedantic), func(t *testing.T) {
			jwt.Settings(jwt.WithNumericDateParsePedantic(pedantic))
			tok := openid.New()
			_, err := jwt.Parse(
				[]byte(src),
				jwt.WithToken(tok),
				jwt.WithVerify(false),
				jwt.WithValidate(false),
			)
			if pedantic {
				require.Error(t, err, `jwt.Parse should fail for pedantic parser`)
			} else {
				require.NoError(t, err, `jwt.Parse should succeed`)
				require.Equal(t, expected, tok.UpdatedAt(), `updated_at should match`)
			}
		})
	}
	jwt.Settings(jwt.WithNumericDateParsePedantic(false))
}
