package openid_test

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/jwt/internal/types"
	"github.com/lestrrat-go/jwx/jwt/openid"
	"github.com/stretchr/testify/assert"
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
			t.Parallel()
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
		Key      string
		Check    func(openid.Token)
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
			Value: "https://github.com/lestrrat-go/jwx",
			Key:   openid.ProfileKey,
			Check: func(token openid.Token) {
				assert.Equal(t, token.Profile(), "https://github.com/lestrrat-go/jwx")
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
			Value: "https://github.com/lestrrat-go/jwx",
			Key:   openid.WebsiteKey,
			Check: func(token openid.Token) {
				assert.Equal(t, token.Website(), "https://github.com/lestrrat-go/jwx")
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
		Name  string
		Token openid.Token
	}
	var tokens []openidTokTestCase

	{ // one with Set()
		token := openid.New()
		for name, value := range data {
			if !assert.NoError(t, token.Set(name, value), `token.Set should succeed`) {
				return
			}
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
	})
}

func TestBirthdateClaim(t *testing.T) {
	t.Run("regular date", func(t *testing.T) {
		const src = `"2015-11-04"`
		var b openid.BirthdateClaim
		if !assert.NoError(t, json.Unmarshal([]byte(src), &b), `json.Unmarshal should succeed`) {
			return
		}

		if !assert.Equal(t, b.Year(), 2015, "year should match") {
			return
		}
		if !assert.Equal(t, b.Month(), 11, "month should match") {
			return
		}
		if !assert.Equal(t, b.Day(), 4, "day should match") {
			return
		}
		serialized, err := json.Marshal(b)
		if !assert.NoError(t, err, `json.Marshal should succeed`) {
			return
		}
		if !assert.Equal(t, string(serialized), src, `serialized format should be the same`) {
			return
		}
	})
}
