package openid_test

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/jwt/openid"
	"github.com/stretchr/testify/assert"
)

const aLongLongTimeAgo = 233431200
const aLongLongTimeAgoString = "233431200"

func assertStockAddressClaim(t *testing.T, x *openid.AddressClaim) bool {
	t.Helper()
	if !assert.NotNil(t, x) {
		return false
	}

	if !assert.Equal(t, "〒105-0011 東京都港区芝公園４丁目２−８", x.Formatted(), "formatted should match") {
		return false
	}

	if !assert.Equal(t, "日本", x.Country(), "country should match") {
		return false
	}

	if !assert.Equal(t, "東京都", x.Region(), "region should match") {
		return false
	}

	if !assert.Equal(t, "港区", x.Locality(), "locality should match") {
		return false
	}

	if !assert.Equal(t, "芝公園４丁目２−８", x.StreetAddress(), "street_address should match") {
		return false
	}

	if !assert.Equal(t, "105-0011", x.PostalCode(), "postal_code should match") {
		return false
	}
	return true
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
		if !assertStockAddressClaim(t, x) {
			return
		}
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

	var base = map[string]struct {
		Value interface{}
		Key   string
		Check func(openid.Token) bool
	}{
		"name": {
			Value: "jwx",
			Key:   openid.NameKey,
			Check: func(token openid.Token) bool {
				return assert.Equal(t, token.Name(), "jwx")
			},
		},
		"given_name": {
			Value: "jay",
			Key:   openid.GivenNameKey,
			Check: func(token openid.Token) bool {
				return assert.Equal(t, token.GivenName(), "jay")
			},
		},
		"middle_name": {
			Value: "weee",
			Key:   openid.MiddleNameKey,
			Check: func(token openid.Token) bool {
				return assert.Equal(t, token.MiddleName(), "weee")
			},
		},
		"family_name": {
			Value: "xi",
			Key:   openid.FamilyNameKey,
			Check: func(token openid.Token) bool {
				return assert.Equal(t, token.FamilyName(), "xi")
			},
		},
		"nickname": {
			Value: "jayweexi",
			Key:   openid.NicknameKey,
			Check: func(token openid.Token) bool {
				return assert.Equal(t, token.Nickname(), "jayweexi")
			},
		},
		"preferred_username": {
			Value: "jwx",
			Key:   openid.PreferredUsernameKey,
			Check: func(token openid.Token) bool {
				return assert.Equal(t, token.PreferredUsername(), "jwx")
			},
		},
		"profile": {
			Value: "https://github.com/lestrrat-go/jwx",
			Key:   openid.ProfileKey,
			Check: func(token openid.Token) bool {
				return assert.Equal(t, token.Profile(), "https://github.com/lestrrat-go/jwx")
			},
		},
		"picture": {
			Value: "https://avatars1.githubusercontent.com/u/36653903?s=400&amp;v=4",
			Key:   openid.PictureKey,
			Check: func(token openid.Token) bool {
				return assert.Equal(t, token.Picture(), "https://avatars1.githubusercontent.com/u/36653903?s=400&amp;v=4")
			},
		},
		"website": {
			Value: "https://github.com/lestrrat-go/jwx",
			Key:   openid.WebsiteKey,
			Check: func(token openid.Token) bool {
				return assert.Equal(t, token.Website(), "https://github.com/lestrrat-go/jwx")
			},
		},
		"email": {
			Value: "lestrrat+github@gmail.com",
			Key:   openid.EmailKey,
			Check: func(token openid.Token) bool {
				return assert.Equal(t, token.Email(), "lestrrat+github@gmail.com")
			},
		},
		"email_verified": {
			Value: true,
			Key:   openid.EmailVerifiedKey,
			Check: func(token openid.Token) bool {
				return assert.True(t, token.EmailVerified())
			},
		},
		"gender": {
			Value: "n/a",
			Key:   openid.GenderKey,
			Check: func(token openid.Token) bool {
				return assert.Equal(t, token.Gender(), "n/a")
			},
		},
		"birthdate": {
			Value: "2015-11-04",
			Check: func(token openid.Token) bool {
				var b openid.BirthdateClaim
				b.Accept("2015-11-04")
				return assert.Equal(t, token.Birthdate(), &b)
			},
		},
		"zoneinfo": {
			Value: "Asia/Tokyo",
			Key:   openid.ZoneinfoKey,
			Check: func(token openid.Token) bool {
				return assert.Equal(t, token.Zoneinfo(), "Asia/Tokyo")
			},
		},
		"locale": {
			Value: "ja_JP",
			Key:   openid.LocaleKey,
			Check: func(token openid.Token) bool {
				return assert.Equal(t, token.Locale(), "ja_JP")
			},
		},
		"phone_number": {
			Value: "819012345678",
			Key:   openid.PhoneNumberKey,
			Check: func(token openid.Token) bool {
				return assert.Equal(t, token.PhoneNumber(), "819012345678")
			},
		},
		"phone_number_verified": {
			Value: true,
			Key:   openid.PhoneNumberVerifiedKey,
			Check: func(token openid.Token) bool {
				return assert.True(t, token.PhoneNumberVerified())
			},
		},
		"address": {
			Value: map[string]interface{}{
				"formatted":      "〒105-0011 東京都港区芝公園４丁目２−８",
				"street_address": "芝公園４丁目２−８",
				"locality":       "港区",
				"region":         "東京都",
				"country":        "日本",
				"postal_code":    "105-0011",
			},
			Check: func(token openid.Token) bool {
				return assertStockAddressClaim(t, token.Address())
			},
		},
		"updated_at": {
			Value: aLongLongTimeAgoString,
			Check: func(token openid.Token) bool {
				return assert.Equal(t, time.Unix(aLongLongTimeAgo, 0).UTC(), token.UpdatedAt())
			},
		},
	}

	var data = map[string]interface{}{}
	for name, value := range base {
		data[name] = value.Value
	}

	src, err := json.Marshal(data)
	if !assert.NoError(t, err, `failed to marshal base map`) {
		return
	}

	t.Logf("Using source JSON: %s", src)

	token := openid.New()
	if !assert.NoError(t, json.Unmarshal(src, &token), `json.Unmarshal should succeed`) {
		return
	}

	for name, value := range base {
		value := value
		t.Run(name, func(t *testing.T) {
			value.Check(token)
		})
		if value.Key != "" {
			t.Run(name+" via Get()", func(t *testing.T) {
				getVerify(token, value.Key, value.Value)
			})
		}
	}
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
