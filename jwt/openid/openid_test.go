package openid_test

import (
	"encoding/json"
	"testing"

	"github.com/lestrrat-go/jwx/jwt"
	"github.com/lestrrat-go/jwx/jwt/openid"
	"github.com/stretchr/testify/assert"
)

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
		if !assert.Equal(t, "〒105-0011 東京都港区芝公園４丁目２−８", x.Formatted(), "formatted should match") {
			return
		}

		if !assert.Equal(t, "日本", x.Country(), "country should match") {
			return
		}

		if !assert.Equal(t, "東京都", x.Region(), "region should match") {
			return
		}

		if !assert.Equal(t, "港区", x.Locality(), "locality should match") {
			return
		}

		if !assert.Equal(t, "芝公園４丁目２−８", x.StreetAddress(), "street_address should match") {
			return
		}

		if !assert.Equal(t, "105-0011", x.PostalCode(), "postal_code should match") {
			return
		}
	}
}

func TestOpenIDClaims(t *testing.T) {
	const src = `{
		"name": "jwx",
		"given_name": "jay",
		"middle_name": "weee",
		"family_name": "xi",
		"nickname": "jayweexi",
		"preferred_username": "jwx",
		"profile": "https://github.com/lestrrat-go/jwx",
		"picture": "https://avatars1.githubusercontent.com/u/36653903?s=400&amp;v=4",
		"website": "https://github.com/lestrrat-go/jwx",
		"email": "lestrrat+github@gmail.com",
		"email_verified": true,
		"gender": "n/a",
		"birthdate": "2015-11-04"
	}`

	var token jwt.Token
	if !assert.NoError(t, json.Unmarshal([]byte(src), &token), `json.Unmarshal should succeed`) {
		return
	}

	t.Logf("%#v", token)

	t.Logf("%s", openid.Birthdate(&token))
	/*
		{
			Name:    "zoneinfo",
			Type:    "string",
			Comment: "https://openid.net/specs/openid-connect-core-1_0.html",
		},
		{
			Name:    "locale",
			Type:    "string",
			Comment: "https://openid.net/specs/openid-connect-core-1_0.html",
		},
		{
			Name:    "phone_number",
			Type:    "string",
			Comment: "https://openid.net/specs/openid-connect-core-1_0.html",
		},
		{
			Name:    "phone_number_verified",
			Type:    "bool",
			Comment: "https://openid.net/specs/openid-connect-core-1_0.html",
		},
		{
			Name:    "address",
			Type:    "*AddressClaim",
			Comment: "https://openid.net/specs/openid-connect-core-1_0.html",
		},
		{
			Name:    "updated_at",
			Type:    "*jwt.NumericDate",
			Comment: "https://openid.net/specs/openid-connect-core-1_0.html",
	*/
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
