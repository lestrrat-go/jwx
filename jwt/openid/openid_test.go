package openid_test

import (
	"encoding/json"
	"testing"

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
	// TODO. too tired now
}
