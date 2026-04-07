package openid_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"strconv"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v4/internal/json"
	"github.com/lestrrat-go/jwx/v4/internal/jwxtest"
	"github.com/lestrrat-go/jwx/v4/internal/tokens"

	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jwt"
	"github.com/lestrrat-go/jwx/v4/jwt/internal/types"
	"github.com/lestrrat-go/jwx/v4/jwt/openid"
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
	require.NotNil(t, x)

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
		t.Run(tc.KeyName, func(t *testing.T) {
			t.Run("Accessor", func(t *testing.T) {
				require.Equal(t, tc.Value, tc.Accessor(), "values should match")
			})
			t.Run("Get", func(t *testing.T) {
				v, ok := x.Get(tc.KeyName)
				require.True(t, ok, `x.Get should succeed`)
				require.Equal(t, tc.Value, v, `values should match`)
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
	require.NoError(t, json.Unmarshal([]byte(src), &address), "json.Unmarshal should succeed")

	var roundtrip openid.AddressClaim
	buf, err := json.Marshal(address)
	require.NoError(t, err, `json.Marshal(address) should succeed`)
	require.NoError(t, json.Unmarshal(buf, &roundtrip), "json.Unmarshal should succeed")

	for _, x := range []*openid.AddressClaim{&address, &roundtrip} {
		testStockAddressClaim(t, x)
	}
}

func TestOpenIDClaims(t *testing.T) {
	getVerify := func(token openid.Token, key string, expected any) bool {
		v, ok := token.Field(key)
		if !assert.True(t, ok, `token.Field %#v should succeed`, key) {
			return false
		}
		return assert.Equal(t, v, expected)
	}

	var base = []struct {
		Value    any
		Expected func(any) any
		Check    func(openid.Token)
		Key      string
	}{
		{
			Key:   openid.AudienceKey,
			Value: []string{"developers", "secops", "tac"},
			Check: func(token openid.Token) {
				v, ok := token.Audience()
				require.True(t, ok, `token.Audience should succeed`)
				require.Equal(t, v, []string{"developers", "secops", "tac"})
			},
		},
		{
			Key:   openid.ExpirationKey,
			Value: tokenTime,
			Expected: func(v any) any {
				var n types.NumericDate
				if err := n.Accept(v); err != nil {
					panic(err)
				}
				return n.Get()
			},
			Check: func(token openid.Token) {
				v, ok := token.Expiration()
				require.True(t, ok, `token.Expiration should succeed`)
				require.Equal(t, v, expectedTokenTime)
			},
		},
		{
			Key:   openid.IssuedAtKey,
			Value: tokenTime,
			Expected: func(v any) any {
				var n types.NumericDate
				if err := n.Accept(v); err != nil {
					panic(err)
				}
				return n.Get()
			},
			Check: func(token openid.Token) {
				v, ok := token.Expiration()
				require.True(t, ok, `token.Expiration should succeed`)
				require.Equal(t, v, expectedTokenTime)
			},
		},
		{
			Key:   openid.IssuerKey,
			Value: "http://www.example.com",
			Check: func(token openid.Token) {
				v, ok := token.Issuer()
				require.True(t, ok, `token.Issuer should succeed`)
				require.Equal(t, v, "http://www.example.com")
			},
		},
		{
			Key:   openid.JwtIDKey,
			Value: "e9bc097a-ce51-4036-9562-d2ade882db0d",
			Check: func(token openid.Token) {
				v, ok := token.JwtID()
				require.True(t, ok, `token.JwtID should succeed`)
				require.Equal(t, v, "e9bc097a-ce51-4036-9562-d2ade882db0d")
			},
		},
		{
			Key:   openid.NotBeforeKey,
			Value: tokenTime,
			Expected: func(v any) any {
				var n types.NumericDate
				if err := n.Accept(v); err != nil {
					panic(err)
				}
				return n.Get()
			},
			Check: func(token openid.Token) {
				v, ok := token.NotBefore()
				require.True(t, ok, `token.NotBefore should succeed`)
				require.Equal(t, v, expectedTokenTime)
			},
		},
		{
			Key:   openid.SubjectKey,
			Value: "unit test",
			Check: func(token openid.Token) {
				v, ok := token.Subject()
				require.True(t, ok, `token.Subject should succeed`)
				require.Equal(t, v, "unit test")
			},
		},
		{
			Value: "jwx",
			Key:   openid.NameKey,
			Check: func(token openid.Token) {
				v, ok := token.Name()
				require.True(t, ok, `token.Name should succeed`)
				require.Equal(t, v, "jwx")
			},
		},
		{
			Value: "jay",
			Key:   openid.GivenNameKey,
			Check: func(token openid.Token) {
				v, ok := token.GivenName()
				require.True(t, ok, `token.GivenName should succeed`)
				require.Equal(t, v, "jay")
			},
		},
		{
			Value: "weee",
			Key:   openid.MiddleNameKey,
			Check: func(token openid.Token) {
				v, ok := token.MiddleName()
				require.True(t, ok, `token.MiddleName should succeed`)
				require.Equal(t, v, "weee")
			},
		},
		{
			Value: "xi",
			Key:   openid.FamilyNameKey,
			Check: func(token openid.Token) {
				v, ok := token.FamilyName()
				require.True(t, ok, `token.FamilyName should succeed`)
				require.Equal(t, v, "xi")
			},
		},
		{
			Value: "jayweexi",
			Key:   openid.NicknameKey,
			Check: func(token openid.Token) {
				v, ok := token.Nickname()
				require.True(t, ok, `token.Nickname should succeed`)
				require.Equal(t, v, "jayweexi")
			},
		},
		{
			Value: "jwx",
			Key:   openid.PreferredUsernameKey,
			Check: func(token openid.Token) {
				v, ok := token.PreferredUsername()
				require.True(t, ok, `token.PreferredUsername should succeed`)
				require.Equal(t, v, "jwx")
			},
		},
		{
			Value: "https://github.com/lestrrat-go/jwx/v4",
			Key:   openid.ProfileKey,
			Check: func(token openid.Token) {
				v, ok := token.Profile()
				require.True(t, ok, `token.Profile should succeed`)
				require.Equal(t, v, "https://github.com/lestrrat-go/jwx/v4")
			},
		},
		{
			Value: "https://avatars1.githubusercontent.com/u/36653903?s=400&amp;v=4",
			Key:   openid.PictureKey,
			Check: func(token openid.Token) {
				v, ok := token.Picture()
				require.True(t, ok, `token.Picture should succeed`)
				require.Equal(t, v, "https://avatars1.githubusercontent.com/u/36653903?s=400&amp;v=4")
			},
		},
		{
			Value: "https://github.com/lestrrat-go/jwx/v4",
			Key:   openid.WebsiteKey,
			Check: func(token openid.Token) {
				v, ok := token.Website()
				require.True(t, ok, `token.Website should succeed`)
				require.Equal(t, v, "https://github.com/lestrrat-go/jwx/v4")
			},
		},
		{
			Value: "lestrrat+github@gmail.com",
			Key:   openid.EmailKey,
			Check: func(token openid.Token) {
				v, ok := token.Email()
				require.True(t, ok, `token.Email should succeed`)
				require.Equal(t, v, "lestrrat+github@gmail.com")
			},
		},
		{
			Value: true,
			Key:   openid.EmailVerifiedKey,
			Check: func(token openid.Token) {
				v, ok := token.EmailVerified()
				require.True(t, ok, `token.EmailVerified should succeed`)
				require.True(t, v, `values should match`)
			},
		},
		{
			Value: "n/a",
			Key:   openid.GenderKey,
			Check: func(token openid.Token) {
				v, ok := token.Gender()
				require.True(t, ok, `token.Gender should succeed`)
				require.Equal(t, v, "n/a", `values should match`)
			},
		},
		{
			Value: "2015-11-04",
			Key:   openid.BirthdateKey,
			Expected: func(v any) any {
				var b openid.BirthdateClaim
				if err := b.Accept(v); err != nil {
					panic(err)
				}
				return &b
			},
			Check: func(token openid.Token) {
				var b openid.BirthdateClaim
				b.Accept("2015-11-04")
				v, ok := token.Birthdate()
				require.True(t, ok, `token.Birthdate should succeed`)
				require.Equal(t, v, &b)
			},
		},
		{
			Value: "Asia/Tokyo",
			Key:   openid.ZoneinfoKey,
			Check: func(token openid.Token) {
				v, ok := token.Zoneinfo()
				require.True(t, ok, `token.Zoneinfo should succeed`)
				require.Equal(t, v, "Asia/Tokyo")
			},
		},
		{
			Value: "ja_JP",
			Key:   openid.LocaleKey,
			Check: func(token openid.Token) {
				v, ok := token.Locale()
				require.True(t, ok, `token.Locale should succeed`)
				require.Equal(t, v, "ja_JP")
			},
		},
		{
			Value: "819012345678",
			Key:   openid.PhoneNumberKey,
			Check: func(token openid.Token) {
				v, ok := token.PhoneNumber()
				require.True(t, ok, `token.PhoneNumber should succeed`)
				require.Equal(t, v, "819012345678")
			},
		},
		{
			Value: true,
			Key:   openid.PhoneNumberVerifiedKey,
			Check: func(token openid.Token) {
				v, ok := token.PhoneNumberVerified()
				require.True(t, ok, `token.PhoneNumberVerified should succeed`)
				require.True(t, v)
			},
		},
		{
			Value: map[string]any{
				"formatted":      "〒105-0011 東京都港区芝公園４丁目２−８",
				"street_address": "芝公園４丁目２−８",
				"locality":       "港区",
				"region":         "東京都",
				"country":        "日本",
				"postal_code":    "105-0011",
			},
			Key: openid.AddressKey,
			Expected: func(v any) any {
				address := openid.NewAddress()
				m, ok := v.(map[string]any)
				if !ok {
					panic(fmt.Sprintf("expected map[string]any, got %T", v))
				}
				for name, val := range m {
					require.NoError(t, address.Set(name, val), `address.Set should succeed`)
				}
				return address
			},
			Check: func(token openid.Token) {
				v, ok := token.Address()
				require.True(t, ok, `token.Address should succeed`)
				testStockAddressClaim(t, v)
			},
		},
		{
			Value: aLongLongTimeAgoString,
			Key:   openid.UpdatedAtKey,
			Expected: func(v any) any {
				var n types.NumericDate
				if err := n.Accept(v); err != nil {
					panic(err)
				}
				return n.Get()
			},
			Check: func(token openid.Token) {
				v, ok := token.UpdatedAt()
				require.True(t, ok, `token.UpdatedAt should succeed`)
				require.Equal(t, time.Unix(aLongLongTimeAgo, 0).UTC(), v)
			},
		},
		{
			Value: `dummy`,
			Key:   `dummy`,
			Check: func(token openid.Token) {
				v, ok := token.Field(`dummy`)
				require.True(t, ok, `token.Field should succeed`)
				require.Equal(t, `dummy`, v, `values should match`)
			},
		},
	}

	var data = map[string]any{}
	var expected = map[string]any{}
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
		require.NoError(t, err, `b.Build() should succeed`)
		tokens = append(tokens, openidTokTestCase{Name: `token constructed by calling Set()`, Token: token})
	}

	{ // two with json.Marshal / json.Unmarshal
		src, err := json.MarshalIndent(data, "", "  ")
		require.NoError(t, err, `failed to marshal base map`)

		t.Logf("Using source JSON: %s", src)

		token := openid.New()
		require.NoError(t, json.Unmarshal(src, &token), `json.Unmarshal should succeed`)
		tokens = append(tokens, openidTokTestCase{Name: `token constructed by Marshal(map)+Unmashal`, Token: token})

		// One more... Marshal the token, _and_ re-unmarshal
		buf, err := json.Marshal(token)
		require.NoError(t, err, `json.Marshal should succeed`)

		token2 := openid.New()
		require.NoError(t, json.Unmarshal(buf, &token2), `json.Unmarshal should succeed`)
		tokens = append(tokens, openidTokTestCase{Name: `token constructed by Marshal(openid.Token)+Unmashal`, Token: token2})

		// Sign it, and use jwt.Parse

		var token3 openid.Token
		{
			alg := jwa.RS256()
			key, err := jwxtest.GenerateRsaKey()
			require.NoError(t, err, `rsa.GeneraKey should succeed`)
			signed, err := jwt.Sign(token, jwt.WithKey(alg, key))
			require.NoError(t, err, `jwt.Sign should succeed`)

			tokenTmp, err := jwt.Parse(signed, jwt.WithToken(openid.New()), jwt.WithKey(alg, &key.PublicKey), jwt.WithValidate(false))
			require.NoError(t, err, `parsing the token via jwt.Parse should succeed`)

			// Check if token is an OpenID token
			if _, ok := tokenTmp.(openid.Token); !assert.True(t, ok, `token should be a openid.Token (%T)`, tokenTmp) {
				return
			}
			token3 = tokenTmp.(openid.Token)
		}

		tokens = append(tokens, openidTokTestCase{Name: `token constructed by jwt.Parse`, Token: token3})
	}

	for _, token := range tokens {
		t.Run(token.Name, func(t *testing.T) {
			for _, value := range base {
				t.Run(value.Key, func(_ *testing.T) {
					value.Check(token.Token)
				})
				t.Run(value.Key+" via Get()", func(_ *testing.T) {
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
		tok := tokens[0].Token
		t.Run("Iterate", func(t *testing.T) {
			seen := make(map[string]any)
			for _, k := range tok.Keys() {
				v, ok := tok.Field(k)
				require.True(t, ok, `tok.Field should succeed`)
				seen[k] = v
			}
			require.Equal(t, expected, seen, `values should match`)
		})
		t.Run("Clone", func(t *testing.T) {
			cloned, err := tok.Clone()
			require.NoError(t, err, `tok.Clone should succeed`)
			require.True(t, jwt.Equal(tok, cloned), `values should match`)
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
				Year:   0, // year 0000 means omitted per OIDC spec
				Month:  1,
				Day:    1,
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
			t.Run(tc.Source, func(t *testing.T) {
				var b openid.BirthdateClaim
				if tc.Error {
					assert.Error(t, json.Unmarshal([]byte(tc.Source), &b), `json.Unmarshal should fail`)
					return
				}

				require.NoError(t, json.Unmarshal([]byte(tc.Source), &b), `json.Unmarshal should succeed`)
				require.Equal(t, b.Year(), tc.Year, "year should match")
				require.Equal(t, b.Month(), tc.Month, "month should match")
				require.Equal(t, b.Day(), tc.Day, "day should match")
				serialized, err := json.Marshal(b)
				require.NoError(t, err, `json.Marshal should succeed`)
				require.Equal(t, string(serialized), tc.Source, `serialized format should be the same`)
				stringified := b.String()
				expectedString, _ := strconv.Unquote(tc.Source)
				require.Equal(t, stringified, expectedString, `stringified format should be the same`)
			})
		}
	})
	t.Run("empty date", func(t *testing.T) {
		t.Parallel()
		var b openid.BirthdateClaim
		require.Equal(t, b.Year(), 0, "year should match")
		require.Equal(t, b.Month(), 0, "month should match")
		require.Equal(t, b.Day(), 0, "day should match")
	})
	t.Run("invalid accept", func(t *testing.T) {
		t.Parallel()
		var b openid.BirthdateClaim
		require.Error(t, b.Accept(nil))
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
				v, ok := tok.UpdatedAt()
				require.True(t, ok, `updated_at should be set`)
				require.Equal(t, expected, v, `updated_at should match`)
			}
		})
	}
	jwt.Settings(jwt.WithNumericDateParsePedantic(false))
}

func TestWithBase64Encoder(t *testing.T) {
	// see #1324
	t.Run("Roundtrip", func(t *testing.T) {
		key, err := jwxtest.GenerateEcdsaKey(jwa.P256())
		require.NoError(t, err)

		tok, err := openid.NewBuilder().
			Subject("subject").
			Name("John Smith").
			Locale("CA").
			Email("john@example.org").
			PreferredUsername("john@example.org").
			GivenName("John").
			FamilyName("Smith").
			EmailVerified(false).
			Issuer("https://example.org/oauth2/default").
			Build()
		require.NoError(t, err, `openid.NewBuilder should succeed`)

		signed, err := jwt.Sign(tok, jwt.WithKey(jwa.ES256(), key), jwt.WithBase64Encoder(base64.URLEncoding))
		require.NoError(t, err, `jwt.Sign should succeed`)

		parsed := openid.New()
		_, err = jwt.Parse(signed, jwt.WithToken(parsed), jwt.WithKey(jwa.ES256(), key.PublicKey), jwt.WithBase64Encoder(base64.URLEncoding))
		require.NoError(t, err, `jwt.Parse should succeed`)
		require.Equal(t, tok, parsed, `parsed token should match original`)
	})
	t.Run("Contributed Test Case", func(t *testing.T) {
		key, err := jwxtest.GenerateEcdsaKey(jwa.P256())
		require.NoError(t, err)

		// ALB JWTs usually expire very quickly, but this one isn't real and isn't
		// signed by AWS so we'll make it an hour to be less tedious.
		expiry := time.Now().Add(time.Hour).Unix()

		// Generate header + payload
		header := map[string]any{
			"typ":    "JWT",
			"kid":    "2563ee81-616e-4a38-b2f8-48a2cccba80f", // Not a real AWS Key ID
			"alg":    "ES256",
			"iss":    "https://example.org/oauth2/default",
			"client": "a-client-id",
			"signer": "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/an-alb-name/abcdef0123456789", // Not real
			"exp":    expiry,
		}

		payload := map[string]any{
			"sub":                "some-subject-id",
			"name":               "John Smith",
			"locale":             "CA",
			"email":              "john@example.org",
			"preferred_username": "john@example.org",
			"given_name":         "John",
			"family_name":        "Smith",
			"zone_info":          "America/Winnipeg",
			"updated_at":         time.Date(2025, time.March, 0, 0, 0, 0, 0, time.UTC).Unix(),
			"email_verified":     false,
			"exp":                expiry,
			"iss":                "https://example.org/oauth2/default",
		}

		// Marshal header+bytes
		headerBytes, _ := json.Marshal(header)
		payloadBytes, _ := json.Marshal(payload)

		// Ok here's where it gets weird. AWS pads all base64-encoded components,
		// including the header, payload, and signature (they do however use the URL
		// encoding format). The following is _not_ specs compliant and should not be
		// used as an example of how to create + sign JWT.
		//
		// We want some test cases involving these JWTs though, so we have to generate
		// them the "wrong" way to be consistent with what we see from ALBs.
		headerEncoded := base64.URLEncoding.EncodeToString(headerBytes)
		payloadEncoded := base64.URLEncoding.EncodeToString(payloadBytes)

		// Assemble `<header>.<payload>`
		var buf bytes.Buffer
		buf.WriteString(headerEncoded)
		buf.WriteRune(tokens.Period)
		buf.WriteString(payloadEncoded)

		// Sign
		h := sha256.New()
		_, _ = h.Write(buf.Bytes())

		curveBits := key.Curve.Params().BitSize
		r, s, err := ecdsa.Sign(rand.Reader, key, h.Sum(nil))
		require.NoError(t, err, `ecdsa.Sign should succeed`)
		keyBytes := curveBits / 8
		// Curve bits do not need to be a multiple of 8.
		if curveBits%8 > 0 {
			keyBytes++
		}

		rBytes := r.Bytes()
		rBytesPadded := make([]byte, keyBytes)
		copy(rBytesPadded[keyBytes-len(rBytes):], rBytes)

		sBytes := s.Bytes()
		sBytesPadded := make([]byte, keyBytes)
		copy(sBytesPadded[keyBytes-len(sBytes):], sBytes)

		signature := append(rBytesPadded, sBytesPadded...)

		// Encode the signature, also URL-encoded + padding
		signatureEncoded := base64.URLEncoding.EncodeToString(signature)

		// Tack on signature to get `<header>.<payload>.<signature>`
		buf.WriteRune(tokens.Period)
		buf.WriteString(signatureEncoded)

		_, err = jwt.Parse(buf.Bytes(), jwt.WithBase64Encoder(base64.URLEncoding), jwt.WithKey(jwa.ES256(), key))
		require.NoError(t, err, `jwt.Parse should succeed`)
	})
}
