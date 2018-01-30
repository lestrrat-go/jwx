package jwt_test

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/lestrrat/go-jwx/jwt"
	"github.com/stretchr/testify/assert"
)

const aLongLongTimeAgo = 233431200
const aLongLongTimeAgoString = "233431200"

func TestUnmarshal(t *testing.T) {
	testcases := []struct {
		Title    string
		JSON     string
		Expected func() *jwt.Token
	}{
		{
			Title: "single aud",
			JSON:  `{"aud":"foo"}`,
			Expected: func() *jwt.Token {
				t := jwt.New()
				t.Set("aud", "foo")
				return t
			},
		},
		{
			Title: "multiple aud's",
			JSON:  `{"aud":["foo","bar"]}`,
			Expected: func() *jwt.Token {
				t := jwt.New()
				t.Set("aud", []string{"foo", "bar"})
				return t
			},
		},
		{
			Title: "issuedAt",
			JSON:  `{"` + jwt.IssuedAtKey + `":` + aLongLongTimeAgoString + `}`,
			Expected: func() *jwt.Token {
				t := jwt.New()
				t.Set(jwt.IssuedAtKey, aLongLongTimeAgo)
				return t
			},
		},
	}

	for _, tc := range testcases {
		t.Run(tc.Title, func(t *testing.T) {
			var token jwt.Token
			if !assert.NoError(t, json.Unmarshal([]byte(tc.JSON), &token), `json.Unmarshal should succeed`) {
				return
			}
			if !assert.Equal(t, tc.Expected(), &token, `token should match expeted value`) {
				return
			}

			var buf bytes.Buffer
			if !assert.NoError(t, json.NewEncoder(&buf).Encode(token), `json.Marshal should succeed`) {
				return
			}
			if !assert.Equal(t, tc.JSON, strings.TrimSpace(buf.String()), `json should match`) {
				return
			}
		})
	}
}

func TestGet(t *testing.T) {
	testcases := []struct {
		Title string
		Test  func(*testing.T, *jwt.Token)
		Token func() *jwt.Token
	}{
		{
			Title: `Get IssuedAt`,
			Test: func(t *testing.T, token *jwt.Token) {
				expected := time.Unix(aLongLongTimeAgo, 0)
				if !assert.Equal(t, expected, token.IssuedAt(), `IssuedAt should match`) {
					return
				}
			},
			Token: func() *jwt.Token {
				t := jwt.New()
				t.Set(jwt.IssuedAtKey, 233431200)
				return t
			},
		},
	}

	for _, tc := range testcases {
		t.Run(tc.Title, func(t *testing.T) {
			tc.Test(t, tc.Token())
		})
	}
}
