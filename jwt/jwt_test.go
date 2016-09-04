package jwt

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestClaimSet(t *testing.T) {
	c1 := NewClaimSet()
	c1.Set("jti", "AbCdEfG")
	c1.Set("sub", "foobar@example.com")
	now := time.Now()
	c1.Set("iat", now)
	c1.Set("nbf", now.Add(5*time.Second))
	c1.Set("exp", now.Add(10*time.Second))
	c1.Set("custom", "MyValue")

	jsonbuf1, err := json.MarshalIndent(c1, "", "  ")
	if !assert.NoError(t, err, "JSON marshal should succeed") {
		return
	}
	t.Logf("%s", jsonbuf1)

	c2 := NewClaimSet()
	if !assert.NoError(t, json.Unmarshal(jsonbuf1, c2), "JSON unmarshal should succeed") {
		return
	}

	jsonbuf2, err := json.MarshalIndent(c2, "", "  ")
	if !assert.NoError(t, err, "JSON marshal should succeed") {
		return
	}
	t.Logf("%s", jsonbuf2)

	if !assert.Equal(t, c1, c2, "Claim sets match") {
		return
	}
}
