package jwt

import (
	"encoding/json"
	"log"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func ExampleClaimSet() {
	c := NewClaimSet()
	c.Set("sub", "123456789")
	c.Set("aud", "foo")
	c.Set("https://github.com/lestrrat", "me")

	buf, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		log.Printf("failed to generate JSON: %s", err)
		return
	}

	log.Printf("%s", buf)
	log.Printf("sub     -> '%s'", c.Get("sub").(string))
	log.Printf("aud     -> '%v'", c.Get("aud").([]string))
	log.Printf("private -> '%s'", c.Get("https://github.com/lestrrat").(string))
}

func TestClaimSet(t *testing.T) {
	c1 := NewClaimSet()
	c1.Set("nonce", "AbCdEfG")
	c1.Set("sub", "foobar@example.com")
	c1.Set("iat", time.Now().Unix())

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