package jwt

import (
	"encoding/json"
	"log"
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
