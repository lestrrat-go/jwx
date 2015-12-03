package jwk

import "log"

func Example() {
	set, err := FetchHTTP("https://foobar.domain/json")
	if err != nil {
		log.Printf("failed to parse JWK: %s", err)
		return
	}

	// If you KNOW you have exactly one key, you can just
	// use set.Keys[0]
	keys := set.LookupKeyID("mykey")
	if len(keys) == 0 {
		log.Printf("failed to lookup key: %s", err)
		return
	}

	key, err := keys[0].Materialize()
	if err != nil {
		log.Printf("failed to generate public key: %s", err)
		return
	}
	// Use key for jws.Verify() or whatever
	_ = key
}
