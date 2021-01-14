# Sign and Verify a payload

```go
func ExampleSign() {
	privkey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Printf("failed to create private key: %s", err)
		return
	}

	buf, err := jws.Sign([]byte("Lorem ipsum"), jwa.RS256, privkey)
	if err != nil {
		log.Printf("failed to sign payload: %s", err)
		return
	}

	log.Printf("%s", buf)

	verified, err := jws.Verify(buf, jwa.RS256, &privkey.PublicKey)
	if err != nil {
		log.Printf("failed to verify JWS message: %s", err)
		return
	}
	log.Printf("message verified!")

	// Do something with `verified` ....
	_ = verified
}
```

# Programatically manipulate `jws.Message`

```go
func ExampleMessage() {
	// initialization for the following variables have been omitted.
	// please see jws_example_test.go for details
	var decodedPayload, decodedSig1, decodedSig2 []byte
	var public1, protected1, public2, protected2 jws.Header

	// Construct a message. DO NOT use values that are base64 encoded
	m := jws.NewMessage().
		SetPayload(decodedPayload).
		AppendSignature(
			jws.NewSignature().
				SetSignature(decodedSig1).
				SetProtectedHeaders(public1).
				SetPublicHeaders(protected1),
		).
		AppendSignature(
			jws.NewSignature().
				SetSignature(decodedSig2).
				SetProtectedHeaders(public2).
				SetPublicHeaders(protected2),
		)

	buf, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		fmt.Printf("%s\n", err)
		return
	}

	_ = buf
}
```
