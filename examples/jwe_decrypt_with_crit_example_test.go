package examples_test

import (
	"fmt"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwe"
	"github.com/lestrrat-go/jwx/v3/jwk"
)

// Example_jwe_decrypt_with_crit demonstrates RFC 7516 Section 4.1.13
// (which references RFC 7515 Section 4.1.11) "crit" (Critical) header
// validation using jwe.WithCritValidation and jwe.WithCritExtension.
//
// By default jwe.Decrypt ignores the "crit" header for backwards
// compatibility. Enable validation with jwe.WithCritValidation(true) and
// declare the extension names your application understands via
// jwe.WithCritExtension. The library will then reject any JWE whose
// "crit" list names an extension you have not declared.
func Example_jwe_decrypt_with_crit() {
	// 16-byte key for jwa.A128KW.
	key, err := jwk.Import([]byte(`0123456789abcdef`))
	if err != nil {
		fmt.Printf("failed to import key: %s\n", err)
		return
	}

	// Encrypt a payload with a protected "crit" header that references a
	// custom extension "x-wonka". The application is expected to process
	// "x-wonka" itself after a successful Decrypt.
	hdrs := jwe.NewHeaders()
	if err := hdrs.Set("x-wonka", "golden-ticket"); err != nil {
		fmt.Printf("failed to set header: %s\n", err)
		return
	}
	if err := hdrs.Set(jwe.CriticalKey, []string{"x-wonka"}); err != nil {
		fmt.Printf("failed to set crit: %s\n", err)
		return
	}

	encrypted, err := jwe.Encrypt([]byte(`Lorem ipsum`),
		jwe.WithKey(jwa.A128KW(), key),
		jwe.WithContentEncryption(jwa.A128CBC_HS256()),
		jwe.WithProtectedHeaders(hdrs),
	)
	if err != nil {
		fmt.Printf("failed to encrypt: %s\n", err)
		return
	}

	// 1. Default behavior (lax): the "crit" header is ignored entirely.
	//    Any JWE decrypts as long as the key is correct.
	if _, err := jwe.Decrypt(encrypted, jwe.WithKey(jwa.A128KW(), key)); err == nil {
		fmt.Println("default lax: decrypted")
	}

	// 2. Validation enabled but the application has not declared
	//    "x-wonka" as understood. Per RFC 7516 §4.1.13 the library MUST
	//    reject the message.
	if _, err := jwe.Decrypt(encrypted,
		jwe.WithKey(jwa.A128KW(), key),
		jwe.WithCritValidation(true),
	); err != nil {
		fmt.Println("strict, undeclared: rejected")
	}

	// 3. Validation enabled AND the application declares that it
	//    understands "x-wonka". Decryption succeeds.
	//
	//    IMPORTANT: declaring "x-wonka" via WithCritExtension is a
	//    promise to the library that this code will perform whatever
	//    check the extension actually requires. The library only
	//    confirms that "x-wonka" was declared; it has no idea what
	//    "x-wonka" means. Forgetting the post-decrypt step would silently
	//    defeat the protection the producer obtained by marking the
	//    extension critical. The block below shows the shape of that
	//    obligation.
	var msg jwe.Message
	decrypted, err := jwe.Decrypt(encrypted,
		jwe.WithKey(jwa.A128KW(), key),
		jwe.WithCritValidation(true),
		jwe.WithCritExtension("x-wonka"),
		jwe.WithMessage(&msg),
	)
	if err == nil {
		var ticket string
		if err := msg.ProtectedHeaders().Get("x-wonka", &ticket); err != nil {
			fmt.Printf("failed to read x-wonka: %s\n", err)
			return
		}
		// Application-specific check: in this fictional example, the
		// only acceptable ticket is "golden-ticket". A failure here
		// MUST be treated as a decryption failure even though
		// jwe.Decrypt returned no error.
		if ticket != "golden-ticket" {
			fmt.Println("strict, declared: x-wonka check failed (treat as decrypt failure)")
			return
		}
		fmt.Printf("strict, declared: decrypted, payload=%s\n", decrypted)
	}

	// WithCritExtension is variadic and accumulating: a single call may
	// register multiple names, and multiple calls also append. Use the
	// shape that reads best at the call site.
	//
	//   jwe.WithCritExtension("x-wonka", "x-oompa")
	//   jwe.WithCritExtension("x-wonka")
	//   jwe.WithCritExtension("x-oompa")

	// OUTPUT:
	// default lax: decrypted
	// strict, undeclared: rejected
	// strict, declared: decrypted, payload=Lorem ipsum
}
