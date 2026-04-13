package examples_test

import (
	"fmt"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jws"
)

// Example_jws_verify_with_crit demonstrates RFC 7515 Section 4.1.11
// "crit" (Critical) header validation using jws.WithCritValidation and
// jws.WithCritExtension.
//
// By default jws.Verify ignores the "crit" header for backwards
// compatibility. Enable validation with jws.WithCritValidation(true) and
// declare the extension names your application understands via
// jws.WithCritExtension. The library will then reject any JWS whose
// "crit" list names an extension you have not declared.
func Example_jws_verify_with_crit() {
	key, err := jwk.Import([]byte(`abracadabra`))
	if err != nil {
		fmt.Printf("failed to import key: %s\n", err)
		return
	}

	// Sign a payload with a protected "crit" header that references a
	// custom extension "x-wonka". The application is expected to process
	// "x-wonka" itself after a successful Verify.
	hdrs := jws.NewHeaders()
	if err := hdrs.Set("x-wonka", "golden-ticket"); err != nil {
		fmt.Printf("failed to set header: %s\n", err)
		return
	}
	if err := hdrs.Set(jws.CriticalKey, []string{"x-wonka"}); err != nil {
		fmt.Printf("failed to set crit: %s\n", err)
		return
	}

	signed, err := jws.Sign([]byte(`Lorem ipsum`),
		jws.WithKey(jwa.HS256(), key, jws.WithProtectedHeaders(hdrs)),
	)
	if err != nil {
		fmt.Printf("failed to sign: %s\n", err)
		return
	}

	// 1. Default behavior (lax): the "crit" header is ignored entirely.
	//    Any JWS verifies as long as the signature is valid.
	if _, err := jws.Verify(signed, jws.WithKey(jwa.HS256(), key)); err == nil {
		fmt.Println("default lax: verified")
	}

	// 2. Validation enabled but the application has not declared
	//    "x-wonka" as understood. Per RFC 7515 the library MUST reject
	//    the message.
	if _, err := jws.Verify(signed,
		jws.WithKey(jwa.HS256(), key),
		jws.WithCritValidation(true),
	); err != nil {
		fmt.Println("strict, undeclared: rejected")
	}

	// 3. Validation enabled AND the application declares that it
	//    understands "x-wonka". Verification succeeds.
	//
	//    IMPORTANT: declaring "x-wonka" via WithCritExtension is a
	//    promise to the library that this code will perform whatever
	//    check the extension actually requires. The library only
	//    confirms that "x-wonka" was declared; it has no idea what
	//    "x-wonka" means. Forgetting the post-verify step would silently
	//    defeat the protection the producer obtained by marking the
	//    extension critical. The block below shows the shape of that
	//    obligation.
	verified, err := jws.Verify(signed,
		jws.WithKey(jwa.HS256(), key),
		jws.WithCritValidation(true),
		jws.WithCritExtension("x-wonka"),
	)
	if err == nil {
		// Re-parse the message so we can read the protected header
		// fields. In real code you would typically parse and verify
		// in a single pass via jws.WithMessage.
		msg, err := jws.Parse(signed)
		if err != nil {
			fmt.Printf("failed to parse for header inspection: %s\n", err)
			return
		}
		var ticket string
		if err := msg.Signatures()[0].ProtectedHeaders().Get("x-wonka", &ticket); err != nil {
			fmt.Printf("failed to read x-wonka: %s\n", err)
			return
		}
		// Application-specific check: in this fictional example, the
		// only acceptable ticket is "golden-ticket". A failure here
		// MUST be treated as a verification failure even though
		// jws.Verify returned no error.
		if ticket != "golden-ticket" {
			fmt.Println("strict, declared: x-wonka check failed (treat as verify failure)")
			return
		}
		fmt.Printf("strict, declared: verified, payload=%s\n", verified)
	}

	// WithCritExtension is variadic and accumulating: a single call may
	// register multiple names, and multiple calls also append. Use the
	// shape that reads best at the call site.
	//
	//   jws.WithCritExtension("x-wonka", "x-oompa")
	//   jws.WithCritExtension("x-wonka")
	//   jws.WithCritExtension("x-oompa")

	// OUTPUT:
	// default lax: verified
	// strict, undeclared: rejected
	// strict, declared: verified, payload=Lorem ipsum
}
