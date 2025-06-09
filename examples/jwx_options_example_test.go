package examples_test

import (
	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jws"
)

func Example_jwx_options() {
	// Most functions under the jwx module can take options as variadic arguments
	// that control how the function behaves. For example, the `jws.Sign` function
	// can take options that control how the signature is created, such as the
	// algorithm + key used, whether to use a compact or JSON serialization, and so on.
	_, _ = jws.Sign([]byte("message"), jws.WithKey(jwa.HS256(), []byte("key")), jws.WithJSON())

	// But if you are doing this a lot, or if you are in a tight loop, the
	// variadic options create a lot of allocation overhead, because they
	// create a slice of options every time you call the function.
	//
	// To avoid this, you can create a opion.Set[T] object that corresponds to
	// the options you want to use, and pass that to the function instead.
	// The above example can be rewritten as:
	opts := jws.SignOptionListPool().Get()
	defer jws.SignOptionListPool().Put(opts)
	opts.Add(jws.WithKey(jwa.HS256(), []byte("key")))
	opts.Add(jws.WithJSON())

	for range 10 { // imitate a tight loop
		_, _ = jws.Sign([]byte("message"), opts.List()...)

	}
}
