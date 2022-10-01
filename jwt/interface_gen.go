package jwt

import "time"

// Token represents a generic JWT token.
// which are type-aware (to an extent). Other claims may be accessed via the `Get`/`Set`
// methods but their types are not taken into consideration at all. If you have non-standard
// claims that you must frequently access, consider creating accessors functions
// like the following
//
// func SetFoo(tok jwt.Token) error
// func GetFoo(tok jwt.Token) (*Customtyp, error)
//
// Embedding jwt.Token into another struct is not recommended, because
// jwt.Token needs to handle private claims, and this really does not
// work well when it is embedded in other structure
type Token interface {
	// Audience represents the `aud` field as described in https://tools.ietf.org/html/rfc7519#section-4.1.3
	Audience() []string
	// Expiration represents the `exp` field as described in https://tools.ietf.org/html/rfc7519#section-4.1.4
	Expiration() time.Time
	// IssuedAt represents the `iat` field as described in https://tools.ietf.org/html/rfc7519#section-4.1.6
	IssuedAt() time.Time
	// Issuer represents the `iss` field as described in https://tools.ietf.org/html/rfc7519#section-4.1.1
	Issuer() string
	// JwtID represents the `jti` field as described in https://tools.ietf.org/html/rfc7519#section-4.1.7
	JwtID() string
	// NotBefore represents the `nbf` field as described in https://tools.ietf.org/html/rfc7519#section-4.1.5
	NotBefore() time.Time
	// Subject represents the `sub` field as described in https://tools.ietf.org/html/rfc7519#section-4.1.2
	Subject() string
	// HasAudience returns true if the `aud` field
	// of the Token has been populated
	HasAudience() bool
	// HasExpiration returns true if the `exp` field
	// of the Token has been populated
	HasExpiration() bool
	// HasIssuedAt returns true if the `iat` field
	// of the Token has been populated
	HasIssuedAt() bool
	// HasIssuer returns true if the `iss` field
	// of the Token has been populated
	HasIssuer() bool
	// HasJwtID returns true if the `jti` field
	// of the Token has been populated
	HasJwtID() bool
	// HasNotBefore returns true if the `nbf` field
	// of the Token has been populated
	HasNotBefore() bool
	// HasSubject returns true if the `sub` field
	// of the Token has been populated
	HasSubject() bool
	// Get retrieves the value of the corresponding field in the token, such as
	// `nbf`, `exp`, `iat`, and other user-defined fields.
	//
	// The first argument to `Get` must be the JSON field name, not the
	// Go structure's field name.
	//
	// The second argument must be a pointer to either a raw `interface{}`
	// or a Go variable capable of holding the value of the field. For example
	// for a field that should contain a `string`, you can declared a variable
	// `var s string` and pass a pointer to it as `&s`. For fields which you
	// do not know the type of, you can declared a variable such as `var v interface{}`
	// and pass a pointer to it as `&v'. If the second argument is not of
	// a proper type, an error is returned.
	//
	// If the field does not exist in the token, `Get` will return an error.
	//
	// Note that this method only retrieves values for the JWT, not JWE or JWS.
	// If you need to access fields like `alg`, `kid`, `jku`, etc, you need
	// to access the corresponding fields in the JWS/JWE message. For this,
	// you will need to access them by directly parsing the payload using
	// `jws.Parse` and `jwe.Parse`
	Get(string, interface{}) error

	// Set assigns a value to the corresponding field in the token.
	//
	// The first argument to `Set` must be the JSON field name, not the
	// Go structure's field name.
	//
	// The second argument is the value to be set. For pre-defined fields such
	// as `nbf`, `iat`, `iss` the value must be of specific types.
	// See the builder or the getter methods for pre-defined types to learn what
	// the types for these pre-defined fields must be.
	//
	// For extra fields, `Set` accepts any value.
	Set(string, interface{}) error

	// Has returns true if the corresponding field is populated in the token.
	//
	// The first argument to `Has` must be the JSON field name, not the
	// Go structure's field name.
	Has(string) bool

	// Remove removes the corresponding field from the Token.
	//
	// The first argument to `Remove` must be the JSON field name, not the
	// Go structure's field name.
	Remove(string) error

	// Clone returns a new Token with the same content
	Clone() (Token, error)

	// Keys returns the list of all keys in the token
	Keys() []string
}
