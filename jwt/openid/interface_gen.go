package openid

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
	Address() *AddressClaim

	Audience() []string

	Birthdate() *BirthdateClaim

	Email() string

	EmailVerified() bool

	Expiration() time.Time

	FamilyName() string

	Gender() string

	GivenName() string

	IssuedAt() time.Time

	Issuer() string

	JwtID() string

	Locale() string

	MiddleName() string

	Name() string

	Nickname() string

	NotBefore() time.Time

	PhoneNumber() string

	PhoneNumberVerified() bool

	Picture() string

	PreferredUsername() string

	Profile() string

	Subject() string

	UpdatedAt() time.Time

	Website() string

	Zoneinfo() string
	// HasAddress returns true if the `address` field
	// of the Token has been populated
	HasAddress() bool
	// HasAudience returns true if the `aud` field
	// of the Token has been populated
	HasAudience() bool
	// HasBirthdate returns true if the `birthdate` field
	// of the Token has been populated
	HasBirthdate() bool
	// HasEmail returns true if the `email` field
	// of the Token has been populated
	HasEmail() bool
	// HasEmailVerified returns true if the `email_verified` field
	// of the Token has been populated
	HasEmailVerified() bool
	// HasExpiration returns true if the `exp` field
	// of the Token has been populated
	HasExpiration() bool
	// HasFamilyName returns true if the `family_name` field
	// of the Token has been populated
	HasFamilyName() bool
	// HasGender returns true if the `gender` field
	// of the Token has been populated
	HasGender() bool
	// HasGivenName returns true if the `given_name` field
	// of the Token has been populated
	HasGivenName() bool
	// HasIssuedAt returns true if the `iat` field
	// of the Token has been populated
	HasIssuedAt() bool
	// HasIssuer returns true if the `iss` field
	// of the Token has been populated
	HasIssuer() bool
	// HasJwtID returns true if the `jti` field
	// of the Token has been populated
	HasJwtID() bool
	// HasLocale returns true if the `locale` field
	// of the Token has been populated
	HasLocale() bool
	// HasMiddleName returns true if the `middle_name` field
	// of the Token has been populated
	HasMiddleName() bool
	// HasName returns true if the `name` field
	// of the Token has been populated
	HasName() bool
	// HasNickname returns true if the `nickname` field
	// of the Token has been populated
	HasNickname() bool
	// HasNotBefore returns true if the `nbf` field
	// of the Token has been populated
	HasNotBefore() bool
	// HasPhoneNumber returns true if the `phone_number` field
	// of the Token has been populated
	HasPhoneNumber() bool
	// HasPhoneNumberVerified returns true if the `phone_number_verified` field
	// of the Token has been populated
	HasPhoneNumberVerified() bool
	// HasPicture returns true if the `picture` field
	// of the Token has been populated
	HasPicture() bool
	// HasPreferredUsername returns true if the `preferred_username` field
	// of the Token has been populated
	HasPreferredUsername() bool
	// HasProfile returns true if the `profile` field
	// of the Token has been populated
	HasProfile() bool
	// HasSubject returns true if the `sub` field
	// of the Token has been populated
	HasSubject() bool
	// HasUpdatedAt returns true if the `updated_at` field
	// of the Token has been populated
	HasUpdatedAt() bool
	// HasWebsite returns true if the `website` field
	// of the Token has been populated
	HasWebsite() bool
	// HasZoneinfo returns true if the `zoneinfo` field
	// of the Token has been populated
	HasZoneinfo() bool
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

	// Clone creates a new Token with the same content, and sets
	// the value into the first argument. The first argument must
	// be a pointer to a variable that can hold the resulting type
	Clone(interface{}) error

	// FieldNames returns the list of all keys in the token
	FieldNames() []string
}
