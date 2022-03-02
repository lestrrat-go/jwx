// This file is auto-generated by jwt/internal/cmd/gentoken/main.go. DO NOT EDIT

package openid

import (
	"bytes"
	"context"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/lestrrat-go/iter/mapiter"
	"github.com/lestrrat-go/jwx/v2/internal/base64"
	"github.com/lestrrat-go/jwx/v2/internal/iter"
	"github.com/lestrrat-go/jwx/v2/internal/json"
	"github.com/lestrrat-go/jwx/v2/internal/pool"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/lestrrat-go/jwx/v2/jwt/internal/types"
)

const (
	AddressKey             = "address"
	AudienceKey            = "aud"
	BirthdateKey           = "birthdate"
	EmailKey               = "email"
	EmailVerifiedKey       = "email_verified"
	ExpirationKey          = "exp"
	FamilyNameKey          = "family_name"
	GenderKey              = "gender"
	GivenNameKey           = "given_name"
	IssuedAtKey            = "iat"
	IssuerKey              = "iss"
	JwtIDKey               = "jti"
	LocaleKey              = "locale"
	MiddleNameKey          = "middle_name"
	NameKey                = "name"
	NicknameKey            = "nickname"
	NotBeforeKey           = "nbf"
	PhoneNumberKey         = "phone_number"
	PhoneNumberVerifiedKey = "phone_number_verified"
	PictureKey             = "picture"
	PreferredUsernameKey   = "preferred_username"
	ProfileKey             = "profile"
	SubjectKey             = "sub"
	UpdatedAtKey           = "updated_at"
	WebsiteKey             = "website"
	ZoneinfoKey            = "zoneinfo"
)

type Token interface {

	// Address returns the value for "address" field of the token
	Address() *AddressClaim

	// Audience returns the value for "aud" field of the token
	Audience() []string

	// Birthdate returns the value for "birthdate" field of the token
	Birthdate() *BirthdateClaim

	// Email returns the value for "email" field of the token
	Email() string

	// EmailVerified returns the value for "email_verified" field of the token
	EmailVerified() bool

	// Expiration returns the value for "exp" field of the token
	Expiration() time.Time

	// FamilyName returns the value for "family_name" field of the token
	FamilyName() string

	// Gender returns the value for "gender" field of the token
	Gender() string

	// GivenName returns the value for "given_name" field of the token
	GivenName() string

	// IssuedAt returns the value for "iat" field of the token
	IssuedAt() time.Time

	// Issuer returns the value for "iss" field of the token
	Issuer() string

	// JwtID returns the value for "jti" field of the token
	JwtID() string

	// Locale returns the value for "locale" field of the token
	Locale() string

	// MiddleName returns the value for "middle_name" field of the token
	MiddleName() string

	// Name returns the value for "name" field of the token
	Name() string

	// Nickname returns the value for "nickname" field of the token
	Nickname() string

	// NotBefore returns the value for "nbf" field of the token
	NotBefore() time.Time

	// PhoneNumber returns the value for "phone_number" field of the token
	PhoneNumber() string

	// PhoneNumberVerified returns the value for "phone_number_verified" field of the token
	PhoneNumberVerified() bool

	// Picture returns the value for "picture" field of the token
	Picture() string

	// PreferredUsername returns the value for "preferred_username" field of the token
	PreferredUsername() string

	// Profile returns the value for "profile" field of the token
	Profile() string

	// Subject returns the value for "sub" field of the token
	Subject() string

	// UpdatedAt returns the value for "updated_at" field of the token
	UpdatedAt() time.Time

	// Website returns the value for "website" field of the token
	Website() string

	// Zoneinfo returns the value for "zoneinfo" field of the token
	Zoneinfo() string

	// PrivateClaims return the entire set of fields (claims) in the token
	// *other* than the pre-defined fields such as `iss`, `nbf`, `iat`, etc.
	PrivateClaims() map[string]interface{}

	// Get returns the value of the corresponding field in the token, such as
	// `nbf`, `exp`, `iat`, and other user-defined fields. If the field does not
	// exist in the token, the second return value will be `false`
	//
	// If you need to access fields like `alg`, `kid`, `jku`, etc, you need
	// to access the corresponding fields in the JWS/JWE message. For this,
	// you will need to access them by directly parsing the payload using
	// `jws.Parse` and `jwe.Parse`
	Get(string) (interface{}, bool)

	// Set assigns a value to the corresponding field in the token. Some
	// pre-defined fields such as `nbf`, `iat`, `iss` need their values to
	// be of a specific type. See the other getter methods in this interface
	// for the types of each of these fields
	Set(string, interface{}) error
	Remove(string) error
	Clone() (jwt.Token, error)
	Iterate(context.Context) Iterator
	Walk(context.Context, Visitor) error
	AsMap(context.Context) (map[string]interface{}, error)
}
type stdToken struct {
	mu                  *sync.RWMutex
	dc                  DecodeCtx // per-object context for decoding
	address             *AddressClaim
	audience            types.StringList // https://tools.ietf.org/html/rfc7519#section-4.1.3
	birthdate           *BirthdateClaim
	email               *string
	emailVerified       *bool
	expiration          *types.NumericDate // https://tools.ietf.org/html/rfc7519#section-4.1.4
	familyName          *string
	gender              *string
	givenName           *string
	issuedAt            *types.NumericDate // https://tools.ietf.org/html/rfc7519#section-4.1.6
	issuer              *string            // https://tools.ietf.org/html/rfc7519#section-4.1.1
	jwtID               *string            // https://tools.ietf.org/html/rfc7519#section-4.1.7
	locale              *string
	middleName          *string
	name                *string
	nickname            *string
	notBefore           *types.NumericDate // https://tools.ietf.org/html/rfc7519#section-4.1.5
	phoneNumber         *string
	phoneNumberVerified *bool
	picture             *string
	preferredUsername   *string
	profile             *string
	subject             *string // https://tools.ietf.org/html/rfc7519#section-4.1.2
	updatedAt           *types.NumericDate
	website             *string
	zoneinfo            *string
	privateClaims       map[string]interface{}
}

// New creates a standard token, with minimal knowledge of
// possible claims. Standard claims include"address", "aud", "birthdate", "email", "email_verified", "exp", "family_name", "gender", "given_name", "iat", "iss", "jti", "locale", "middle_name", "name", "nickname", "nbf", "phone_number", "phone_number_verified", "picture", "preferred_username", "profile", "sub", "updated_at", "website" and "zoneinfo".
// Convenience accessors are provided for these standard claims
func New() Token {
	return &stdToken{
		mu:            &sync.RWMutex{},
		privateClaims: make(map[string]interface{}),
	}
}

func (t *stdToken) Get(name string) (interface{}, bool) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	switch name {
	case AddressKey:
		if t.address == nil {
			return nil, false
		}
		v := t.address
		return v, true
	case AudienceKey:
		if t.audience == nil {
			return nil, false
		}
		v := t.audience.Get()
		return v, true
	case BirthdateKey:
		if t.birthdate == nil {
			return nil, false
		}
		v := t.birthdate
		return v, true
	case EmailKey:
		if t.email == nil {
			return nil, false
		}
		v := *(t.email)
		return v, true
	case EmailVerifiedKey:
		if t.emailVerified == nil {
			return nil, false
		}
		v := *(t.emailVerified)
		return v, true
	case ExpirationKey:
		if t.expiration == nil {
			return nil, false
		}
		v := t.expiration.Get()
		return v, true
	case FamilyNameKey:
		if t.familyName == nil {
			return nil, false
		}
		v := *(t.familyName)
		return v, true
	case GenderKey:
		if t.gender == nil {
			return nil, false
		}
		v := *(t.gender)
		return v, true
	case GivenNameKey:
		if t.givenName == nil {
			return nil, false
		}
		v := *(t.givenName)
		return v, true
	case IssuedAtKey:
		if t.issuedAt == nil {
			return nil, false
		}
		v := t.issuedAt.Get()
		return v, true
	case IssuerKey:
		if t.issuer == nil {
			return nil, false
		}
		v := *(t.issuer)
		return v, true
	case JwtIDKey:
		if t.jwtID == nil {
			return nil, false
		}
		v := *(t.jwtID)
		return v, true
	case LocaleKey:
		if t.locale == nil {
			return nil, false
		}
		v := *(t.locale)
		return v, true
	case MiddleNameKey:
		if t.middleName == nil {
			return nil, false
		}
		v := *(t.middleName)
		return v, true
	case NameKey:
		if t.name == nil {
			return nil, false
		}
		v := *(t.name)
		return v, true
	case NicknameKey:
		if t.nickname == nil {
			return nil, false
		}
		v := *(t.nickname)
		return v, true
	case NotBeforeKey:
		if t.notBefore == nil {
			return nil, false
		}
		v := t.notBefore.Get()
		return v, true
	case PhoneNumberKey:
		if t.phoneNumber == nil {
			return nil, false
		}
		v := *(t.phoneNumber)
		return v, true
	case PhoneNumberVerifiedKey:
		if t.phoneNumberVerified == nil {
			return nil, false
		}
		v := *(t.phoneNumberVerified)
		return v, true
	case PictureKey:
		if t.picture == nil {
			return nil, false
		}
		v := *(t.picture)
		return v, true
	case PreferredUsernameKey:
		if t.preferredUsername == nil {
			return nil, false
		}
		v := *(t.preferredUsername)
		return v, true
	case ProfileKey:
		if t.profile == nil {
			return nil, false
		}
		v := *(t.profile)
		return v, true
	case SubjectKey:
		if t.subject == nil {
			return nil, false
		}
		v := *(t.subject)
		return v, true
	case UpdatedAtKey:
		if t.updatedAt == nil {
			return nil, false
		}
		v := t.updatedAt.Get()
		return v, true
	case WebsiteKey:
		if t.website == nil {
			return nil, false
		}
		v := *(t.website)
		return v, true
	case ZoneinfoKey:
		if t.zoneinfo == nil {
			return nil, false
		}
		v := *(t.zoneinfo)
		return v, true
	default:
		v, ok := t.privateClaims[name]
		return v, ok
	}
}

func (t *stdToken) Remove(key string) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	switch key {
	case AddressKey:
		t.address = nil
	case AudienceKey:
		t.audience = nil
	case BirthdateKey:
		t.birthdate = nil
	case EmailKey:
		t.email = nil
	case EmailVerifiedKey:
		t.emailVerified = nil
	case ExpirationKey:
		t.expiration = nil
	case FamilyNameKey:
		t.familyName = nil
	case GenderKey:
		t.gender = nil
	case GivenNameKey:
		t.givenName = nil
	case IssuedAtKey:
		t.issuedAt = nil
	case IssuerKey:
		t.issuer = nil
	case JwtIDKey:
		t.jwtID = nil
	case LocaleKey:
		t.locale = nil
	case MiddleNameKey:
		t.middleName = nil
	case NameKey:
		t.name = nil
	case NicknameKey:
		t.nickname = nil
	case NotBeforeKey:
		t.notBefore = nil
	case PhoneNumberKey:
		t.phoneNumber = nil
	case PhoneNumberVerifiedKey:
		t.phoneNumberVerified = nil
	case PictureKey:
		t.picture = nil
	case PreferredUsernameKey:
		t.preferredUsername = nil
	case ProfileKey:
		t.profile = nil
	case SubjectKey:
		t.subject = nil
	case UpdatedAtKey:
		t.updatedAt = nil
	case WebsiteKey:
		t.website = nil
	case ZoneinfoKey:
		t.zoneinfo = nil
	default:
		delete(t.privateClaims, key)
	}
	return nil
}

func (t *stdToken) Set(name string, value interface{}) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.setNoLock(name, value)
}

func (t *stdToken) DecodeCtx() DecodeCtx {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.dc
}

func (t *stdToken) SetDecodeCtx(v DecodeCtx) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.dc = v
}

func (t *stdToken) setNoLock(name string, value interface{}) error {
	switch name {
	case AddressKey:
		var acceptor AddressClaim
		if err := acceptor.Accept(value); err != nil {
			return fmt.Errorf(`invalid value for %s key: %w`, AddressKey, err)
		}
		t.address = &acceptor
		return nil
	case AudienceKey:
		var acceptor types.StringList
		if err := acceptor.Accept(value); err != nil {
			return fmt.Errorf(`invalid value for %s key: %w`, AudienceKey, err)
		}
		t.audience = acceptor
		return nil
	case BirthdateKey:
		var acceptor BirthdateClaim
		if err := acceptor.Accept(value); err != nil {
			return fmt.Errorf(`invalid value for %s key: %w`, BirthdateKey, err)
		}
		t.birthdate = &acceptor
		return nil
	case EmailKey:
		if v, ok := value.(string); ok {
			t.email = &v
			return nil
		}
		return fmt.Errorf(`invalid value for %s key: %T`, EmailKey, value)
	case EmailVerifiedKey:
		if v, ok := value.(bool); ok {
			t.emailVerified = &v
			return nil
		}
		return fmt.Errorf(`invalid value for %s key: %T`, EmailVerifiedKey, value)
	case ExpirationKey:
		var acceptor types.NumericDate
		if err := acceptor.Accept(value); err != nil {
			return fmt.Errorf(`invalid value for %s key: %w`, ExpirationKey, err)
		}
		t.expiration = &acceptor
		return nil
	case FamilyNameKey:
		if v, ok := value.(string); ok {
			t.familyName = &v
			return nil
		}
		return fmt.Errorf(`invalid value for %s key: %T`, FamilyNameKey, value)
	case GenderKey:
		if v, ok := value.(string); ok {
			t.gender = &v
			return nil
		}
		return fmt.Errorf(`invalid value for %s key: %T`, GenderKey, value)
	case GivenNameKey:
		if v, ok := value.(string); ok {
			t.givenName = &v
			return nil
		}
		return fmt.Errorf(`invalid value for %s key: %T`, GivenNameKey, value)
	case IssuedAtKey:
		var acceptor types.NumericDate
		if err := acceptor.Accept(value); err != nil {
			return fmt.Errorf(`invalid value for %s key: %w`, IssuedAtKey, err)
		}
		t.issuedAt = &acceptor
		return nil
	case IssuerKey:
		if v, ok := value.(string); ok {
			t.issuer = &v
			return nil
		}
		return fmt.Errorf(`invalid value for %s key: %T`, IssuerKey, value)
	case JwtIDKey:
		if v, ok := value.(string); ok {
			t.jwtID = &v
			return nil
		}
		return fmt.Errorf(`invalid value for %s key: %T`, JwtIDKey, value)
	case LocaleKey:
		if v, ok := value.(string); ok {
			t.locale = &v
			return nil
		}
		return fmt.Errorf(`invalid value for %s key: %T`, LocaleKey, value)
	case MiddleNameKey:
		if v, ok := value.(string); ok {
			t.middleName = &v
			return nil
		}
		return fmt.Errorf(`invalid value for %s key: %T`, MiddleNameKey, value)
	case NameKey:
		if v, ok := value.(string); ok {
			t.name = &v
			return nil
		}
		return fmt.Errorf(`invalid value for %s key: %T`, NameKey, value)
	case NicknameKey:
		if v, ok := value.(string); ok {
			t.nickname = &v
			return nil
		}
		return fmt.Errorf(`invalid value for %s key: %T`, NicknameKey, value)
	case NotBeforeKey:
		var acceptor types.NumericDate
		if err := acceptor.Accept(value); err != nil {
			return fmt.Errorf(`invalid value for %s key: %w`, NotBeforeKey, err)
		}
		t.notBefore = &acceptor
		return nil
	case PhoneNumberKey:
		if v, ok := value.(string); ok {
			t.phoneNumber = &v
			return nil
		}
		return fmt.Errorf(`invalid value for %s key: %T`, PhoneNumberKey, value)
	case PhoneNumberVerifiedKey:
		if v, ok := value.(bool); ok {
			t.phoneNumberVerified = &v
			return nil
		}
		return fmt.Errorf(`invalid value for %s key: %T`, PhoneNumberVerifiedKey, value)
	case PictureKey:
		if v, ok := value.(string); ok {
			t.picture = &v
			return nil
		}
		return fmt.Errorf(`invalid value for %s key: %T`, PictureKey, value)
	case PreferredUsernameKey:
		if v, ok := value.(string); ok {
			t.preferredUsername = &v
			return nil
		}
		return fmt.Errorf(`invalid value for %s key: %T`, PreferredUsernameKey, value)
	case ProfileKey:
		if v, ok := value.(string); ok {
			t.profile = &v
			return nil
		}
		return fmt.Errorf(`invalid value for %s key: %T`, ProfileKey, value)
	case SubjectKey:
		if v, ok := value.(string); ok {
			t.subject = &v
			return nil
		}
		return fmt.Errorf(`invalid value for %s key: %T`, SubjectKey, value)
	case UpdatedAtKey:
		var acceptor types.NumericDate
		if err := acceptor.Accept(value); err != nil {
			return fmt.Errorf(`invalid value for %s key: %w`, UpdatedAtKey, err)
		}
		t.updatedAt = &acceptor
		return nil
	case WebsiteKey:
		if v, ok := value.(string); ok {
			t.website = &v
			return nil
		}
		return fmt.Errorf(`invalid value for %s key: %T`, WebsiteKey, value)
	case ZoneinfoKey:
		if v, ok := value.(string); ok {
			t.zoneinfo = &v
			return nil
		}
		return fmt.Errorf(`invalid value for %s key: %T`, ZoneinfoKey, value)
	default:
		if t.privateClaims == nil {
			t.privateClaims = map[string]interface{}{}
		}
		t.privateClaims[name] = value
	}
	return nil
}

func (t *stdToken) Address() *AddressClaim {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.address
}

func (t *stdToken) Audience() []string {
	t.mu.RLock()
	defer t.mu.RUnlock()
	if t.audience != nil {
		return t.audience.Get()
	}
	return nil
}

func (t *stdToken) Birthdate() *BirthdateClaim {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.birthdate
}

func (t *stdToken) Email() string {
	t.mu.RLock()
	defer t.mu.RUnlock()
	if t.email != nil {
		return *(t.email)
	}
	return ""
}

func (t *stdToken) EmailVerified() bool {
	t.mu.RLock()
	defer t.mu.RUnlock()
	if t.emailVerified != nil {
		return *(t.emailVerified)
	}
	return false
}

func (t *stdToken) Expiration() time.Time {
	t.mu.RLock()
	defer t.mu.RUnlock()
	if t.expiration != nil {
		return t.expiration.Get()
	}
	return time.Time{}
}

func (t *stdToken) FamilyName() string {
	t.mu.RLock()
	defer t.mu.RUnlock()
	if t.familyName != nil {
		return *(t.familyName)
	}
	return ""
}

func (t *stdToken) Gender() string {
	t.mu.RLock()
	defer t.mu.RUnlock()
	if t.gender != nil {
		return *(t.gender)
	}
	return ""
}

func (t *stdToken) GivenName() string {
	t.mu.RLock()
	defer t.mu.RUnlock()
	if t.givenName != nil {
		return *(t.givenName)
	}
	return ""
}

func (t *stdToken) IssuedAt() time.Time {
	t.mu.RLock()
	defer t.mu.RUnlock()
	if t.issuedAt != nil {
		return t.issuedAt.Get()
	}
	return time.Time{}
}

func (t *stdToken) Issuer() string {
	t.mu.RLock()
	defer t.mu.RUnlock()
	if t.issuer != nil {
		return *(t.issuer)
	}
	return ""
}

func (t *stdToken) JwtID() string {
	t.mu.RLock()
	defer t.mu.RUnlock()
	if t.jwtID != nil {
		return *(t.jwtID)
	}
	return ""
}

func (t *stdToken) Locale() string {
	t.mu.RLock()
	defer t.mu.RUnlock()
	if t.locale != nil {
		return *(t.locale)
	}
	return ""
}

func (t *stdToken) MiddleName() string {
	t.mu.RLock()
	defer t.mu.RUnlock()
	if t.middleName != nil {
		return *(t.middleName)
	}
	return ""
}

func (t *stdToken) Name() string {
	t.mu.RLock()
	defer t.mu.RUnlock()
	if t.name != nil {
		return *(t.name)
	}
	return ""
}

func (t *stdToken) Nickname() string {
	t.mu.RLock()
	defer t.mu.RUnlock()
	if t.nickname != nil {
		return *(t.nickname)
	}
	return ""
}

func (t *stdToken) NotBefore() time.Time {
	t.mu.RLock()
	defer t.mu.RUnlock()
	if t.notBefore != nil {
		return t.notBefore.Get()
	}
	return time.Time{}
}

func (t *stdToken) PhoneNumber() string {
	t.mu.RLock()
	defer t.mu.RUnlock()
	if t.phoneNumber != nil {
		return *(t.phoneNumber)
	}
	return ""
}

func (t *stdToken) PhoneNumberVerified() bool {
	t.mu.RLock()
	defer t.mu.RUnlock()
	if t.phoneNumberVerified != nil {
		return *(t.phoneNumberVerified)
	}
	return false
}

func (t *stdToken) Picture() string {
	t.mu.RLock()
	defer t.mu.RUnlock()
	if t.picture != nil {
		return *(t.picture)
	}
	return ""
}

func (t *stdToken) PreferredUsername() string {
	t.mu.RLock()
	defer t.mu.RUnlock()
	if t.preferredUsername != nil {
		return *(t.preferredUsername)
	}
	return ""
}

func (t *stdToken) Profile() string {
	t.mu.RLock()
	defer t.mu.RUnlock()
	if t.profile != nil {
		return *(t.profile)
	}
	return ""
}

func (t *stdToken) Subject() string {
	t.mu.RLock()
	defer t.mu.RUnlock()
	if t.subject != nil {
		return *(t.subject)
	}
	return ""
}

func (t *stdToken) UpdatedAt() time.Time {
	t.mu.RLock()
	defer t.mu.RUnlock()
	if t.updatedAt != nil {
		return t.updatedAt.Get()
	}
	return time.Time{}
}

func (t *stdToken) Website() string {
	t.mu.RLock()
	defer t.mu.RUnlock()
	if t.website != nil {
		return *(t.website)
	}
	return ""
}

func (t *stdToken) Zoneinfo() string {
	t.mu.RLock()
	defer t.mu.RUnlock()
	if t.zoneinfo != nil {
		return *(t.zoneinfo)
	}
	return ""
}

func (t *stdToken) PrivateClaims() map[string]interface{} {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.privateClaims
}

func (t *stdToken) makePairs() []*ClaimPair {
	t.mu.RLock()
	defer t.mu.RUnlock()

	pairs := make([]*ClaimPair, 0, 26)
	if t.address != nil {
		v := t.address
		pairs = append(pairs, &ClaimPair{Key: AddressKey, Value: v})
	}
	if t.audience != nil {
		v := t.audience.Get()
		pairs = append(pairs, &ClaimPair{Key: AudienceKey, Value: v})
	}
	if t.birthdate != nil {
		v := t.birthdate
		pairs = append(pairs, &ClaimPair{Key: BirthdateKey, Value: v})
	}
	if t.email != nil {
		v := *(t.email)
		pairs = append(pairs, &ClaimPair{Key: EmailKey, Value: v})
	}
	if t.emailVerified != nil {
		v := *(t.emailVerified)
		pairs = append(pairs, &ClaimPair{Key: EmailVerifiedKey, Value: v})
	}
	if t.expiration != nil {
		v := t.expiration.Get()
		pairs = append(pairs, &ClaimPair{Key: ExpirationKey, Value: v})
	}
	if t.familyName != nil {
		v := *(t.familyName)
		pairs = append(pairs, &ClaimPair{Key: FamilyNameKey, Value: v})
	}
	if t.gender != nil {
		v := *(t.gender)
		pairs = append(pairs, &ClaimPair{Key: GenderKey, Value: v})
	}
	if t.givenName != nil {
		v := *(t.givenName)
		pairs = append(pairs, &ClaimPair{Key: GivenNameKey, Value: v})
	}
	if t.issuedAt != nil {
		v := t.issuedAt.Get()
		pairs = append(pairs, &ClaimPair{Key: IssuedAtKey, Value: v})
	}
	if t.issuer != nil {
		v := *(t.issuer)
		pairs = append(pairs, &ClaimPair{Key: IssuerKey, Value: v})
	}
	if t.jwtID != nil {
		v := *(t.jwtID)
		pairs = append(pairs, &ClaimPair{Key: JwtIDKey, Value: v})
	}
	if t.locale != nil {
		v := *(t.locale)
		pairs = append(pairs, &ClaimPair{Key: LocaleKey, Value: v})
	}
	if t.middleName != nil {
		v := *(t.middleName)
		pairs = append(pairs, &ClaimPair{Key: MiddleNameKey, Value: v})
	}
	if t.name != nil {
		v := *(t.name)
		pairs = append(pairs, &ClaimPair{Key: NameKey, Value: v})
	}
	if t.nickname != nil {
		v := *(t.nickname)
		pairs = append(pairs, &ClaimPair{Key: NicknameKey, Value: v})
	}
	if t.notBefore != nil {
		v := t.notBefore.Get()
		pairs = append(pairs, &ClaimPair{Key: NotBeforeKey, Value: v})
	}
	if t.phoneNumber != nil {
		v := *(t.phoneNumber)
		pairs = append(pairs, &ClaimPair{Key: PhoneNumberKey, Value: v})
	}
	if t.phoneNumberVerified != nil {
		v := *(t.phoneNumberVerified)
		pairs = append(pairs, &ClaimPair{Key: PhoneNumberVerifiedKey, Value: v})
	}
	if t.picture != nil {
		v := *(t.picture)
		pairs = append(pairs, &ClaimPair{Key: PictureKey, Value: v})
	}
	if t.preferredUsername != nil {
		v := *(t.preferredUsername)
		pairs = append(pairs, &ClaimPair{Key: PreferredUsernameKey, Value: v})
	}
	if t.profile != nil {
		v := *(t.profile)
		pairs = append(pairs, &ClaimPair{Key: ProfileKey, Value: v})
	}
	if t.subject != nil {
		v := *(t.subject)
		pairs = append(pairs, &ClaimPair{Key: SubjectKey, Value: v})
	}
	if t.updatedAt != nil {
		v := t.updatedAt.Get()
		pairs = append(pairs, &ClaimPair{Key: UpdatedAtKey, Value: v})
	}
	if t.website != nil {
		v := *(t.website)
		pairs = append(pairs, &ClaimPair{Key: WebsiteKey, Value: v})
	}
	if t.zoneinfo != nil {
		v := *(t.zoneinfo)
		pairs = append(pairs, &ClaimPair{Key: ZoneinfoKey, Value: v})
	}
	for k, v := range t.privateClaims {
		pairs = append(pairs, &ClaimPair{Key: k, Value: v})
	}
	sort.Slice(pairs, func(i, j int) bool {
		return pairs[i].Key.(string) < pairs[j].Key.(string)
	})
	return pairs
}

func (t *stdToken) UnmarshalJSON(buf []byte) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.address = nil
	t.audience = nil
	t.birthdate = nil
	t.email = nil
	t.emailVerified = nil
	t.expiration = nil
	t.familyName = nil
	t.gender = nil
	t.givenName = nil
	t.issuedAt = nil
	t.issuer = nil
	t.jwtID = nil
	t.locale = nil
	t.middleName = nil
	t.name = nil
	t.nickname = nil
	t.notBefore = nil
	t.phoneNumber = nil
	t.phoneNumberVerified = nil
	t.picture = nil
	t.preferredUsername = nil
	t.profile = nil
	t.subject = nil
	t.updatedAt = nil
	t.website = nil
	t.zoneinfo = nil
	dec := json.NewDecoder(bytes.NewReader(buf))
LOOP:
	for {
		tok, err := dec.Token()
		if err != nil {
			return fmt.Errorf(`error reading token: %w`, err)
		}
		switch tok := tok.(type) {
		case json.Delim:
			// Assuming we're doing everything correctly, we should ONLY
			// get either '{' or '}' here.
			if tok == '}' { // End of object
				break LOOP
			} else if tok != '{' {
				return fmt.Errorf(`expected '{', but got '%c'`, tok)
			}
		case string: // Objects can only have string keys
			switch tok {
			case AddressKey:
				var decoded AddressClaim
				if err := dec.Decode(&decoded); err != nil {
					return fmt.Errorf(`failed to decode value for key %s: %w`, AddressKey, err)
				}
				t.address = &decoded
			case AudienceKey:
				var decoded types.StringList
				if err := dec.Decode(&decoded); err != nil {
					return fmt.Errorf(`failed to decode value for key %s: %w`, AudienceKey, err)
				}
				t.audience = decoded
			case BirthdateKey:
				var decoded BirthdateClaim
				if err := dec.Decode(&decoded); err != nil {
					return fmt.Errorf(`failed to decode value for key %s: %w`, BirthdateKey, err)
				}
				t.birthdate = &decoded
			case EmailKey:
				if err := json.AssignNextStringToken(&t.email, dec); err != nil {
					return fmt.Errorf(`failed to decode value for key %s: %w`, EmailKey, err)
				}
			case EmailVerifiedKey:
				var decoded bool
				if err := dec.Decode(&decoded); err != nil {
					return fmt.Errorf(`failed to decode value for key %s: %w`, EmailVerifiedKey, err)
				}
				t.emailVerified = &decoded
			case ExpirationKey:
				var decoded types.NumericDate
				if err := dec.Decode(&decoded); err != nil {
					return fmt.Errorf(`failed to decode value for key %s: %w`, ExpirationKey, err)
				}
				t.expiration = &decoded
			case FamilyNameKey:
				if err := json.AssignNextStringToken(&t.familyName, dec); err != nil {
					return fmt.Errorf(`failed to decode value for key %s: %w`, FamilyNameKey, err)
				}
			case GenderKey:
				if err := json.AssignNextStringToken(&t.gender, dec); err != nil {
					return fmt.Errorf(`failed to decode value for key %s: %w`, GenderKey, err)
				}
			case GivenNameKey:
				if err := json.AssignNextStringToken(&t.givenName, dec); err != nil {
					return fmt.Errorf(`failed to decode value for key %s: %w`, GivenNameKey, err)
				}
			case IssuedAtKey:
				var decoded types.NumericDate
				if err := dec.Decode(&decoded); err != nil {
					return fmt.Errorf(`failed to decode value for key %s: %w`, IssuedAtKey, err)
				}
				t.issuedAt = &decoded
			case IssuerKey:
				if err := json.AssignNextStringToken(&t.issuer, dec); err != nil {
					return fmt.Errorf(`failed to decode value for key %s: %w`, IssuerKey, err)
				}
			case JwtIDKey:
				if err := json.AssignNextStringToken(&t.jwtID, dec); err != nil {
					return fmt.Errorf(`failed to decode value for key %s: %w`, JwtIDKey, err)
				}
			case LocaleKey:
				if err := json.AssignNextStringToken(&t.locale, dec); err != nil {
					return fmt.Errorf(`failed to decode value for key %s: %w`, LocaleKey, err)
				}
			case MiddleNameKey:
				if err := json.AssignNextStringToken(&t.middleName, dec); err != nil {
					return fmt.Errorf(`failed to decode value for key %s: %w`, MiddleNameKey, err)
				}
			case NameKey:
				if err := json.AssignNextStringToken(&t.name, dec); err != nil {
					return fmt.Errorf(`failed to decode value for key %s: %w`, NameKey, err)
				}
			case NicknameKey:
				if err := json.AssignNextStringToken(&t.nickname, dec); err != nil {
					return fmt.Errorf(`failed to decode value for key %s: %w`, NicknameKey, err)
				}
			case NotBeforeKey:
				var decoded types.NumericDate
				if err := dec.Decode(&decoded); err != nil {
					return fmt.Errorf(`failed to decode value for key %s: %w`, NotBeforeKey, err)
				}
				t.notBefore = &decoded
			case PhoneNumberKey:
				if err := json.AssignNextStringToken(&t.phoneNumber, dec); err != nil {
					return fmt.Errorf(`failed to decode value for key %s: %w`, PhoneNumberKey, err)
				}
			case PhoneNumberVerifiedKey:
				var decoded bool
				if err := dec.Decode(&decoded); err != nil {
					return fmt.Errorf(`failed to decode value for key %s: %w`, PhoneNumberVerifiedKey, err)
				}
				t.phoneNumberVerified = &decoded
			case PictureKey:
				if err := json.AssignNextStringToken(&t.picture, dec); err != nil {
					return fmt.Errorf(`failed to decode value for key %s: %w`, PictureKey, err)
				}
			case PreferredUsernameKey:
				if err := json.AssignNextStringToken(&t.preferredUsername, dec); err != nil {
					return fmt.Errorf(`failed to decode value for key %s: %w`, PreferredUsernameKey, err)
				}
			case ProfileKey:
				if err := json.AssignNextStringToken(&t.profile, dec); err != nil {
					return fmt.Errorf(`failed to decode value for key %s: %w`, ProfileKey, err)
				}
			case SubjectKey:
				if err := json.AssignNextStringToken(&t.subject, dec); err != nil {
					return fmt.Errorf(`failed to decode value for key %s: %w`, SubjectKey, err)
				}
			case UpdatedAtKey:
				var decoded types.NumericDate
				if err := dec.Decode(&decoded); err != nil {
					return fmt.Errorf(`failed to decode value for key %s: %w`, UpdatedAtKey, err)
				}
				t.updatedAt = &decoded
			case WebsiteKey:
				if err := json.AssignNextStringToken(&t.website, dec); err != nil {
					return fmt.Errorf(`failed to decode value for key %s: %w`, WebsiteKey, err)
				}
			case ZoneinfoKey:
				if err := json.AssignNextStringToken(&t.zoneinfo, dec); err != nil {
					return fmt.Errorf(`failed to decode value for key %s: %w`, ZoneinfoKey, err)
				}
			default:
				if dc := t.dc; dc != nil {
					if localReg := dc.Registry(); localReg != nil {
						decoded, err := localReg.Decode(dec, tok)
						if err == nil {
							t.setNoLock(tok, decoded)
							continue
						}
					}
				}
				decoded, err := registry.Decode(dec, tok)
				if err == nil {
					t.setNoLock(tok, decoded)
					continue
				}
				return fmt.Errorf(`could not decode field %s: %w`, tok, err)
			}
		default:
			return fmt.Errorf(`invalid token %T`, tok)
		}
	}
	return nil
}

func (t stdToken) MarshalJSON() ([]byte, error) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	buf := pool.GetBytesBuffer()
	defer pool.ReleaseBytesBuffer(buf)
	buf.WriteByte('{')
	enc := json.NewEncoder(buf)
	for i, pair := range t.makePairs() {
		f := pair.Key.(string)
		if i > 0 {
			buf.WriteByte(',')
		}
		buf.WriteRune('"')
		buf.WriteString(f)
		buf.WriteString(`":`)
		switch f {
		case AudienceKey:
			if err := json.EncodeAudience(enc, pair.Value.([]string)); err != nil {
				return nil, fmt.Errorf(`failed to encode "aud": %w`, err)
			}
			continue
		case ExpirationKey, IssuedAtKey, NotBeforeKey, UpdatedAtKey:
			enc.Encode(pair.Value.(time.Time).Unix())
			continue
		}
		switch v := pair.Value.(type) {
		case []byte:
			buf.WriteRune('"')
			buf.WriteString(base64.EncodeToString(v))
			buf.WriteRune('"')
		default:
			if err := enc.Encode(v); err != nil {
				return nil, fmt.Errorf(`failed to marshal field %s: %w`, f, err)
			}
			buf.Truncate(buf.Len() - 1)
		}
	}
	buf.WriteByte('}')
	ret := make([]byte, buf.Len())
	copy(ret, buf.Bytes())
	return ret, nil
}

func (t *stdToken) Iterate(ctx context.Context) Iterator {
	pairs := t.makePairs()
	ch := make(chan *ClaimPair, len(pairs))
	go func(ctx context.Context, ch chan *ClaimPair, pairs []*ClaimPair) {
		defer close(ch)
		for _, pair := range pairs {
			select {
			case <-ctx.Done():
				return
			case ch <- pair:
			}
		}
	}(ctx, ch, pairs)
	return mapiter.New(ch)
}

func (t *stdToken) Walk(ctx context.Context, visitor Visitor) error {
	return iter.WalkMap(ctx, t, visitor)
}

func (t *stdToken) AsMap(ctx context.Context) (map[string]interface{}, error) {
	return iter.AsMap(ctx, t)
}
