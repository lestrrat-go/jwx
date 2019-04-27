// This file is auto-generated. DO NOT EDIT
package openid

import (
	"github.com/lestrrat-go/jwx/jwt"
)

const (
	NameKey                = "name"
	GivenNameKey           = "given_name"
	MiddleNameKey          = "middle_name"
	FamilyNameKey          = "family_name"
	NicknameKey            = "nickname"
	PreferredUsernameKey   = "preferred_username"
	ProfileKey             = "profile"
	PictureKey             = "picture"
	WebsiteKey             = "website"
	EmailKey               = "email"
	EmailVerifiedKey       = "email_verified"
	GenderKey              = "gender"
	BirthdateKey           = "birthdate"
	ZoneinfoKey            = "zoneinfo"
	LocaleKey              = "locale"
	PhoneNumberKey         = "phone_number"
	PhoneNumberVerifiedKey = "phone_number_verified"
	AddressKey             = "address"
	UpdatedAtKey           = "updated_at"
)

type Token interface {
	Get(string) (interface{}, bool)
	Set(string, interface{}) error
}

// Name returns the value of `name` claim. If the claim does not exist, the zero value will be returned.
func Name(t Token) string {
	v, _ := t.Get(NameKey)
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

// GivenName returns the value of `given_name` claim. If the claim does not exist, the zero value will be returned.
func GivenName(t Token) string {
	v, _ := t.Get(GivenNameKey)
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

// MiddleName returns the value of `middle_name` claim. If the claim does not exist, the zero value will be returned.
func MiddleName(t Token) string {
	v, _ := t.Get(MiddleNameKey)
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

// FamilyName returns the value of `family_name` claim. If the claim does not exist, the zero value will be returned.
func FamilyName(t Token) string {
	v, _ := t.Get(FamilyNameKey)
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

// Nickname returns the value of `nickname` claim. If the claim does not exist, the zero value will be returned.
func Nickname(t Token) string {
	v, _ := t.Get(NicknameKey)
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

// PreferredUsername returns the value of `preferred_username` claim. If the claim does not exist, the zero value will be returned.
func PreferredUsername(t Token) string {
	v, _ := t.Get(PreferredUsernameKey)
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

// Profile returns the value of `profile` claim. If the claim does not exist, the zero value will be returned.
func Profile(t Token) string {
	v, _ := t.Get(ProfileKey)
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

// Picture returns the value of `picture` claim. If the claim does not exist, the zero value will be returned.
func Picture(t Token) string {
	v, _ := t.Get(PictureKey)
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

// Website returns the value of `website` claim. If the claim does not exist, the zero value will be returned.
func Website(t Token) string {
	v, _ := t.Get(WebsiteKey)
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

// Email returns the value of `email` claim. If the claim does not exist, the zero value will be returned.
func Email(t Token) string {
	v, _ := t.Get(EmailKey)
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

// EmailVerified returns the value of `email_verified` claim. If the claim does not exist, the zero value will be returned.
func EmailVerified(t Token) bool {
	v, _ := t.Get(EmailVerifiedKey)
	if s, ok := v.(bool); ok {
		return s
	}
	return false
}

// Gender returns the value of `gender` claim. If the claim does not exist, the zero value will be returned.
func Gender(t Token) string {
	v, _ := t.Get(GenderKey)
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

// Birthdate returns the value of `birthdate` claim. If the claim does not exist, the zero value will be returned.
func Birthdate(t Token) *BirthdateClaim {
	v, _ := t.Get(BirthdateKey)
	if s, ok := v.(*BirthdateClaim); ok {
		return s
	}
	return nil
}

// Zoneinfo returns the value of `zoneinfo` claim. If the claim does not exist, the zero value will be returned.
func Zoneinfo(t Token) string {
	v, _ := t.Get(ZoneinfoKey)
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

// Locale returns the value of `locale` claim. If the claim does not exist, the zero value will be returned.
func Locale(t Token) string {
	v, _ := t.Get(LocaleKey)
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

// PhoneNumber returns the value of `phone_number` claim. If the claim does not exist, the zero value will be returned.
func PhoneNumber(t Token) string {
	v, _ := t.Get(PhoneNumberKey)
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

// PhoneNumberVerified returns the value of `phone_number_verified` claim. If the claim does not exist, the zero value will be returned.
func PhoneNumberVerified(t Token) bool {
	v, _ := t.Get(PhoneNumberVerifiedKey)
	if s, ok := v.(bool); ok {
		return s
	}
	return false
}

// Address returns the value of `address` claim. If the claim does not exist, the zero value will be returned.
func Address(t Token) *AddressClaim {
	v, _ := t.Get(AddressKey)
	if s, ok := v.(*AddressClaim); ok {
		return s
	}
	return nil
}

// UpdatedAt returns the value of `updated_at` claim. If the claim does not exist, the zero value will be returned.
func UpdatedAt(t Token) *types.NumericDate {
	v, _ := t.Get(UpdatedAtKey)
	if s, ok := v.(*types.NumericDate); ok {
		return s
	}
	return nil
}
