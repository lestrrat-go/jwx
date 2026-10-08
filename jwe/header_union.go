package jwe

import (
	"bytes"
	"fmt"

	"github.com/lestrrat-go/jwx/v4/internal/json"
	"github.com/lestrrat-go/jwx/v4/jwa"
)

// RFC 7516 §7.2.1: in the JSON serialization, a recipient's JOSE header is
// the union of the protected header ("protected"), the shared unprotected
// header ("unprotected"), and the recipient's own header ("header"). A
// header parameter name may appear in only one of the three.
//
// A null "crit" is not checked here: the generated header decoder rejects it
// in every location and regardless of WithStrictHeaderRules, because RFC 7515
// §4.1.11 requires an array and a null would otherwise read as an absent
// "crit" and skip extension checks. The full reasoning is next to the
// reject_null flag on "crit" in objects.yml.

// protectedOnlyHeaderNames lists the parameters that RFC 7516 §4.1.3 ("zip")
// and RFC 7515 §4.1.11 ("crit", adopted by RFC 7516 §4.1.13) only allow in
// the protected header.
var protectedOnlyHeaderNames = [...]string{CompressionKey, CriticalKey}

// headerRules carries a WithStrictHeaderRules value from the start of a
// Parse, Decrypt, or Encrypt call into Message.UnmarshalJSON and
// Message.MarshalJSON, so that one call never reads the global setting twice.
// The zero value means the caller did not set it, and the method reads the
// global setting once on entry.
type headerRules uint8

const (
	headerRulesUnset headerRules = iota
	headerRulesStrict
	headerRulesLenient
)

func headerRulesFor(strict bool) headerRules {
	if strict {
		return headerRulesStrict
	}
	return headerRulesLenient
}

// strict resolves the setting, reading the global value only when the
// caller left it unset.
func (r headerRules) strict() bool {
	switch r {
	case headerRulesStrict:
		return true
	case headerRulesLenient:
		return false
	default:
		return strictHeaderRules.Load()
	}
}

// checkUnprotectedHeader returns an error when hdr, which the AEAD tag does
// not cover, carries a parameter that must be in the protected header.
func checkUnprotectedHeader(hdr Headers) error {
	for _, name := range protectedOnlyHeaderNames {
		if hdr.Has(name) {
			return fmt.Errorf(`header parameter %q must be in the protected header`, name)
		}
	}
	return nil
}

// checkDisjointHeaders returns an error naming a header parameter that both
// a and b carry.
func checkDisjointHeaders(a, b Headers) error {
	for _, name := range a.Keys() {
		if b.Has(name) {
			return fmt.Errorf(`header parameter %q appears in more than one header location`, name)
		}
	}
	return nil
}

// checkRecipientHeader applies the placement rules to one recipient header
// against the headers shared by every recipient.
func checkRecipientHeader(recipient Headers, shared ...Headers) error {
	if err := checkUnprotectedHeader(recipient); err != nil {
		return err
	}
	for _, hdr := range shared {
		if hdr == nil {
			continue
		}
		if err := checkDisjointHeaders(hdr, recipient); err != nil {
			return err
		}
	}
	return nil
}

// wireRecipientHeaders returns hdr without the names that a shared header
// already carries with the same value. Parsing copies the protected header
// into the recipient header of a compact message, and of a flattened JSON
// message with no "header" member, so that callers can read "alg" and "kid"
// from the recipient. Writing that copy back out would repeat names across
// header locations. A name whose values differ is an error, because no
// valid message can carry both.
func wireRecipientHeaders(hdr Headers, shared ...Headers) (Headers, error) {
	var out Headers
	for _, name := range hdr.Keys() {
		for _, s := range shared {
			if s == nil {
				continue
			}
			sharedValue, ok := s.Field(name)
			if !ok {
				continue
			}
			recipientValue, _ := hdr.Field(name)
			same, err := sameHeaderValue(recipientValue, sharedValue)
			if err != nil {
				return nil, fmt.Errorf(`failed to compare header parameter %q: %w`, name, err)
			}
			if !same {
				return nil, fmt.Errorf(`header parameter %q has different values in more than one header location`, name)
			}
			if out == nil {
				out, err = hdr.Clone()
				if err != nil {
					return nil, fmt.Errorf(`failed to copy recipient headers: %w`, err)
				}
			}
			if err := out.Remove(name); err != nil {
				return nil, fmt.Errorf(`failed to remove header parameter %q: %w`, name, err)
			}
			break
		}
	}
	if out == nil {
		return hdr, nil
	}
	return out, nil
}

// sameHeaderValue reports whether a and b encode to the same JSON.
func sameHeaderValue(a, b any) (bool, error) {
	encodedA, err := json.Marshal(a)
	if err != nil {
		return false, err
	}
	encodedB, err := json.Marshal(b)
	if err != nil {
		return false, err
	}
	return bytes.Equal(encodedA, encodedB), nil
}

// validateJSONHeaders applies the RFC 7516 §7.2.1 header rules to a message
// parsed from the JSON serialization. shared is nil when the message has no
// "unprotected" member. It must run before makeDummyRecipient, which copies
// the protected header into a recipient header.
func validateJSONHeaders(protected, shared Headers, recipients []Recipient) error {
	if shared != nil {
		if err := checkUnprotectedHeader(shared); err != nil {
			return fmt.Errorf(`"unprotected": %w`, err)
		}
		if err := checkDisjointHeaders(protected, shared); err != nil {
			return err
		}
	}

	// Every recipient decrypts the same ciphertext, so every recipient's
	// JOSE header must name the same "enc". When a shared header carries
	// it, the disjointness checks already keep it out of every recipient
	// header.
	hasEnc := protected.Has(ContentEncryptionKey) || (shared != nil && shared.Has(ContentEncryptionKey))
	var firstEnc jwa.ContentEncryptionAlgorithm
	var firstHasEnc bool
	for i, r := range recipients {
		rh := r.Headers()
		if rh != nil {
			if err := checkRecipientHeader(rh, protected, shared); err != nil {
				return fmt.Errorf(`recipient #%d: %w`, i+1, err)
			}
		}

		if hasEnc {
			continue
		}
		var recipientEnc jwa.ContentEncryptionAlgorithm
		var recipientHasEnc bool
		if rh != nil {
			recipientEnc, recipientHasEnc = rh.ContentEncryption()
		}
		if i == 0 {
			firstEnc, firstHasEnc = recipientEnc, recipientHasEnc
			continue
		}
		if recipientHasEnc != firstHasEnc || recipientEnc != firstEnc {
			return fmt.Errorf(`recipient #%d: all recipients must use the same "enc" header parameter`, i+1)
		}
	}
	return nil
}
