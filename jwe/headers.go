package jwe

import (
	"bytes"
	"fmt"

	"github.com/lestrrat-go/jwx/v4/internal/base64"
	"github.com/lestrrat-go/jwx/v4/internal/json"
	"github.com/lestrrat-go/jwx/v4/jwa"
)

type isZeroer interface {
	isZero() bool
}

func (h *stdHeaders) Clone() (Headers, error) {
	dst := &stdHeaders{}
	dst.cloneFrom(h)
	return dst, nil
}

func (h *stdHeaders) Copy(dst Headers) error {
	for _, key := range h.Keys() {
		v, ok := h.Field(key)
		if !ok {
			return fmt.Errorf(`jwe.Headers: Copy: failed to get header %q`, key)
		}
		if err := dst.Set(key, v); err != nil {
			return fmt.Errorf(`jwe.Headers: Copy: failed to set header %q: %w`, key, err)
		}
	}
	return nil
}

// copyNoLock copies all fields from h to dst without acquiring any mutexes.
// Both h and dst must be exclusively owned by the caller (not shared).
func (h *stdHeaders) copyNoLock(dst *stdHeaders) {
	dst.cloneFrom(h)
}

func (h *stdHeaders) Merge(h2 Headers) (Headers, error) {
	h3 := NewHeaders()

	if h != nil {
		if err := h.Copy(h3); err != nil {
			return nil, fmt.Errorf(`failed to copy headers from receiver: %w`, err)
		}
	}

	if h2 != nil {
		if err := h2.Copy(h3); err != nil {
			return nil, fmt.Errorf(`failed to copy headers from argument: %w`, err)
		}
	}

	return h3, nil
}

// mergeIntoNoLock copies non-nil fields from h into dst without acquiring
// any mutexes. Both h and dst must be exclusively owned by the caller.
// Unlike cloneFrom, this only overwrites fields that are set in h,
// leaving existing values in dst untouched.
func (h *stdHeaders) mergeIntoNoLock(dst *stdHeaders) {
	if h.agreementPartyUInfo != nil {
		dst.agreementPartyUInfo = h.agreementPartyUInfo
	}
	if h.agreementPartyVInfo != nil {
		dst.agreementPartyVInfo = h.agreementPartyVInfo
	}
	if h.algorithm != nil {
		dst.algorithm = h.algorithm
	}
	if h.compression != nil {
		dst.compression = h.compression
	}
	if h.contentEncryption != nil {
		dst.contentEncryption = h.contentEncryption
	}
	if h.contentType != nil {
		dst.contentType = h.contentType
	}
	if h.critical != nil {
		dst.critical = h.critical
	}
	if h.encapsulatedKey != nil {
		dst.encapsulatedKey = h.encapsulatedKey
	}
	if h.ephemeralPublicKey != nil {
		dst.ephemeralPublicKey = h.ephemeralPublicKey
	}
	if h.jwk != nil {
		dst.jwk = h.jwk
	}
	if h.jwkSetURL != nil {
		dst.jwkSetURL = h.jwkSetURL
	}
	if h.keyID != nil {
		dst.keyID = h.keyID
	}
	if h.pskID != nil {
		dst.pskID = h.pskID
	}
	if h.typ != nil {
		dst.typ = h.typ
	}
	if h.x509CertChain != nil {
		dst.x509CertChain = h.x509CertChain
	}
	if h.x509CertThumbprint != nil {
		dst.x509CertThumbprint = h.x509CertThumbprint
	}
	if h.x509CertThumbprintS256 != nil {
		dst.x509CertThumbprintS256 = h.x509CertThumbprintS256
	}
	if h.x509URL != nil {
		dst.x509URL = h.x509URL
	}
	for k, v := range h.privateParams {
		if dst.privateParams == nil {
			dst.privateParams = make(map[string]any)
		}
		dst.privateParams[k] = v
	}
}

func (h *stdHeaders) Encode() ([]byte, error) {
	buf, err := json.Marshal(h)
	if err != nil {
		return nil, fmt.Errorf(`failed to marshal headers to JSON prior to encoding: %w`, err)
	}

	return base64.Encode(buf), nil
}

func (h *stdHeaders) Decode(buf []byte) error {
	// base64 json string -> json object representation of header
	decoded, err := base64.Decode(buf)
	if err != nil {
		return fmt.Errorf(`failed to unmarshal base64 encoded buffer: %w`, err)
	}

	if err := json.Unmarshal(decoded, h); err != nil {
		return fmt.Errorf(`failed to unmarshal buffer: %w`, err)
	}

	return nil
}

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
