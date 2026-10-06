package jws

import (
	"fmt"

	"github.com/lestrrat-go/jwx/v4/jwa"
)

func (h *stdHeaders) Copy(dst Headers) error {
	for _, k := range h.Keys() {
		v, ok := h.Field(k)
		if !ok {
			return fmt.Errorf(`failed to get header %q`, k)
		}
		if err := dst.Set(k, v); err != nil {
			return fmt.Errorf(`failed to set header %q: %w`, k, err)
		}
	}
	return nil
}

// mergeHeaders merges two headers, and works even if the first Header
// object is nil. This is not exported because ATM it felt like this
// function is not frequently used, and MergeHeaders seemed a clunky name
func mergeHeaders(h1, h2 Headers) (Headers, error) {
	h3 := NewHeaders()

	if h1 != nil {
		if err := h1.Copy(h3); err != nil {
			return nil, fmt.Errorf(`failed to copy headers from first Header: %w`, err)
		}
	}

	if h2 != nil {
		if err := h2.Copy(h3); err != nil {
			return nil, fmt.Errorf(`failed to copy headers from second Header: %w`, err)
		}
	}

	return h3, nil
}

func (h *stdHeaders) Merge(h2 Headers) (Headers, error) {
	return mergeHeaders(h, h2)
}

// Clone creates a deep copy of the header
func (h *stdHeaders) Clone() (Headers, error) {
	dst, _ := NewHeaders().(*stdHeaders)
	dst.cloneFrom(h)
	return dst, nil
}

// These helpers inspect the header union without allocating a merged header.
func signatureAlgorithm(sig *Signature) (jwa.SignatureAlgorithm, bool) {
	if sig.protected != nil {
		if alg, ok := sig.protected.Algorithm(); ok {
			return alg, true
		}
	}
	if sig.headers != nil {
		return sig.headers.Algorithm()
	}
	return jwa.SignatureAlgorithm{}, false
}

func signatureKeyID(sig *Signature) (string, bool) {
	if sig.protected != nil {
		if kid, ok := sig.protected.KeyID(); ok {
			return kid, true
		}
	}
	if sig.headers != nil {
		return sig.headers.KeyID()
	}
	return "", false
}

func signatureJWKSetURL(sig *Signature) (string, bool) {
	if sig.protected != nil {
		if url, ok := sig.protected.JWKSetURL(); ok {
			return url, true
		}
	}
	if sig.headers != nil {
		return sig.headers.JWKSetURL()
	}
	return "", false
}

// Called only on freshly parsed headers, before they are exposed to providers.
// Both headers are distinct stdHeaders constructed by the JSON parser.
func validateSignatureHeaders(sig *Signature) error {
	if sig.headers == nil {
		return nil
	}
	if sig.headers.Has(CriticalKey) {
		return fmt.Errorf(`"crit" must be in the protected header`)
	}
	if sig.headers.Has(B64Key) {
		return fmt.Errorf(`"b64" must be in the protected header`)
	}
	if sig.protected == nil {
		return nil
	}
	for _, name := range stdHeaderNames {
		if sig.protected.Has(name) && sig.headers.Has(name) {
			return fmt.Errorf(`header parameter %q occurs in both protected and unprotected headers`, name)
		}
	}
	protected, ok := sig.protected.(*stdHeaders)
	if !ok {
		return fmt.Errorf(`unexpected parsed protected header type %T`, sig.protected)
	}
	protected.mu.RLock()
	defer protected.mu.RUnlock()
	for name := range protected.privateParams {
		if sig.headers.Has(name) {
			return fmt.Errorf(`header parameter %q occurs in both protected and unprotected headers`, name)
		}
	}
	return nil
}

func (vc *verifyContext) matchAlgorithm(sig *Signature, alg jwa.SignatureAlgorithm) error {
	advertised, ok := signatureAlgorithm(sig)
	if !ok {
		return makeVerifyError(`required "alg" header is missing`)
	}
	if !vc.skipAlgorithmMatch && advertised.String() != alg.String() {
		return verifyError{verificationError{fmt.Errorf(`JOSE header %q %q does not match verification algorithm %q`, AlgorithmKey, advertised, alg)}}
	}
	return nil
}
