package jws

import (
	"errors"
	"fmt"
)

// errNonMinimalHeader is the umbrella sentinel for every VerifyCompactFast
// header refusal: the protected header is not in the minimal shape the fast
// path handles ("alg" exactly once, an optional single "typ"/"kid"/"cty", no
// JSON escape sequences, and no other parameters). fastjson (used by the fast
// path) keeps duplicate object members and resolves them first-wins, whereas
// encoding/json/v2 (used by jws.Verify) rejects duplicate names outright — so
// a header carrying a duplicate, a nested object, an unknown or key-source
// parameter, or an escaped key could be read differently by the two paths
// (see issue #2234). Refusing such headers defers them to jws.Verify, whose
// strict, recursive duplicate rejection and full header handling are the
// authoritative behavior.
//
// The crit and b64 refusals (errCritPresent, errB64Present) are specific
// reasons that wrap this sentinel, so a single errors.Is(err,
// jws.ErrNonMinimalHeader()) check classifies every fast-path header refusal,
// while errors.Is(err, jws.ErrCritPresent()) still identifies the precise
// cause. The sentinel is wrapped in verifyError at the return site, so the
// resulting error also matches errors.Is(err, jws.VerifyError()).
var errNonMinimalHeader = errors.New(`VerifyCompactFast: protected header is not in the fast-path minimal shape; use jws.Verify`)

// ErrNonMinimalHeader returns the umbrella sentinel that VerifyCompactFast
// returns for every protected-header refusal: a duplicate, a nested object,
// an unknown or key-source parameter, an escaped key, or the more specific
// "crit"/"b64" cases (see ErrCritPresent / ErrB64Present, which both match
// this sentinel too). Treat it as "the fast path declined this header; retry
// through jws.Verify". Errors returned from VerifyCompactFast that wrap this
// sentinel additionally match jws.VerifyError() (they are wrapped in
// verifyError at the return site); the bare sentinel value returned here does
// not.
func ErrNonMinimalHeader() error {
	return errNonMinimalHeader
}

// errCritPresent is the specific case of errNonMinimalHeader where the
// protected header carries a "crit" list. The fast path cannot enforce
// RFC 7515 §4.1.11 (it has no WithCritExtension allowlist), so it refuses
// rather than silently accepting. It wraps errNonMinimalHeader, so the
// returned error matches errors.Is(err, jws.ErrCritPresent()) (the specific
// reason), errors.Is(err, jws.ErrNonMinimalHeader()) (the umbrella), and —
// via the verifyError wrapper at the return site — errors.Is(err,
// jws.VerifyError()) (the general class).
var errCritPresent = fmt.Errorf(`%w (header contains "crit")`, errNonMinimalHeader)

// ErrCritPresent returns the sentinel error returned by VerifyCompactFast
// when the protected header contains a "crit" list. This sentinel itself also
// matches jws.ErrNonMinimalHeader() (it wraps the umbrella refusal). Errors
// returned from VerifyCompactFast that wrap it additionally match
// jws.VerifyError() (the general class), so callers can branch at whatever
// granularity fits.
func ErrCritPresent() error {
	return errCritPresent
}

// errB64Present is the specific case of errNonMinimalHeader where the
// protected header carries a "b64" entry (typically b64=false per RFC 7797).
// The fast path assumes the default b64=true encoding for both the
// signing-input reconstruction and the post-verify payload decode; a
// b64=false message signed under non-conformant rules (b64 not declared in
// "crit") would otherwise verify cryptographically while returning a decoded
// payload that differs from the producer's intent. Refusing here defers such
// messages to jws.Verify, which has the WithDetachedPayload and
// WithCritExtension machinery to handle b64=false correctly. Like
// errCritPresent it wraps errNonMinimalHeader and is wrapped in verifyError at
// the return site, so it matches ErrB64Present(), ErrNonMinimalHeader(), and
// VerifyError().
var errB64Present = fmt.Errorf(`%w (header contains "b64")`, errNonMinimalHeader)

// ErrB64Present returns the sentinel error returned by VerifyCompactFast when
// the protected header contains a "b64" entry. This sentinel itself also
// matches jws.ErrNonMinimalHeader() (it wraps the umbrella refusal). Errors
// returned from VerifyCompactFast that wrap it additionally match
// jws.VerifyError() (the general class).
func ErrB64Present() error {
	return errB64Present
}

// errUnclassifiableKey is the common sentinel for AlgorithmsForKey
// failures: the key shape cannot be matched to any registered key type
// for signing. Three different code paths land here — Import-failed,
// kty-not-registered, and shape-rejected (e.g. ecdh) — but they're all
// the same logical "we can't classify this key" outcome from the
// caller's perspective. Wrap-with-this lets callers branch on
// errors.Is(err, jws.ErrUnclassifiableKey()) instead of pattern-matching
// the three error-message shapes the function previously emitted.
var errUnclassifiableKey = errors.New("jws: key cannot be classified for signing")

// ErrUnclassifiableKey returns the sentinel that jws.AlgorithmsForKey
// (and indirectly jws.Sign / jws.Verify when option-time validation
// fails) wraps when the supplied key cannot be matched to a registered
// key type. Branching on this sentinel is the right way to ask "is this
// a 'we can't tell what this key is' failure?" — the wrapping error
// also carries the concrete %T or %q diagnostic in its message, so the
// human-readable error stays specific.
func ErrUnclassifiableKey() error {
	return errUnclassifiableKey
}

type signError struct {
	error
}

const (
	prefixJwsSign    = `jws.Sign`
	prefixJwsCompact = `jws.Compact`
)

var errDefaultSignError = makeSignError(prefixJwsSign, `unknown error`)

// SignError returns an error that can be passed to `errors.Is` to check if the error is a sign error.
func SignError() error {
	return errDefaultSignError
}

func (e signError) Unwrap() error {
	return e.error
}

func (signError) Is(err error) bool {
	_, ok := err.(signError)
	return ok
}

func makeSignError(prefix string, f string, args ...any) error {
	return signError{fmt.Errorf(prefix+`: `+f, args...)}
}

// This error is returned when jws.Verify fails, but note that there's another type of
// message that can be returned by jws.Verify, which is `errVerification`.
type verifyError struct {
	error
}

var errDefaultVerifyError = makeVerifyError(`unknown error`)

// VerifyError returns an error that can be passed to `errors.Is` to check if the error is a verify error.
func VerifyError() error {
	return errDefaultVerifyError
}

func (e verifyError) Unwrap() error {
	return e.error
}

func (verifyError) Is(err error) bool {
	_, ok := err.(verifyError)
	return ok
}

func makeVerifyError(f string, args ...any) error {
	return verifyError{fmt.Errorf(`jws.Verify: `+f, args...)}
}

// verificationError is returned when the actual _verification_ of the key/payload fails.
type verificationError struct {
	error
}

var errDefaultVerificationError = verificationError{fmt.Errorf(`unknown verification error`)}

// VerificationError returns an error that can be passed to `errors.Is` to check if the error is a verification error.
func VerificationError() error {
	return errDefaultVerificationError
}

func (e verificationError) Unwrap() error {
	return e.error
}

func (verificationError) Is(err error) bool {
	_, ok := err.(verificationError)
	return ok
}

type parseError struct {
	error
}

var errDefaultParseError = makeParseError(`jws.Parse`, `unknown error`)

// ParseError returns an error that can be passed to `errors.Is` to check if the error is a parse error.
func ParseError() error {
	return errDefaultParseError
}

func (e parseError) Unwrap() error {
	return e.error
}

func (parseError) Is(err error) bool {
	_, ok := err.(parseError)
	return ok
}

func makeParseError(prefix string, f string, args ...any) error {
	return parseError{fmt.Errorf(prefix+": "+f, args...)}
}

//-------------------------------------------------------------------
// FieldNotFoundError
//-------------------------------------------------------------------

// FieldNotFoundError is returned when jws.Get fails to find the
// requested field on a jws.Headers.
type FieldNotFoundError struct {
	// Name is the name of the field that was not found.
	Name string
}

func (e FieldNotFoundError) Error() string {
	return fmt.Sprintf(`field %q not found`, e.Name)
}

func (e FieldNotFoundError) Is(target error) bool {
	_, ok := target.(FieldNotFoundError)
	return ok
}

//-------------------------------------------------------------------
// FieldTypeMismatchError
//-------------------------------------------------------------------

// FieldTypeMismatchError is returned when jws.Get finds the requested
// field but the stored value cannot be converted to the requested type.
//
// Callers that need to distinguish "field missing" from "field present
// but wrong type" should use errors.Is with FieldNotFoundError{} /
// FieldTypeMismatchError{}, or errors.AsType to recover Name, Got, and
// Want fields.
type FieldTypeMismatchError struct {
	// Name is the name of the field whose value could not be converted.
	Name string
	// Got is the value currently stored under the field. Use %T to
	// inspect its concrete type.
	Got any
	// Want is a zero value of the requested type T. Use %T to inspect
	// its concrete type.
	Want any
}

func (e FieldTypeMismatchError) Error() string {
	return fmt.Sprintf(`field %q is %T, not %T`, e.Name, e.Got, e.Want)
}

func (e FieldTypeMismatchError) Is(target error) bool {
	_, ok := target.(FieldTypeMismatchError)
	return ok
}
