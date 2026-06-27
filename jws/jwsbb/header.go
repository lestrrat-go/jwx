package jwsbb

import (
	impl "github.com/lestrrat-go/jwx/v4/jws/internal/jwsbb"
)

// This file is a thin public facade over jws/internal/jwsbb. The header probe
// implementation lives in the internal package so that jwx-internal-only
// helpers (e.g. HeaderForEachKey) can be shared across the module without being
// exposed to end users. Everything below simply re-exports the internal API.

// Header is an object that allows you to access the JWS header in a quick and
// dirty way. It does not verify anything, it does not know anything about what
// each header field means, and it does not care about the JWS specification.
// But when you need to access the JWS header for that one field that you
// need, this is the object you want to use.
//
// As of this writing, Header cannot be used from concurrent goroutines.
// You will need to create a new instance for each goroutine that needs to parse a JWS header.
// Also, in general values obtained from this object should only be used
// while the Header object is still in scope.
//
// This type is experimental and may change or be removed in the future.
type Header = impl.Header

// ErrHeaderNotFound returns an error that can be passed to `errors.Is` to check if the error is
// the result of the field not being found.
func ErrHeaderNotFound() error {
	return impl.ErrHeaderNotFound()
}

// HeaderParseCompact parses a JWS header from a compact serialization format.
// You will need to call HeaderGet* functions to extract the values from the header.
//
// This function is experimental and may change or be removed in the future.
func HeaderParseCompact(buf []byte) Header {
	return impl.HeaderParseCompact(buf)
}

// HeaderParse parses a JWS header from a byte slice containing the decoded JSON.
// You will need to call HeaderGet* functions to extract the values from the header.
//
// Unlike HeaderParseCompact, this function does not perform any base64 decoding.
// This function is experimental and may change or be removed in the future.
func HeaderParse(decoded []byte) Header {
	return impl.HeaderParse(decoded)
}

// HeaderGetString returns the string value for the given key from the JWS header.
// An error is returned if the JSON was not valid, if the key does not exist,
// or if the value is not a string.
//
// This function is experimental and may change or be removed in the future.
func HeaderGetString(h Header, key string) (string, error) {
	return impl.HeaderGetString(h, key)
}

// HeaderGetBool returns the boolean value for the given key from the JWS header.
// An error is returned if the JSON was not valid, if the key does not exist,
// or if the value is not a boolean.
//
// This function is experimental and may change or be removed in the future.
func HeaderGetBool(h Header, key string) (bool, error) {
	return impl.HeaderGetBool(h, key)
}

// HeaderGetFloat64 returns the float64 value for the given key from the JWS header.
// An error is returned if the JSON was not valid, if the key does not exist,
// or if the value is not a float64.
//
// This function is experimental and may change or be removed in the future.
func HeaderGetFloat64(h Header, key string) (float64, error) {
	return impl.HeaderGetFloat64(h, key)
}

// HeaderGetInt returns the int value for the given key from the JWS header.
// An error is returned if the JSON was not valid, if the key does not exist,
// or if the value is not an int.
//
// This function is experimental and may change or be removed in the future.
func HeaderGetInt(h Header, key string) (int, error) {
	return impl.HeaderGetInt(h, key)
}

// HeaderGetInt64 returns the int64 value for the given key from the JWS header.
// An error is returned if the JSON was not valid, if the key does not exist,
// or if the value is not an int64.
//
// This function is experimental and may change or be removed in the future.
func HeaderGetInt64(h Header, key string) (int64, error) {
	return impl.HeaderGetInt64(h, key)
}

// HeaderGetStringBytes returns the JSON string bytes for the given key
// from the JWS header, without copying. An error is returned if the JSON
// was not valid, if the key does not exist, or if the value is not a
// JSON string.
//
// WARNING: the returned slice aliases memory owned by h. It becomes
// invalid as soon as h is reused, re-parsed, or goes out of scope and is
// garbage collected. Do not retain the slice, share it across
// goroutines, or use it after any further call on h. If you need a value
// that outlives h, use [HeaderGetString], which returns a string copy.
//
// This function is experimental and may change or be removed in the future.
func HeaderGetStringBytes(h Header, key string) ([]byte, error) {
	return impl.HeaderGetStringBytes(h, key)
}

// HeaderHas returns true if the given key exists in the JWS header.
//
// This function is experimental and may change or be removed in the future.
func HeaderHas(h Header, key string) bool {
	return impl.HeaderHas(h, key)
}

// HeaderGetStringArray returns a string array for the given key from the JWS header.
// An error is returned if the JSON was not valid, if the key does not exist,
// or if the value is not a JSON array of strings.
//
// This function is experimental and may change or be removed in the future.
func HeaderGetStringArray(h Header, key string) ([]string, error) {
	return impl.HeaderGetStringArray(h, key)
}

// HeaderGetUint returns the uint value for the given key from the JWS header.
// An error is returned if the JSON was not valid, if the key does not exist,
// or if the value is not a uint.
//
// This function is experimental and may change or be removed in the future.
func HeaderGetUint(h Header, key string) (uint, error) {
	return impl.HeaderGetUint(h, key)
}

// HeaderGetUint64 returns the uint64 value for the given key from the JWS header.
// An error is returned if the JSON was not valid, if the key does not exist,
// or if the value is not a uint64.
//
// This function is experimental and may change or be removed in the future.
func HeaderGetUint64(h Header, key string) (uint64, error) {
	return impl.HeaderGetUint64(h, key)
}
