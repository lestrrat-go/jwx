// Code generated by tools/cmd/genoptions/main.go. DO NOT EDIT.

package jwk

import (
	"crypto"
	"io/fs"
	"time"

	"github.com/lestrrat-go/jwx/v2/internal/json"
	"github.com/lestrrat-go/option"
)

type Option = option.Interface

type AssignKeyIDOption interface {
	Option
	assignKeyIDOption()
}

type assignKeyIDOption struct {
	Option
}

func (*assignKeyIDOption) assignKeyIDOption() {}

// CacheOption is a type of Option that can be passed to the
// `jwk.Cache` object.
type CacheOption interface {
	Option
	cacheOption()
}

type cacheOption struct {
	Option
}

func (*cacheOption) cacheOption() {}

// FetchOption is a type of Option that can be passed to `jwk.Fetch()`
// FetchOption also implements the `RegisterOption`, and thus can
// safely be passed to `(*jwk.Cache).Register()`
type FetchOption interface {
	Option
	fetchOption()
	parseOption()
	registerOption()
}

type fetchOption struct {
	Option
}

func (*fetchOption) fetchOption() {}

func (*fetchOption) parseOption() {}

func (*fetchOption) registerOption() {}

// ParseOption is a type of Option that can be passed to `jwk.Parse()`
// ParseOption also implmentsthe `ReadFileOption` and `CacheOption`,
// and thus safely be passed to `jwk.ReadFile` and `(*jwk.Cache).Configure()`
type ParseOption interface {
	Option
	fetchOption()
	registerOption()
	readFileOption()
}

type parseOption struct {
	Option
}

func (*parseOption) fetchOption() {}

func (*parseOption) registerOption() {}

func (*parseOption) readFileOption() {}

// ReadFileOption is a type of `Option` that can be passed to `jwk.ReadFile`
type ReadFileOption interface {
	Option
	readFileOption()
}

type readFileOption struct {
	Option
}

func (*readFileOption) readFileOption() {}

// RegisterOption desribes options that can be passed to `(jwk.Cache).Register()`
type RegisterOption interface {
	Option
	registerOption()
}

type registerOption struct {
	Option
}

func (*registerOption) registerOption() {}

type identErrSink struct{}
type identFS struct{}
type identFetchWhitelist struct{}
type identHTTPClient struct{}
type identIgnoreParseError struct{}
type identLocalRegistry struct{}
type identMinRefreshInterval struct{}
type identPEM struct{}
type identPostFetcher struct{}
type identRefreshInterval struct{}
type identRefreshWindow struct{}
type identThumbprintHash struct{}

func (identErrSink) String() string {
	return "WithErrSink"
}

func (identFS) String() string {
	return "WithFS"
}

func (identFetchWhitelist) String() string {
	return "WithFetchWhitelist"
}

func (identHTTPClient) String() string {
	return "WithHTTPClient"
}

func (identIgnoreParseError) String() string {
	return "WithIgnoreParseError"
}

func (identLocalRegistry) String() string {
	return "withLocalRegistry"
}

func (identMinRefreshInterval) String() string {
	return "WithMinRefreshInterval"
}

func (identPEM) String() string {
	return "WithPEM"
}

func (identPostFetcher) String() string {
	return "WithPostFetcher"
}

func (identRefreshInterval) String() string {
	return "WithRefreshInterval"
}

func (identRefreshWindow) String() string {
	return "WithRefreshWindow"
}

func (identThumbprintHash) String() string {
	return "WithThumbprintHash"
}

// WithErrSink specifies the `httprc.ErrSink` object that handles errors
// that occurred during the cache's execution.
//
// See the documentation in `httprc.WithErrSink` for more details.
func WithErrSink(v ErrSink) CacheOption {
	return &cacheOption{option.New(identErrSink{}, v)}
}

// WithFS specifies the source `fs.FS` object to read the file from.
func WithFS(v fs.FS) ReadFileOption {
	return &readFileOption{option.New(identFS{}, v)}
}

// WithFetchWhitelist specifies the Whitelist object to use when
// fetching JWKs from a remote source. This option can be passed
// to both `jwk.Fetch()`, `jwk.NewCache()`, and `(*jwk.Cache).Configure()`
func WithFetchWhitelist(v Whitelist) FetchOption {
	return &fetchOption{option.New(identFetchWhitelist{}, v)}
}

// WithHTTPClient allows users to specify the "net/http".Client object that
// is used when fetching jwk.Set objects.
func WithHTTPClient(v HTTPClient) FetchOption {
	return &fetchOption{option.New(identHTTPClient{}, v)}
}

// WithIgnoreParseError is only applicable when used with `jwk.Parse()`
// (i.e. to parse JWK sets). If passed to `jwk.ParseKey()`, the function
// will return an error no matter what the input is.
//
// DO NOT USE WITHOUT EXHAUSTING ALL OTHER ROUTES FIRST.
//
// The option specifies that errors found during parsing of individual
// keys are ignored. For example, if you had keys A, B, C where B is
// invalid (e.g. it does not contain the required fields), then the
// resulting JWKS will contain keys A and C only.
//
// This options exists as an escape hatch for those times when a
// key in a JWKS that is irrelevant for your use case is causing
// your JWKS parsing to fail, and you want to get to the rest of the
// keys in the JWKS.
//
// Again, DO NOT USE unless you have exhausted all other routes.
// When you use this option, you will not be able to tell if you are
// using a faulty JWKS, except for when there are JSON syntax errors.
func WithIgnoreParseError(v bool) ParseOption {
	return &parseOption{option.New(identIgnoreParseError{}, v)}
}

// This option is only available for internal code. Users don't get to play with it
func withLocalRegistry(v *json.Registry) ParseOption {
	return &parseOption{option.New(identLocalRegistry{}, v)}
}

// WithMinRefreshInterval specifies the minimum refresh interval to be used
// when using `jwk.Cache`. This value is ONLY used if you did not specify
// a user-supplied static refresh interval via `WithRefreshInterval`.
//
// This value is used as a fallback value when tokens are refreshed.
//
// When we fetch the key from a remote URL, we first look at the max-age
// directive from Cache-Control response header. If this value is present,
// we compare the max-age value and the value specified by this option
// and take the larger one.
//
// Next we check for the Expires header, and similarly if the header is
// present, we compare it against the value specified by this option,
// and take the larger one.
//
// Finally, if neither of the above headers are present, we use the
// value specified by this option as the next refresh timing
//
// If unspecified, the minimum refresh interval is 1 hour
func WithMinRefreshInterval(v time.Duration) RegisterOption {
	return &registerOption{option.New(identMinRefreshInterval{}, v)}
}

// WithPEM specifies that the input to `Parse()` is a PEM encoded key.
func WithPEM(v bool) ParseOption {
	return &parseOption{option.New(identPEM{}, v)}
}

// WithPostFetcher specifies the PostFetcher object to be used on the
// jwk.Set object obtained in `jwk.Cache`. This option can be used
// to, for example, modify the jwk.Set to give it key IDs or algorithm
// names after it has been fetched and parsed, but before it is cached.
func WithPostFetcher(v PostFetcher) RegisterOption {
	return &registerOption{option.New(identPostFetcher{}, v)}
}

// WithRefreshInterval specifies the static interval between refreshes
// of jwk.Set objects controlled by jwk.Cache.
//
// Providing this option overrides the adaptive token refreshing based
// on Cache-Control/Expires header (and jwk.WithMinRefreshInterval),
// and refreshes will *always* happen in this interval.
func WithRefreshInterval(v time.Duration) RegisterOption {
	return &registerOption{option.New(identRefreshInterval{}, v)}
}

// WithRefreshWindow specifies the interval between checks for refreshes.
//
// See the documentation in `httprc.WithRefreshWindow` for more details.
func WithRefreshWindow(v time.Duration) CacheOption {
	return &cacheOption{option.New(identRefreshWindow{}, v)}
}

func WithThumbprintHash(v crypto.Hash) AssignKeyIDOption {
	return &assignKeyIDOption{option.New(identThumbprintHash{}, v)}
}
