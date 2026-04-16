package json

import (
	"encoding/json/jsontext"
	jsonv2 "encoding/json/v2"
	"fmt"
	"io"

	"sync/atomic"

	"github.com/lestrrat-go/jwx/v4/internal/base64"
)

var globalUseNumber atomic.Bool

// SetUseNumber controls whether JSON numbers in private/custom fields
// should be decoded as json.Number instead of float64.
func SetUseNumber(v bool) {
	globalUseNumber.Store(v)
}

// GetUseNumber returns the current UseNumber setting.
func GetUseNumber() bool {
	return globalUseNumber.Load()
}

type (
	Decoder    = jsontext.Decoder
	Encoder    = jsontext.Encoder
	RawMessage = jsontext.Value
)

func Engine() string {
	return "encoding/json/v2"
}

func NewDecoder(r io.Reader) *jsontext.Decoder {
	return jsontext.NewDecoder(r)
}

func NewEncoder(w io.Writer) *jsontext.Encoder {
	return jsontext.NewEncoder(w)
}

func Marshal(v any) ([]byte, error) {
	return jsonv2.Marshal(v)
}

func MarshalIndent(v any, prefix, indent string) ([]byte, error) {
	b, err := jsonv2.Marshal(v)
	if err != nil {
		return nil, err
	}
	var val jsontext.Value = b
	if err := val.Indent(jsontext.WithIndentPrefix(prefix), jsontext.WithIndent(indent)); err != nil {
		return nil, err
	}
	return []byte(val), nil
}

func Unmarshal(b []byte, v any) error {
	return jsonv2.Unmarshal(b, v)
}

func MarshalEncode(enc *jsontext.Encoder, v any) error {
	return jsonv2.MarshalEncode(enc, v)
}

func UnmarshalDecode(dec *jsontext.Decoder, v any) error {
	return jsonv2.UnmarshalDecode(dec, v)
}

func AssignNextBytesToken(dst *[]byte, dec *Decoder) error {
	tok, err := dec.ReadToken()
	if err != nil {
		return fmt.Errorf(`error reading next value: %w`, err)
	}
	if tok.Kind() != jsontext.KindString {
		return fmt.Errorf(`expected string token for base64 value, got %s`, tok.Kind())
	}

	buf, err := base64.DecodeString(tok.String())
	if err != nil {
		return fmt.Errorf(`expected base64 encoded []byte`)
	}
	*dst = buf
	return nil
}

func shouldRejectNullStrings(dc DecodeCtx) bool {
	if dc != nil {
		if sdc, ok := dc.(StrictStringDecodeCtx); ok {
			return sdc.StrictStrings()
		}
	}
	return false
}

// ReadNextStringToken reads the next JSON token from the decoder and
// returns it as a string. By default, JSON null is silently accepted as "".
// When the given DecodeCtx implements StrictStringDecodeCtx and StrictStrings()
// returns true, null values are rejected.
func ReadNextStringToken(dec *Decoder, dc DecodeCtx) (string, error) {
	tok, err := dec.ReadToken()
	if err != nil {
		return "", fmt.Errorf(`error reading next value: %w`, err)
	}

	switch tok.Kind() {
	case jsontext.KindNull:
		if shouldRejectNullStrings(dc) {
			return "", fmt.Errorf(`error reading next value: expected string, got null`)
		}
		return "", nil
	case jsontext.KindString:
		return tok.String(), nil
	default:
		return "", fmt.Errorf(`error reading next value: expected string, got %s`, tok.Kind())
	}
}

func AssignNextStringToken(dst **string, dec *Decoder, dc DecodeCtx) error {
	val, err := ReadNextStringToken(dec, dc)
	if err != nil {
		return err
	}
	*dst = &val
	return nil
}

// FlattenAudience is a flag to specify if we should flatten the "aud"
// entry to a string when there's only one entry.
// In jwx < 1.1.8 we just dumped everything as an array of strings,
// but apparently AWS Cognito doesn't handle this well.
//
// So now we have the ability to dump "aud" as a string if there's
// only one entry, but we need to retain the old behavior so that
// we don't accidentally break somebody else's code. (e.g. messing
// up how signatures are calculated)
var FlattenAudience uint32

func MarshalAudience(aud []string, flatten bool) ([]byte, error) {
	var val any
	if len(aud) == 1 && flatten {
		val = aud[0]
	} else {
		val = aud
	}
	return Marshal(val)
}

func EncodeAudience(enc *Encoder, aud []string, flatten bool) error {
	var val any
	if len(aud) == 1 && flatten {
		val = aud[0]
	} else {
		val = aud
	}
	return MarshalEncode(enc, val)
}

// DecodeCtx is an interface for objects that needs that extra something
// when decoding JSON into an object.
type DecodeCtx interface {
	Registry() *Registry
}

// DecodeCtxContainer is used to differentiate objects that can carry extra
// decoding hints and those who can't.
type DecodeCtxContainer interface {
	DecodeCtx() DecodeCtx
	SetDecodeCtx(DecodeCtx)
}

// StrictStringDecodeCtx is an optional interface that DecodeCtx implementations
// can satisfy to control per-call null string rejection.
type StrictStringDecodeCtx interface {
	StrictStrings() bool
}

// stock decodeCtx. should cover 80% of the cases
type decodeCtx struct {
	registry      *Registry
	strictStrings bool
}

// NewDecodeCtx creates a new DecodeCtx with the given registry.
func NewDecodeCtx(r *Registry) DecodeCtx {
	return &decodeCtx{registry: r}
}

// NewDecodeCtxStrictStrings creates a new DecodeCtx with the given registry
// and strict string rejection flag.
func NewDecodeCtxStrictStrings(r *Registry, strict bool) DecodeCtx {
	return &decodeCtx{registry: r, strictStrings: strict}
}

func (dc *decodeCtx) Registry() *Registry {
	return dc.registry
}

func (dc *decodeCtx) StrictStrings() bool {
	return dc.strictStrings
}
