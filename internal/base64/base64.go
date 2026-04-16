package base64

import (
	"bytes"
	stdbase64 "encoding/base64"
	"encoding/binary"
	"fmt"
	"sync/atomic"
)

type Decoder interface {
	Decode([]byte) ([]byte, error)
}

type Encoder interface {
	Encode([]byte, []byte)
	EncodedLen(int) int
	EncodeToString([]byte) string
	AppendEncode([]byte, []byte) []byte
}

type stdEncoder struct {
	enc *stdbase64.Encoding
}

func (e stdEncoder) Encode(dst, src []byte) {
	e.enc.Encode(dst, src)
}

func (e stdEncoder) EncodedLen(n int) int {
	return e.enc.EncodedLen(n)
}

func (e stdEncoder) EncodeToString(src []byte) string {
	return e.enc.EncodeToString(src)
}

func (e stdEncoder) AppendEncode(dst, src []byte) []byte {
	return e.enc.AppendEncode(dst, src)
}

// encoderHolder and decoderHolder are fixed concrete types so that
// atomic.Value.Store never sees a type change (which would panic).
type encoderHolder struct{ enc Encoder }
type decoderHolder struct{ dec Decoder }

var atomicEncoder atomic.Value
var atomicDecoder atomic.Value

func init() {
	atomicEncoder.Store(encoderHolder{stdEncoder{enc: stdbase64.RawURLEncoding}})
	atomicDecoder.Store(decoderHolder{defaultDecoder{}})
}

func SetEncoder(enc Encoder) {
	atomicEncoder.Store(encoderHolder{enc})
}

func getEncoder() Encoder {
	//nolint:forcetypeassert
	return atomicEncoder.Load().(encoderHolder).enc
}

func DefaultEncoder() Encoder {
	return getEncoder()
}

func SetDecoder(dec Decoder) {
	atomicDecoder.Store(decoderHolder{dec})
}

func getDecoder() Decoder {
	//nolint:forcetypeassert
	return atomicDecoder.Load().(decoderHolder).dec
}

func Encode(src []byte) []byte {
	encoder := getEncoder()
	dst := make([]byte, encoder.EncodedLen(len(src)))
	encoder.Encode(dst, src)
	return dst
}

func AppendEncode(dst, src []byte) []byte {
	return getEncoder().AppendEncode(dst, src)
}

func EncodedLen(n int) int {
	return getEncoder().EncodedLen(n)
}

func EncodeToString(src []byte) string {
	return getEncoder().EncodeToString(src)
}

func EncodeUint64ToString(v uint64) string {
	data := make([]byte, 8)
	binary.BigEndian.PutUint64(data, v)

	i := 0
	for ; i < len(data); i++ {
		if data[i] != 0x0 {
			break
		}
	}

	return EncodeToString(data[i:])
}

const (
	InvalidEncoding = iota
	Std
	URL
	RawStd
	RawURL
)

func Guess(src []byte) int {
	var isRaw = !bytes.HasSuffix(src, []byte{'='})
	var isURL = !bytes.ContainsAny(src, "+/")
	switch {
	case isRaw && isURL:
		return RawURL
	case isURL:
		return URL
	case isRaw:
		return RawStd
	default:
		return Std
	}
}

// defaultDecoder is a Decoder that detects the encoding of the source and
// decodes it accordingly. This shouldn't really be required per the spec, but
// it exist because we have seen in the wild JWTs that are encoded using
// various versions of the base64 encoding.
type defaultDecoder struct{}

func (defaultDecoder) Decode(src []byte) ([]byte, error) {
	var enc *stdbase64.Encoding

	switch Guess(src) {
	case RawURL:
		enc = stdbase64.RawURLEncoding
	case URL:
		enc = stdbase64.URLEncoding
	case RawStd:
		enc = stdbase64.RawStdEncoding
	case Std:
		enc = stdbase64.StdEncoding
	default:
		return nil, fmt.Errorf(`invalid encoding`)
	}

	dst := make([]byte, enc.DecodedLen(len(src)))
	n, err := enc.Decode(dst, src)
	if err != nil {
		return nil, fmt.Errorf(`failed to decode source: %w`, err)
	}
	return dst[:n], nil
}

func Decode(src []byte) ([]byte, error) {
	return getDecoder().Decode(src)
}

func DecodeString(src string) ([]byte, error) {
	return getDecoder().Decode([]byte(src))
}

// DecodeStrict decodes base64url-encoded data (RFC 7515 / RFC 4648 §5, no padding)
// directly using base64.RawURLEncoding. It writes into the provided dst buffer
// and returns the number of bytes written.
//
// Unlike Decode, this function does not auto-detect the encoding variant,
// does not acquire any mutex, and does not allocate. The caller must ensure
// dst is large enough (use DecodedStrictLen).
func DecodeStrict(dst, src []byte) (int, error) {
	return stdbase64.RawURLEncoding.Decode(dst, src)
}

// DecodedStrictLen returns the maximum decoded length for a base64url-encoded
// input of length n (no padding).
func DecodedStrictLen(n int) int {
	return stdbase64.RawURLEncoding.DecodedLen(n)
}
