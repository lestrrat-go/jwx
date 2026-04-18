package base64

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
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

// StreamEncoder is an [Encoder] that can also produce an incremental
// [io.WriteCloser] for encoding a byte stream directly into a downstream
// writer. This is the shape the jws streaming detached-payload path needs
// to avoid materializing the payload in memory.
//
// The stdlib *[encoding/base64.Encoding] satisfies this interface
// automatically, so the default jwx encoder does. Extension modules
// providing custom encoders should implement [io.WriteCloser]-returning
// NewEncoder if they want their encoder honored by the streaming path.
type StreamEncoder interface {
	Encoder
	// NewEncoder returns a new [io.WriteCloser] that encodes bytes
	// written to it and forwards the encoded output to w. Close must
	// be called to flush any partial final block.
	NewEncoder(w io.Writer) io.WriteCloser
}

// AsStreamEncoder reports whether e can be used as a [StreamEncoder]
// and returns the stream-capable view. Callers should error out when
// the second return value is false rather than silently falling back to
// a different encoder, to avoid mixing encodings within a single
// signing operation.
//
// The stdlib [*encoding/base64.Encoding] is supported as a special case
// (its streaming form is a top-level function rather than a method, so
// it does not directly satisfy the interface).
func AsStreamEncoder(e Encoder) (StreamEncoder, bool) {
	if s, ok := e.(StreamEncoder); ok {
		return s, true
	}
	if enc, ok := e.(*base64.Encoding); ok {
		return stdStreamEncoder{Encoding: enc}, true
	}
	return nil, false
}

// stdStreamEncoder wraps the stdlib [*base64.Encoding] so it satisfies
// [StreamEncoder]. It is used for the default encoder and as the
// fallback in [AsStreamEncoder] when a caller passes a raw
// [*base64.Encoding].
type stdStreamEncoder struct {
	*base64.Encoding
}

func (e stdStreamEncoder) NewEncoder(w io.Writer) io.WriteCloser {
	return base64.NewEncoder(e.Encoding, w)
}

// encoderHolder and decoderHolder are fixed concrete types so that
// atomic.Value.Store never sees a type change (which would panic).
type encoderHolder struct{ enc Encoder }
type decoderHolder struct{ dec Decoder }

var atomicEncoder atomic.Value
var atomicDecoder atomic.Value

func init() {
	atomicEncoder.Store(encoderHolder{base64.RawURLEncoding})
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
	var enc *base64.Encoding

	switch Guess(src) {
	case RawURL:
		enc = base64.RawURLEncoding
	case URL:
		enc = base64.URLEncoding
	case RawStd:
		enc = base64.RawStdEncoding
	case Std:
		enc = base64.StdEncoding
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
	return base64.RawURLEncoding.Decode(dst, src)
}

// DecodedStrictLen returns the maximum decoded length for a base64url-encoded
// input of length n (no padding).
func DecodedStrictLen(n int) int {
	return base64.RawURLEncoding.DecodedLen(n)
}
