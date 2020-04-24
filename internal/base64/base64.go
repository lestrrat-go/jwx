package base64

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"strings"

	"github.com/pkg/errors"
)

func EncodeToStringStd(src []byte) string {
	return base64.StdEncoding.EncodeToString(src)
}

func EncodeToString(src []byte) string {
	return base64.RawURLEncoding.EncodeToString(src)
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

func Decode(src []byte) ([]byte, error) {
	var isRaw = src[len(src)-1] == '='
	var enc *base64.Encoding
	if bytes.ContainsAny(src, "+/") {
		if isRaw {
			enc = base64.RawStdEncoding
		} else {
			enc = base64.StdEncoding
		}
	} else if isRaw {
		enc = base64.RawURLEncoding
	} else {
		enc = base64.URLEncoding
	}

	dst := make([]byte, enc.DecodedLen(len(src)))

	if _, err := enc.Decode(src, dst); err != nil {
		return nil, errors.Wrapf(err, `failed to decode base64 encoded buffer %s`, src)
	}
	return dst, nil
}

func DecodeString(src string) ([]byte, error) {
	var isRaw = !strings.HasSuffix(src, "=")
	if strings.ContainsAny(src, "+/") {
		if isRaw {
			return base64.RawStdEncoding.DecodeString(src)
		}
		return base64.StdEncoding.DecodeString(src)
	}

	if isRaw {
		return base64.RawURLEncoding.DecodeString(src)
	}
	return base64.URLEncoding.DecodeString(src)
}

func AddPadding(src []byte) []byte {
	count := len(src) % 4
	if count == 0 {
		return src
	}

	padding := make([]byte, count)
	for i := 0; i < len(padding); i++ {
		padding[i] = '='
	}
	return append(src, padding...)
}
