// Package mlkemkdf implements the KMAC256-based KDF specified in
// draft-ietf-jose-pqc-kem for ML-KEM key derivation.
//
// KMAC256 is built on cSHAKE256 per NIST SP 800-185 Section 4.
package mlkemkdf

import (
	"encoding/binary"

	"golang.org/x/crypto/sha3"
)

// kmac256 computes KMAC256(K, X, L, S) per NIST SP 800-185 Section 4.
//
//	K: key
//	x: input data
//	outputLen: desired output length in bytes
//	s: customization string
func kmac256(key, x []byte, outputLen int, s string) []byte {
	// KMAC256(K, X, L, S) = cSHAKE256(bytepad(encode_string(K), 136) || X || right_encode(L), L, "KMAC", S)
	//
	// cSHAKE256 with N="KMAC" and S=s
	h := sha3.NewCShake256([]byte("KMAC"), []byte(s))

	// Write bytepad(encode_string(K), 136)
	writeBytepad(h, key, 136)

	// Write X
	_, _ = h.Write(x)

	// Write right_encode(L) where L = outputLen * 8 (bits)
	_, _ = h.Write(rightEncode(uint64(outputLen) * 8))

	out := make([]byte, outputLen)
	_, _ = h.Read(out)
	return out
}

// writeBytepad writes bytepad(encode_string(X), w) to h.
// bytepad(X, w) = left_encode(w) || X || zeros  (padded to multiple of w)
// Here X = encode_string(K), so we write:
//
//	left_encode(w) || left_encode(len(K)*8) || K || 0-padding
func writeBytepad(h sha3.ShakeHash, x []byte, w int) {
	// left_encode(w)
	lew := leftEncode(uint64(w))
	_, _ = h.Write(lew)

	// encode_string(x) = left_encode(len(x)*8) || x
	les := leftEncode(uint64(len(x)) * 8)
	_, _ = h.Write(les)
	_, _ = h.Write(x)

	// Pad with zeros to multiple of w
	written := len(lew) + len(les) + len(x)
	padLen := w - (written % w)
	if padLen < w {
		zeros := make([]byte, padLen)
		_, _ = h.Write(zeros)
	}
}

// leftEncode encodes x as left_encode(x) per NIST SP 800-185.
// Returns O_1 || ... || O_n || n, where n is the number of bytes needed.
// Wait — left_encode is: n || O_1 || ... || O_n (length prefix first).
func leftEncode(x uint64) []byte {
	if x == 0 {
		return []byte{1, 0}
	}
	// Determine number of bytes needed
	var buf [9]byte // max 8 bytes for uint64 + 1 for length
	binary.BigEndian.PutUint64(buf[1:], x)

	// Find first non-zero byte
	i := 1
	for i < 9 && buf[i] == 0 {
		i++
	}

	// buf[0] = number of significant bytes
	n := byte(9 - i)
	buf[i-1] = n
	return buf[i-1:]
}

// rightEncode encodes x as right_encode(x) per NIST SP 800-185.
// Returns O_1 || ... || O_n || n (value bytes, then length byte).
func rightEncode(x uint64) []byte {
	if x == 0 {
		return []byte{0, 1}
	}
	var buf [9]byte
	binary.BigEndian.PutUint64(buf[:8], x)

	// Find first non-zero byte
	i := 0
	for i < 8 && buf[i] == 0 {
		i++
	}

	n := byte(8 - i)
	buf[8] = n
	return buf[i:]
}
