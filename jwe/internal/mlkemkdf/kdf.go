package mlkemkdf

import "encoding/binary"

// DeriveKey derives a key from the ML-KEM shared secret per draft-ietf-jose-pqc-kem.
//
// The KDF uses KMAC256 per NIST SP 800-108r1-upd1 with context fields from
// NIST SP 800-56Ar3 Section 5.8.1:
//
//	SS = KMAC256(K=sharedSecret, X=AlgorithmID||SuppPubInfo, L=ssLen*8, S="")
//
// Parameters:
//   - sharedSecret: the raw 32-byte shared secret from KEM Encapsulate/Decapsulate
//   - alg: the algorithm identifier string — for direct mode, use the "enc" (content
//     encryption) algorithm; for key-wrap mode, use the "alg" (key encryption) algorithm
//   - ssLen: desired output key length in bytes
func DeriveKey(sharedSecret []byte, alg string, ssLen int) []byte {
	// Build X = AlgorithmID || SuppPubInfo
	// AlgorithmID = UTF-8 bytes of alg
	// SuppPubInfo = 4-byte big-endian key data length in bits
	algBytes := []byte(alg)
	var suppPubInfo [4]byte
	binary.BigEndian.PutUint32(suppPubInfo[:], uint32(ssLen)*8)

	x := make([]byte, len(algBytes)+4)
	copy(x, algBytes)
	copy(x[len(algBytes):], suppPubInfo[:])

	return kmac256(sharedSecret, x, ssLen, "")
}
