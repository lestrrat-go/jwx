package jwebb

import (
	"github.com/lestrrat-go/jwx/v4/internal/base64"
	"github.com/lestrrat-go/jwx/v4/internal/tokens"
)

// JoinCompact builds JWE compact serialization directly from raw parts.
// The protected header must already be base64url-encoded. The remaining
// parts (encryptedKey, iv, ciphertext, tag) are raw bytes that will be
// base64url-encoded into a single pre-sized output buffer.
//
// The result format is: base64(protected).base64(encryptedKey).base64(iv).base64(ciphertext).base64(tag)
func JoinCompact(encoder base64.Encoder, protected, encryptedKey, iv, ciphertext, tag []byte) []byte {
	protLen := len(protected)
	ekLen := encoder.EncodedLen(len(encryptedKey))
	ivLen := encoder.EncodedLen(len(iv))
	ctLen := encoder.EncodedLen(len(ciphertext))
	tagLen := encoder.EncodedLen(len(tag))

	total := protLen + 1 + ekLen + 1 + ivLen + 1 + ctLen + 1 + tagLen
	result := make([]byte, total)

	pos := copy(result, protected)
	result[pos] = tokens.Period
	pos++

	encoder.Encode(result[pos:pos+ekLen], encryptedKey)
	pos += ekLen
	result[pos] = tokens.Period
	pos++

	encoder.Encode(result[pos:pos+ivLen], iv)
	pos += ivLen
	result[pos] = tokens.Period
	pos++

	encoder.Encode(result[pos:pos+ctLen], ciphertext)
	pos += ctLen
	result[pos] = tokens.Period
	pos++

	encoder.Encode(result[pos:pos+tagLen], tag)

	return result
}
