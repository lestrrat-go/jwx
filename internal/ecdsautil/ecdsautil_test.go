package ecdsautil

import (
	"bytes"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"testing"
)

func TestKeyConversions(t *testing.T) {

	const ECPrivateKey = `-----BEGIN PRIVATE KEY-----
MHcCAQEEIModxWofWpbtNo6KlPEUzX6M5BoqVhcriHM/jtQYcDMDoAoGCCqGSM49
AwEHoUQDQgAE2mFHYH1k9QGmpzTirHWgGtRRKmFh8deqKNZVUuxEH4sIQrj2zOkP
7YzeEixA9G+d7ZEPp221fqA5i0u+PchowA==
-----END PRIVATE KEY-----`

	expectedECRawKeyBytes := []byte{123, 34, 99, 114, 118, 34, 58, 34, 80, 45, 50, 53, 54, 34, 44, 34, 100, 34, 58, 34, 121, 104, 51, 70, 97, 104, 57, 97, 108, 117, 48, 50, 106, 111, 113, 85, 56, 82, 84, 78, 102, 111, 122, 107, 71, 105, 112, 87, 70, 121, 117, 73, 99, 122, 45, 79, 49, 66, 104, 119, 77, 119, 77, 34, 44, 34, 120, 34, 58, 34, 50, 109, 70, 72, 89, 72, 49, 107, 57, 81, 71, 109, 112, 122, 84, 105, 114, 72, 87, 103, 71, 116, 82, 82, 75, 109, 70, 104, 56, 100, 101, 113, 75, 78, 90, 86, 85, 117, 120, 69, 72, 52, 115, 34, 44, 34, 121, 34, 58, 34, 67, 69, 75, 52, 57, 115, 122, 112, 68, 45, 50, 77, 51, 104, 73, 115, 81, 80, 82, 118, 110, 101, 50, 82, 68, 54, 100, 116, 116, 88, 54, 103, 79, 89, 116, 76, 118, 106, 51, 73, 97, 77, 65, 34, 125}

	t.Run("RawKeyFromPrivateKey", func(t *testing.T) {

		block, _ := pem.Decode([]byte(ECPrivateKey))
		privateKey, _ := x509.ParseECPrivateKey(block.Bytes)
		rawKey := NewRawKeyFromPrivateKey(privateKey)
		rawKeyBytes, _ := json.Marshal(rawKey)
		if bytes.Compare(expectedECRawKeyBytes, rawKeyBytes) != 0 {
			t.Fatal("Keys dop not match")
		}
	})

}
