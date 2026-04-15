package jwe_test

import (
	"testing"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwe"
	"github.com/stretchr/testify/require"
)

// TestPerRecipientHeadersIsolation is a regression test for the pool-leak
// bug where WithPerRecipientHeaders stored the caller's Headers pointer
// directly: freeRecipient would later clear() it (zeroing a value the
// caller still held), and the pooled recipient retained the same pointer
// for the next Encrypt to mutate. After the fix, WithPerRecipientHeaders
// clones the caller's Headers, and freeRecipient returns the clone to
// headerPool while installing a fresh placeholder on the recipient.
func TestPerRecipientHeadersIsolation(t *testing.T) {
	key := critTestKey(t)

	caller := jwe.NewHeaders()
	require.NoError(t, caller.Set(jwe.KeyIDKey, "user-kid"))

	// Two back-to-back encrypts so any pool reuse of the recipient
	// would re-touch caller on the second pass.
	for range 2 {
		_, err := jwe.Encrypt([]byte(`hello`),
			jwe.WithKey(jwa.A128KW(), key, jwe.WithPerRecipientHeaders(caller)),
			jwe.WithContentEncryption(jwa.A128CBC_HS256()),
		)
		require.NoError(t, err, `jwe.Encrypt should succeed`)

		kid, ok := caller.KeyID()
		require.True(t, ok, `caller.KeyID should still be set after Encrypt`)
		require.Equal(t, "user-kid", kid, `caller.KeyID must not be mutated by Encrypt`)

		alg, ok := caller.Algorithm()
		require.False(t, ok, `caller.Algorithm should not have been written by Encrypt (got %q)`, alg)
	}
}
