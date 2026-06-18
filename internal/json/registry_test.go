package json_test

import (
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v4/internal/json"
	"github.com/stretchr/testify/require"
)

// TestRegistryDecodeReentrant ensures that a registered decoder may call
// Register/Unregister on the same registry during Decode without deadlocking.
// Decode must not hold the registry lock while invoking the user-supplied
// decoder.
func TestRegistryDecodeReentrant(t *testing.T) {
	t.Parallel()

	reg := json.NewRegistry()

	// This decoder re-entrantly mutates the same registry during Decode.
	// Before the fix, Decode held an RLock across this call, and the
	// Register/Unregister calls (which take a write Lock) would deadlock.
	json.RegisterCustomDecoder(reg, "field", json.CustomDecodeFunc[string](func(data []byte) (string, error) {
		reg.Register("other", "")
		reg.Unregister("other")
		return string(data), nil
	}))

	done := make(chan struct{})
	var v any
	var err error
	go func() {
		defer close(done)
		v, err = reg.Decode("field", json.RawMessage(`"hello"`))
	}()

	select {
	case <-done:
		require.NoError(t, err)
		require.Equal(t, `"hello"`, v)
	case <-time.After(5 * time.Second):
		t.Fatal("Decode deadlocked: registered decoder could not re-entrantly mutate the registry")
	}
}
