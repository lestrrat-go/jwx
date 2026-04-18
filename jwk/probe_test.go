package jwk

import (
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestProbeFieldRegistrationConcurrent exercises the race between
// RegisterProbeField (mutating the prober's field/name maps) and
// concurrent KeyProbe.Field reads on a KeyProbe captured from an
// earlier Probe call. Must pass under `go test -race`.
func TestProbeFieldRegistrationConcurrent(t *testing.T) {
	probe, err := keyProbe.Probe(rsaPrivateKeyJSON)
	require.NoError(t, err, `Probe should succeed`)

	stop := make(chan struct{})
	var wg sync.WaitGroup

	// Reader: hammer KeyProbe.Field on the captured probe.
	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
					_, _ = probe.Field("Kty")
					_, _ = probe.Field("D")
				}
			}
		}()
	}

	// Writer: register a batch of fresh fields. Each Register call
	// mutates the prober's internal state that the Reader goroutines
	// also reach via the captured KeyProbe.
	for i := range 16 {
		name := "__jwktest_probe_" + string(rune('a'+i%26)) + string(rune('a'+i/26))
		jsonKey := "__jwktest_jsonkey_" + string(rune('a'+i%26)) + string(rune('a'+i/26))
		require.NoError(t, RegisterProbeField[string](name, jsonKey))
	}

	close(stop)
	wg.Wait()
}
