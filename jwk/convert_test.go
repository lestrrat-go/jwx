package jwk_test

import (
	"testing"

	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/stretchr/testify/require"
)

// keyKinderMock is a minimal jwk.Key that only implements KeyType() and
// KeyKind(). The embedded jwk.Key interface is nil at runtime; only
// findExporters dispatches on this mock, and the sentinel exporter
// registered in the test never touches the other Key methods.
type keyKinderMock struct {
	jwk.Key
	kty  jwa.KeyType
	kind jwk.KeyKind
}

func (m keyKinderMock) KeyType() jwa.KeyType { return m.kty }
func (m keyKinderMock) KeyKind() jwk.KeyKind { return m.kind }

func TestFindExportersCaseInsensitiveKeyKind(t *testing.T) {
	const (
		registeredIdent = jwk.KeyKind("TESTKIND:FindExporters")
		mockIdent       = jwk.KeyKind("testkind:findexporters")
	)
	mockKty := jwa.NewKeyType("Test-FindExporters")

	type sentinelType struct{ name string }
	sentinel := sentinelType{name: "sentinel"}
	require.NoError(t,
		jwk.RegisterKeyExporter(registeredIdent, jwk.KeyExportFunc(func(_ jwk.Key, _ any) (any, error) {
			return sentinel, nil
		})),
		"RegisterKeyExporter should succeed")

	got, err := jwk.Export[any](keyKinderMock{kty: mockKty, kind: mockIdent})
	require.NoError(t, err, "Export should dispatch via case-insensitive KeyKind")
	require.Equal(t, sentinel, got, "Export should return sentinel from registered exporter")
}
