package json

import (
	"bytes"
	"encoding/json"
	"io"
	"sync"
)

type Number = json.Number
type RawMessage = json.RawMessage

var muGlobalConfig sync.RWMutex
var useNumber bool

// Sets the global configuration for json decoding
func DecoderSettings(inUseNumber bool) {
	muGlobalConfig.Lock()
	useNumber = inUseNumber
	muGlobalConfig.Unlock()
}

// NewDecoder respects the values specified in DecoderSettings,
// and creates a Decoder that has certain features turned on/off
func NewDecoder(r io.Reader) *json.Decoder {
	dec := json.NewDecoder(r)

	muGlobalConfig.RLock()
	if useNumber {
		dec.UseNumber()
	}
	muGlobalConfig.RUnlock()

	return dec
}

// Unmarshal respects the values specified in DecoderSettings,
// and uses a Decoder that has certain features turned on/off
func Unmarshal(b []byte, v interface{}) error {
	dec := NewDecoder(bytes.NewReader(b))
	return dec.Decode(v)
}

// NewEncoder is just a proxy for "encoding/json".NewEncoder
func NewEncoder(w io.Writer) *json.Encoder {
	return json.NewEncoder(w)
}

// Marshal is just a proxy for "encoding/json".Marshal
func Marshal(v interface{}) ([]byte, error) {
	return json.Marshal(v)
}

// MarshalIndent is just a proxy for "encoding/json".MarshalIndent
func MarshalIndent(v interface{}, prefix, indent string) ([]byte, error) {
	return json.MarshalIndent(v, prefix, indent)
}
