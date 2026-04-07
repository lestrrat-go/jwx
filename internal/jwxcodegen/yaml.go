package jwxcodegen

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/goccy/go-yaml"
)

// YAML2JSON reads a YAML file and converts it to JSON bytes.
// This is used by code generators to parse YAML config files
// into codegen.Object via JSON decoding.
func YAML2JSON(fn string) ([]byte, error) {
	in, err := os.Open(fn)
	if err != nil {
		return nil, fmt.Errorf(`failed to open %q: %w`, fn, err)
	}
	defer in.Close()

	var v any
	if err := yaml.NewDecoder(in).Decode(&v); err != nil {
		return nil, fmt.Errorf(`failed to decode %q: %w`, fn, err)
	}

	return json.Marshal(v)
}
