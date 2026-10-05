package json

import (
	"bytes"
	"encoding/json/jsontext"
	jsonv2 "encoding/json/v2"
	"fmt"
	"math"
	"strconv"
)

// FieldProbe indexes only the immediate members of a JSON object (or array).
// It owns its input and preserves duplicate object members in document order.
// Nested values are validated, but no tree is allocated for them. Like the
// building-block Header APIs which use it, it is not safe for concurrent use.
type FieldProbe struct {
	data    []byte
	entries []probeEntry
	inline  [4]probeEntry
	kind    jsontext.Kind
}

type probeEntry struct {
	name  []byte
	value ProbeValue
}

// ProbeValue retains the original JSON number spelling, so integer accessors
// never round through float64. String bytes are decoded lazily in owned memory.
type ProbeValue struct {
	raw           []byte
	kind          jsontext.Kind
	stringDecoded bool
}

func ParseFieldProbe(data []byte) (*FieldProbe, error) {
	p := &FieldProbe{data: bytes.Clone(data)}
	p.entries = p.inline[:0]
	if err := jsonv2.Unmarshal(p.data, p, jsontext.AllowDuplicateNames(true)); err != nil {
		return nil, err
	}
	return p, nil
}

func (p *FieldProbe) UnmarshalJSONFrom(dec *jsontext.Decoder) error {
	p.kind = dec.PeekKind()
	if p.kind != '{' && p.kind != '[' {
		return dec.SkipValue()
	}
	if _, err := dec.ReadToken(); err != nil {
		return err
	}
	end := jsontext.Kind('}')
	if p.kind == '[' {
		end = ']'
	}
	for dec.PeekKind() != end {
		var name []byte
		if p.kind == '{' {
			start := int(dec.InputOffset())
			tok, err := dec.ReadToken()
			if err != nil {
				return err
			}
			raw := bytes.TrimLeft(p.data[start:int(dec.InputOffset())], ",: \t\r\n")
			if bytes.IndexByte(raw, '\\') < 0 {
				name = raw[1 : len(raw)-1]
			} else {
				// The decoder still needs the original name for error pointers.
				name = []byte(tok.String())
			}
		}
		raw, err := dec.ReadValue()
		if err != nil {
			return err
		}
		p.entries = append(p.entries, probeEntry{
			name:  name,
			value: ProbeValue{raw: p.inputValue(dec, raw), kind: raw.Kind()},
		})
	}
	_, err := dec.ReadToken()
	return err
}

// ReadValue's buffer is borrowed from a pooled decoder. Its input offset and
// length locate the same value in our owned input instead. Leading delimiters
// and whitespace are excluded by ReadValue; InputOffset is the value's end.
func (p *FieldProbe) inputValue(dec *jsontext.Decoder, raw jsontext.Value) []byte {
	end := int(dec.InputOffset())
	return p.data[end-len(raw) : end]
}

func (p *FieldProbe) Get(key string) *ProbeValue {
	switch p.kind {
	case '{':
		for i := range p.entries {
			if string(p.entries[i].name) == key {
				return &p.entries[i].value
			}
		}
	case '[':
		if i, err := strconv.Atoi(key); err == nil && i >= 0 && i < len(p.entries) {
			return &p.entries[i].value
		}
	}
	return nil
}

func (p *FieldProbe) ForEachKey(fn func([]byte)) error {
	if p.kind != '{' {
		return fmt.Errorf("expected JSON object, got %s", p.kind)
	}
	for i := range p.entries {
		fn(p.entries[i].name)
	}
	return nil
}

func probeString(raw []byte) ([]byte, error) {
	if bytes.IndexByte(raw, '\\') < 0 {
		return raw[1 : len(raw)-1], nil
	}
	var s string
	if err := jsonv2.Unmarshal(raw, &s); err != nil {
		return nil, err
	}
	// The unescaped representation cannot be longer than the original. The
	// caller owns raw and no longer needs its quoted representation.
	n := copy(raw, s)
	return raw[:n], nil
}

func (v *ProbeValue) requireKind(kind jsontext.Kind) error {
	if v.kind != kind {
		return fmt.Errorf("expected %s, got %s", kind, v.kind)
	}
	return nil
}

func (v *ProbeValue) StringBytes() ([]byte, error) {
	if err := v.requireKind('"'); err != nil {
		return nil, err
	}
	if !v.stringDecoded {
		raw, err := probeString(v.raw)
		if err != nil {
			return nil, err
		}
		v.raw = raw
		v.stringDecoded = true
	}
	return v.raw, nil
}

func (v *ProbeValue) Bool() (bool, error) {
	switch v.kind {
	case 't':
		return true, nil
	case 'f':
		return false, nil
	default:
		return false, fmt.Errorf("expected boolean, got %s", v.kind)
	}
}

func (v *ProbeValue) Float64() (float64, error) {
	if err := v.requireKind('0'); err != nil {
		return 0, err
	}
	n, err := strconv.ParseFloat(string(v.raw), 64)
	// Preserve the building-block accessor's saturation behavior for valid
	// JSON numbers outside float64's range.
	if math.IsInf(n, 0) {
		return n, nil
	}
	return n, err
}

func (v *ProbeValue) Int() (int, error) {
	if err := v.requireKind('0'); err != nil {
		return 0, err
	}
	n, err := strconv.ParseInt(string(v.raw), 10, strconv.IntSize)
	if err != nil {
		return 0, err
	}
	return int(n), nil
}

func (v *ProbeValue) Int64() (int64, error) {
	if err := v.requireKind('0'); err != nil {
		return 0, err
	}
	n, err := strconv.ParseInt(string(v.raw), 10, 64)
	if err != nil {
		return 0, err
	}
	return n, nil
}

func (v *ProbeValue) Uint() (uint, error) {
	if err := v.requireKind('0'); err != nil {
		return 0, err
	}
	n, err := strconv.ParseUint(string(v.raw), 10, strconv.IntSize)
	if err != nil {
		return 0, err
	}
	return uint(n), nil
}

func (v *ProbeValue) Uint64() (uint64, error) {
	if err := v.requireKind('0'); err != nil {
		return 0, err
	}
	n, err := strconv.ParseUint(string(v.raw), 10, 64)
	if err != nil {
		return 0, err
	}
	return n, nil
}

func (v *ProbeValue) StringArray() ([]string, error) {
	if err := v.requireKind('['); err != nil {
		return nil, err
	}
	var target stringArrayProbe
	if err := jsonv2.Unmarshal(v.raw, &target); err != nil {
		return nil, err
	}
	return target.values, nil
}

type stringArrayProbe struct{ values []string }

func (p *stringArrayProbe) UnmarshalJSONFrom(dec *jsontext.Decoder) error {
	if _, err := dec.ReadToken(); err != nil {
		return err
	}
	p.values = make([]string, 0)
	for dec.PeekKind() != ']' {
		tok, err := dec.ReadToken()
		if err != nil {
			return err
		}
		if tok.Kind() != '"' {
			return fmt.Errorf("expected string array element, got %s", tok.Kind())
		}
		p.values = append(p.values, tok.String())
	}
	_, err := dec.ReadToken()
	return err
}

// HasField validates the complete JSON input while checking only top-level
// object member presence. It does not copy the input or retain nested values.
func HasField(data []byte, name string) (bool, error) {
	p := fieldPresence{name: name}
	err := jsonv2.Unmarshal(data, &p, jsontext.AllowDuplicateNames(true))
	return p.found, err
}

type fieldPresence struct {
	name  string
	found bool
}

func (p *fieldPresence) UnmarshalJSONFrom(dec *jsontext.Decoder) error {
	if dec.PeekKind() != '{' {
		return dec.SkipValue()
	}
	if _, err := dec.ReadToken(); err != nil {
		return err
	}
	for dec.PeekKind() != '}' {
		tok, err := dec.ReadToken()
		if err != nil {
			return err
		}
		if tok.String() == p.name {
			p.found = true
		}
		if err := dec.SkipValue(); err != nil {
			return err
		}
	}
	_, err := dec.ReadToken()
	return err
}
