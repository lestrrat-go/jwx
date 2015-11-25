package emap

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
)

type SubDummy struct {
	Quux string `json:"quux"`
}

type DummyEssential struct {
	Foo string   `json:"foo"`
	Bar int      `json:"bar"`
	Baz SubDummy `json:"baz"`
}

type Dummy struct {
	DummyEssential `json:"-"`
	ExtraElements  map[string]interface{} `json:"-"`
}

func (d Dummy) MarshalJSON() ([]byte, error) {
	return MergeMarshal(d.DummyEssential, d.ExtraElements)
}

func (d *Dummy) UnmarshalJSON(data []byte) error {
	return MergeUnmarshal(data, &d.DummyEssential, &d.ExtraElements)
}

func (d *DummyEssential) Construct(m map[string]interface{}) error {
	if v, ok := m["foo"]; ok {
		if s, ok := v.(string); ok {
			d.Foo = s
		}
		delete(m, "foo")
	}

	if v, ok := m["bar"]; ok {
		if s, ok := v.(float64); ok {
			d.Bar = int(s)
		}
		delete(m, "bar")
	}

	if v, ok := m["baz"]; ok {
		if s, ok := v.(map[string]interface{}); ok {
			if k, ok := s["quux"]; ok {
				if x, ok := k.(string); ok {
					d.Baz = SubDummy{Quux: x}
					delete(m, "baz")
				}
			}
		}
	}
	return nil
}

func TestRoundTrip(t *testing.T) {
	d1 := &Dummy{}
	d1.Foo = "foo!"
	d1.Bar = 999
	d1.Baz = SubDummy{
		Quux: "quux!",
	}
	d1.ExtraElements = map[string]interface{}{
		"hoge": "fuga",
	}

	buf, err := json.Marshal(d1)
	if !assert.NoError(t, err, "Failed to marshal") {
		return
	}

	d2 := &Dummy{}
	if !assert.NoError(t, json.Unmarshal(buf, d2), "Failed to unmarshal") {
		return
	}

	if !assert.Equal(t, d1, d2) {
		return
	}
}
