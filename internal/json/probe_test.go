package json_test

import (
	"bytes"
	"encoding/json/jsontext"
	"errors"
	"math"
	"strconv"
	"testing"

	"github.com/lestrrat-go/jwx/v4/internal/json"
	"github.com/stretchr/testify/require"
)

func TestFieldProbe(t *testing.T) {
	t.Run("escaped duplicate lookup is stable", func(t *testing.T) {
		for _, src := range []string{
			`{"al\u0067":"HS256","alg":"none"}`,
			`{"alg":"HS256","al\u0067":"none"}`,
		} {
			p, err := json.ParseFieldProbe([]byte(src))
			require.NoError(t, err)
			for range 2 {
				alg, err := p.Get("alg").StringBytes()
				require.NoError(t, err)
				require.Equal(t, "HS256", string(alg))
				require.Nil(t, p.Get("missing"))
				var names []string
				require.NoError(t, p.ForEachKey(func(name []byte) { names = append(names, string(name)) }))
				require.Equal(t, []string{"alg", "alg"}, names)
			}
		}
	})

	t.Run("syntax errors retain escaped field pointers", func(t *testing.T) {
		for _, tc := range []struct{ src, pointer string }{
			{`{"\u0061":}`, "/a"},
			{`{"\u0061":{"x": }}`, "/a/x"},
			{`{"a\u002fb":{"\u007e": }}`, "/a~1b/~0"},
		} {
			_, err := json.ParseFieldProbe([]byte(tc.src))
			syntaxErr, ok := errors.AsType[*jsontext.SyntacticError](err)
			require.True(t, ok, "%v", err)
			require.Equal(t, jsontext.Pointer(tc.pointer), syntaxErr.JSONPointer)
		}
	})

	t.Run("float conversion uses standard rounding", func(t *testing.T) {
		for _, number := range []string{"1.23e-20", "1.234e-20", "-1.23e-20"} {
			p, err := json.ParseFieldProbe([]byte(`{"n":` + number + `}`))
			require.NoError(t, err)
			got, err := p.Get("n").Float64()
			require.NoError(t, err)
			want, err := strconv.ParseFloat(number, 64)
			require.NoError(t, err)
			require.Equal(t, math.Float64bits(want), math.Float64bits(got))
		}
	})

	t.Run("owns input and preserves duplicates and escaped names", func(t *testing.T) {
		src := []byte(" \n { \"alg\" : \"HS256\", \"al\\u0067\":\"none\", \"kid\":\"escaped\\\"key\", \"nested\":{\"a\":1,\"a\":2}} \t")
		p, err := json.ParseFieldProbe(src)
		require.NoError(t, err)
		clear(src)
		var names []string
		require.NoError(t, p.ForEachKey(func(name []byte) { names = append(names, string(name)) }))
		require.Equal(t, []string{"alg", "alg", "kid", "nested"}, names)
		alg, err := p.Get("alg").StringBytes()
		require.NoError(t, err)
		require.Equal(t, "HS256", string(alg))
		kid, err := p.Get("kid").StringBytes()
		require.NoError(t, err)
		require.Equal(t, `escaped"key`, string(kid))
		// Neither a second accessor nor another pooled parse invalidates bytes.
		_, err = json.ParseFieldProbe([]byte(`{"kid":"another"}`))
		require.NoError(t, err)
		again, err := p.Get("kid").StringBytes()
		require.NoError(t, err)
		require.Equal(t, kid, again)
		require.Equal(t, `escaped"key`, string(kid))
		require.Nil(t, p.Get("missing"))
	})

	t.Run("integer precision and overflow", func(t *testing.T) {
		p, err := json.ParseFieldProbe([]byte(`{"max":9223372036854775807,"min":-9223372036854775808,"umax":18446744073709551615,"overflow":18446744073709551616,"fraction":1.5,"exponent":1e2,"negative":-1}`))
		require.NoError(t, err)
		n, err := p.Get("max").Int64()
		require.NoError(t, err)
		require.Equal(t, int64(math.MaxInt64), n)
		n, err = p.Get("min").Int64()
		require.NoError(t, err)
		require.Equal(t, int64(math.MinInt64), n)
		u, err := p.Get("umax").Uint64()
		require.NoError(t, err)
		require.Equal(t, uint64(math.MaxUint64), u)
		for _, name := range []string{"umax", "overflow", "fraction", "exponent"} {
			n, err = p.Get(name).Int64()
			require.Error(t, err)
			require.Zero(t, n)
		}
		for _, name := range []string{"overflow", "negative", "fraction", "exponent"} {
			u, err = p.Get(name).Uint64()
			require.Error(t, err)
			require.Zero(t, u)
		}
		f, err := p.Get("exponent").Float64()
		require.NoError(t, err)
		require.Equal(t, float64(100), f)
		p, err = json.ParseFieldProbe([]byte(`{"huge":1e999}`))
		require.NoError(t, err)
		f, err = p.Get("huge").Float64()
		require.NoError(t, err)
		require.True(t, math.IsInf(f, 1))
	})

	t.Run("types arrays and capacity growth", func(t *testing.T) {
		p, err := json.ParseFieldProbe([]byte(`{"null":null,"false":false,"true":true,"empty":"","array":["a","b\u0063"],"badarray":["a",null]}`))
		require.NoError(t, err)
		_, err = p.Get("null").StringBytes()
		require.Error(t, err)
		_, err = p.Get("true").Int()
		require.Error(t, err)
		value, err := p.Get("false").Bool()
		require.NoError(t, err)
		require.False(t, value)
		value, err = p.Get("true").Bool()
		require.NoError(t, err)
		require.True(t, value)
		s, err := p.Get("empty").StringBytes()
		require.NoError(t, err)
		require.Empty(t, s)
		a, err := p.Get("array").StringArray()
		require.NoError(t, err)
		require.Equal(t, []string{"a", "bc"}, a)
		_, err = p.Get("badarray").StringArray()
		require.Error(t, err)
		p, err = json.ParseFieldProbe([]byte(`["one","two"]`))
		require.NoError(t, err)
		s, err = p.Get("1").StringBytes()
		require.NoError(t, err)
		require.Equal(t, "two", string(s))
		require.Nil(t, p.Get("-1"))
		require.Error(t, p.ForEachKey(func([]byte) {}))
	})

	t.Run("rejects invalid input including skipped values and trailing bytes", func(t *testing.T) {
		for _, src := range []string{
			`{"keys":[],"bad":[}`, `{"keys":[]} false`, `{"x":"\uZZZZ"}`,
			`{"x":NaN}`, `{"x":Inf}`, `{"x":01}`, `{"nested":{"x":1e}}`,
			"{\"x\":\"a\x01b\"}", "{\"x\":\"\xff\"}", `{"nested":{"x":"\uZZZZ"}}`,
		} {
			_, err := json.ParseFieldProbe([]byte(src))
			require.Error(t, err, src)
			_, err = json.HasField([]byte(src), "keys")
			require.Error(t, err, src)
		}
	})
}

func TestHasField(t *testing.T) {
	for _, tc := range []struct {
		src  string
		want bool
	}{
		{`{"keys":[]}`, true}, {`{"keys":null}`, true}, {`{"k\u0065ys":[]}`, true},
		{`{"keys":[],"keys":[]}`, true}, {`{"nested":{"keys":[]}}`, false},
		{`{"kty":"oct"}`, false}, {`["keys"]`, false}, {`null`, false},
	} {
		got, err := json.HasField([]byte(tc.src), "keys")
		require.NoError(t, err)
		require.Equal(t, tc.want, got, tc.src)
	}
}

func FuzzFieldProbe(f *testing.F) {
	for _, src := range []string{`{}`, `{"alg":"HS256","alg":"none"}`, `{"k\u0069d":"quote\""}`, `{"\u0061":{"x": }}`, `{"x":[1,{"a":true}]}`, `["one",1]`, `null`, `{"bad":`, "{\"x\":\"\xff\"}"} {
		f.Add([]byte(src))
	}
	f.Fuzz(func(t *testing.T, src []byte) {
		original := bytes.Clone(src)
		valid := jsontext.Value(src).IsValid(jsontext.AllowDuplicateNames(true))
		p, err := json.ParseFieldProbe(src)
		require.Equal(t, original, src)
		require.Equal(t, valid, err == nil)
		if err != nil {
			return
		}
		_ = p.ForEachKey(func(name []byte) {
			v := p.Get(string(name))
			require.NotNil(t, v)
			_, _ = v.StringBytes()
		})
		require.Equal(t, original, src)
	})
}
