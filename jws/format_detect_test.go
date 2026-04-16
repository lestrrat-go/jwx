package jws

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDetectParseFormat(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		src  []byte
		want int
	}{
		{
			name: "space then BOM then JSON stays compact",
			src:  []byte(" \uFEFF{\"payload\":\"x\"}"),
			want: fmtCompact,
		},
		{
			name: "leading unicode whitespace then JSON",
			src:  []byte("\u3000{\"payload\":\"x\"}"),
			want: fmtJSON,
		},
		{
			name: "leading unicode whitespace then compact",
			src:  []byte("\u3000eyJhbGciOiJIUzI1NiJ9"),
			want: fmtCompact,
		},
		{
			name: "empty input",
			want: 0,
		},
		{
			name: "all whitespace input",
			src:  []byte("\t\r\n "),
			want: 0,
		},
		{
			name: "unicode whitespace only",
			src:  []byte("\u3000"),
			want: 0,
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			require.Equal(t, tc.want, detectParseFormat(tc.src))
		})
	}
}
