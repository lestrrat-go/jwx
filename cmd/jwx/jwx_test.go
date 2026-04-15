package main

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestGetOutput(t *testing.T) {
	t.Run("truncates existing file", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "out")
		stale := bytes.Repeat([]byte{0xFF}, 100)
		require.NoError(t, os.WriteFile(path, stale, 0600))

		w, err := getOutput(path)
		require.NoError(t, err)
		_, err = w.Write([]byte("abc"))
		require.NoError(t, err)
		require.NoError(t, w.Close())

		got, err := os.ReadFile(path)
		require.NoError(t, err)
		require.Equal(t, []byte("abc"), got, "tail bytes from the previous write must not survive")
	})

	t.Run("creates file with 0600 mode", func(t *testing.T) {
		if runtime.GOOS == "windows" {
			t.Skip("windows file modes only honor the write bit")
		}
		path := filepath.Join(t.TempDir(), "fresh")
		w, err := getOutput(path)
		require.NoError(t, err)
		require.NoError(t, w.Close())

		info, err := os.Stat(path)
		require.NoError(t, err)
		require.Equal(t, os.FileMode(0600), info.Mode().Perm())
	})
}
