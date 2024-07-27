package jwe

import (
	"bytes"
	"compress/flate"
	"io"

	"github.com/lestrrat-go/jwx/internal/pool"
	"github.com/lestrrat-go/jwx/jwa"
	"github.com/pkg/errors"
)

func uncompress(src []byte, maxBufferSize int64) ([]byte, error) {
	var dst bytes.Buffer
	r := flate.NewReader(bytes.NewReader(src))
	defer r.Close()
	var buf [16384]byte
	var sofar int64
	for {
		n, readErr := r.Read(buf[:])
		sofar += int64(n)
		if sofar > maxBufferSize {
			return nil, errors.New(`compressed payload exceeds maximum allowed size`)
		}
		if readErr != nil {
			// if we have a read error, and it's not EOF, then we need to stop
			if readErr != io.EOF {
				return nil, errors.Wrap(readErr, `failed to read inflated data`)
			}
		}

		if _, err := dst.Write(buf[:n]); err != nil {
			return nil, errors.Wrap(err, `failed to write inflated data`)
		}

		if readErr != nil {
			// if it got here, then readErr == io.EOF, we're done
			return dst.Bytes(), nil
		}
	}
}

func compress(plaintext []byte, alg jwa.CompressionAlgorithm) ([]byte, error) {
	if alg == jwa.NoCompress {
		return plaintext, nil
	}

	buf := pool.GetBytesBuffer()
	defer pool.ReleaseBytesBuffer(buf)

	w, _ := flate.NewWriter(buf, 1)
	in := plaintext
	for len(in) > 0 {
		n, err := w.Write(in)
		if err != nil {
			return nil, errors.Wrap(err, `failed to write to compression writer`)
		}
		in = in[n:]
	}
	if err := w.Close(); err != nil {
		return nil, errors.Wrap(err, "failed to close compression writer")
	}

	ret := make([]byte, buf.Len())
	copy(ret, buf.Bytes())
	return ret, nil
}
