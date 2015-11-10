// Package padbuf implements a simple buffer that knows how to pad/unpad
// itself so that the buffer size aligns with an arbitrary block size.
package padbuf

import (
	"bytes"
	"errors"
)

type PadBuffer []byte

func (pb PadBuffer) Len() int {
	return len(pb)
}

func (pb PadBuffer) Pad(n int) PadBuffer {
	rem := n - pb.Len() % n
	if rem == 0 {
		return pb
	}

	newpb := pb.Resize(pb.Len() + rem)
	copy(newpb[pb.Len():], bytes.Repeat([]byte{byte(rem)}, rem))
	return newpb
}

func (pb PadBuffer) Resize(newlen int) PadBuffer {
	if pb.Len() == newlen {
		return pb
	}

	buf := make([]byte, newlen)
	copy(buf, pb)
	return PadBuffer(buf)
}

func (pb PadBuffer) Unpad(n int) (PadBuffer, error) {
	rem := pb.Len() % n
	if rem != 0 {
		return pb, errors.New("buffer should be multiple block size")
	}

	last := pb[pb.Len()-1]
	pad := bytes.Repeat([]byte{last}, int(last))
	if !bytes.HasSuffix(pb, pad) {
		return pb, errors.New("invalid padding")
	}

	return PadBuffer(pb[:pb.Len()-int(last)]), nil
}