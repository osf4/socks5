package errio

import (
	"io"

	"github.com/joomcode/errorx"
)

type ErrReader struct {
	err error
	rd  io.Reader
}

// ErrReader is a wrapper for io.Reader.
//
// If a error was occured during the reading, Err != nil.
// Subsequent reading operations would return Err
func NewReader(rd io.Reader) *ErrReader {
	if erd, ok := rd.(*ErrReader); ok {
		return erd
	}

	return &ErrReader{
		rd: rd,
	}
}

func (r *ErrReader) Read(p []byte) (n int, err error) {
	if r.err != nil {
		return 0, r.err
	}

	n, r.err = r.rd.Read(p)
	return n, r.err
}

func (r *ErrReader) Error() error {
	return r.err
}

// Wrap calls t.Wrap() with r.Err
//
// If r.Err == nil, nil is returned
func (r *ErrReader) Wrap(t *errorx.Type, msg string, args ...interface{}) error {
	if r.err == nil {
		return nil
	}

	return t.Wrap(r.err, msg, args...)
}
