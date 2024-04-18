package encrypt

import (
	"io"
	"os"
)

const Size = 16

// Files smaller than this will be hashed in their entirety.
const SampleThreshold = 128 * 1024
const SampleSize = 16 * 1024

var emptyArray = [Size]byte{}

type Encrypt struct{}

func NewEncrypt() *Encrypt {
	return &Encrypt{}
}

// .
func (enc *Encrypt) ReadFile(filename string) ([Size]byte, error) {
	f, err := os.Open(filename)
	defer f.Close()

	if err != nil {
		return emptyArray, err
	}

	fi, err := f.Stat()
	if err != nil {
		return emptyArray, err
	}
	_ = io.NewSectionReader(f, 0, fi.Size())
	return emptyArray, err
}
