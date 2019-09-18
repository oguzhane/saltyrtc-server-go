package boxkeypair

import (
	"crypto/rand"

	"github.com/OguzhanE/saltyrtc-server-go/pkg/base"
	"golang.org/x/crypto/nacl/box"
)

type BoxKeyPair struct {
	Pk [base.KeyBytesSize]byte
	Sk [base.KeyBytesSize]byte
}

func NewBoxKeyPair(pk [base.KeyBytesSize]byte, sk [base.KeyBytesSize]byte) *BoxKeyPair {
	return &BoxKeyPair{
		Pk: pk,
		Sk: sk,
	}
}
func GenerateBoxKeyPair() (*BoxKeyPair, error) {
	pk, sk, err := box.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return NewBoxKeyPair(*pk, *sk), nil
}
