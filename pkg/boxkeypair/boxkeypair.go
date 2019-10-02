package boxkeypair

import (
	"bytes"
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

func (box *BoxKeyPair) PkEqualTo(target [base.KeyBytesSize]byte) bool {
	return bytes.Equal(box.Pk[:], target[:])
}

func (box *BoxKeyPair) SkEqualTo(target [base.KeyBytesSize]byte) bool {
	return bytes.Equal(box.Sk[:], target[:])
}

func (box *BoxKeyPair) Clone() *BoxKeyPair {
	return &BoxKeyPair{
		Pk: box.Pk,
		Sk: box.Sk,
	}
}

func GenerateBoxKeyPair() (*BoxKeyPair, error) {
	pk, sk, err := box.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return NewBoxKeyPair(*pk, *sk), nil
}
