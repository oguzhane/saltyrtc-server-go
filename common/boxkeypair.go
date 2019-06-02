package common

import (
	"crypto/rand"

	"golang.org/x/crypto/nacl/box"
)

type BoxKeyPair struct {
	Pk [KeyBytesSize]byte
	Sk [KeyBytesSize]byte
}

func NewBoxKeyPair(pk [KeyBytesSize]byte, sk [KeyBytesSize]byte) *BoxKeyPair {
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
