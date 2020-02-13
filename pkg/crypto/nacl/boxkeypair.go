package nacl

import (
	"bytes"
	"crypto/rand"

	"golang.org/x/crypto/nacl/box"
)

const (
	// NaclKeyBytesSize ..
	NaclKeyBytesSize = 32
)

// BoxKeyPair ..
type BoxKeyPair struct {
	Pk [NaclKeyBytesSize]byte
	Sk [NaclKeyBytesSize]byte
}

// NewBoxKeyPair ..
func NewBoxKeyPair(pk [NaclKeyBytesSize]byte, sk [NaclKeyBytesSize]byte) *BoxKeyPair {
	return &BoxKeyPair{
		Pk: pk,
		Sk: sk,
	}
}

// PkEqualTo ..
func (box *BoxKeyPair) PkEqualTo(target [NaclKeyBytesSize]byte) bool {
	return bytes.Equal(box.Pk[:], target[:])
}

// SkEqualTo ..
func (box *BoxKeyPair) SkEqualTo(target [NaclKeyBytesSize]byte) bool {
	return bytes.Equal(box.Sk[:], target[:])
}

// Clone ..
func (box *BoxKeyPair) Clone() *BoxKeyPair {
	return &BoxKeyPair{
		Pk: box.Pk,
		Sk: box.Sk,
	}
}

// GenerateBoxKeyPair ..
func GenerateBoxKeyPair() (*BoxKeyPair, error) {
	pk, sk, err := box.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return NewBoxKeyPair(*pk, *sk), nil
}
