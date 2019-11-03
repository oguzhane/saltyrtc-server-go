package boxkeypair

import (
	"crypto/rand"
	"testing"

	"golang.org/x/crypto/nacl/box"
)

func TestEqualTo(t *testing.T) {
	for i := 0; i < 5; i++ {
		pk, sk, _ := box.GenerateKey(rand.Reader)
		keyPair := NewBoxKeyPair(*pk, *sk)
		if !keyPair.PkEqualTo(*pk) || !keyPair.SkEqualTo(*sk) {
			t.Fatalf("bad:\nPk:\n%x\nSk:\n%x", pk, sk)
		}
	}
}

func TestClone(t *testing.T) {
	pk, sk, _ := box.GenerateKey(rand.Reader)
	keyPair := NewBoxKeyPair(*pk, *sk)

	cloneKeyPair := keyPair.Clone()
	if cloneKeyPair == keyPair {
		t.Fail()
	}
}

func TestGenerateBoxKeyPair(t *testing.T) {
	keyPair, err := GenerateBoxKeyPair()
	if err != nil || keyPair == nil {
		t.Fail()
	}
}
