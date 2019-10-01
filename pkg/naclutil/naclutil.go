package naclutil

import (
	"errors"

	"github.com/OguzhanE/saltyrtc-server-go/pkg/base"
)

func IsValidBoxPkBytes(pk interface{}) bool {
	if pk == nil {
		return false
	}
	b, ok := pk.([]byte)
	if ok && len(b) == base.KeyBytesSize {
		return true
	}
	return false
}

func ConvertBoxPkToBytes(pk interface{}) ([]byte, error) {
	if !IsValidBoxPkBytes(pk) {
		return nil, errors.New("invalid BoxPk")
	}
	b, _ := pk.([]byte)
	return b, nil
}

func CreateBoxPkFromBytes(pk []byte) ([base.KeyBytesSize]byte, error) {
	var pkArr [base.KeyBytesSize]byte
	if !IsValidBoxPkBytes(pk) {
		return pkArr, errors.New("invalid BoxPk")
	}
	copy(pkArr[:], pk[:base.KeyBytesSize])
	return pkArr, nil
}
