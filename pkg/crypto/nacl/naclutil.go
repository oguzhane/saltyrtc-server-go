package nacl

import (
	"errors"
)

// IsValidBoxPkBytes ..
func IsValidBoxPkBytes(pk interface{}) bool {
	if pk == nil {
		return false
	}
	b, ok := pk.([]byte)
	if ok && len(b) == NaclKeyBytesSize {
		return true
	}
	return false
}

// ConvertBoxPkToBytes ..
func ConvertBoxPkToBytes(pk interface{}) ([]byte, error) {
	if !IsValidBoxPkBytes(pk) {
		return nil, errors.New("invalid BoxPk")
	}
	b, _ := pk.([]byte)
	return b, nil
}

// CreateBoxPkFromBytes ..
func CreateBoxPkFromBytes(pk []byte) ([NaclKeyBytesSize]byte, error) {
	var pkArr [NaclKeyBytesSize]byte
	if !IsValidBoxPkBytes(pk) {
		return pkArr, errors.New("invalid BoxPk")
	}
	copy(pkArr[:], pk[:NaclKeyBytesSize])
	return pkArr, nil
}
