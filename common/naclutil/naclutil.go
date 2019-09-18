package naclutil

import (
	"errors"

	"github.com/OguzhanE/saltyrtc-server-go/common"
)

func IsValidBoxPkBytes(pk interface{}) bool {
	if pk == nil {
		return false
	}
	b, ok := pk.([]byte)
	if ok && len(b) == common.KeyBytesSize {
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
