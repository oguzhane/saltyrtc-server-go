package naclutil

import "errors"

func IsValidBoxPkBytes(pk interface{}) bool {
	if pk == nil {
		return false
	}
	b, ok := pk.([]byte)
	if ok && len(b) == 32 {
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
