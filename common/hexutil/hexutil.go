package hexutil

import (
	"encoding/hex"
	"fmt"
	"errors"
	"github.com/oguzhane/saltyrtc-server-go/common"
)

// IsValidHexKeyString validates key
func IsValidHexKeyString(key string) error {

	if len(key) != common.KeyStringLength {
		return common.NewValueError(fmt.Sprintf("invalid key length. Key length must be:{%d}", common.KeyStringLength))
	}
	return IsValidHexString(key)
}

// IsValidHexPathString validates pathStr
func IsValidHexPathString(pathStr string) error {
	if len(pathStr) != common.PathLength {
		return common.NewPathError(fmt.Sprintf("invalid path length. Path length must be :{%d}", common.PathLength))
	}
	err := IsValidHexString(pathStr)
	if err != nil {
		return common.NewPathError("Path characters should be valid hex char(0-f)")
	}
	return nil
}

// IsValidHexString validates s
func IsValidHexString(s string) error {
	for _, c := range s {
		isValid := (c >= 48 && c <= 57) || (c >= 65 && c <= 70) || (c >= 97 && c <= 102)
		if !isValid {
			return common.NewValueError("invalid hex string")
		}
	}
	return nil
}

// HexStringToBytes converts string to bytes
func HexStringToBytes(s string) ([]byte, error) {
	bytes, err := hex.DecodeString(s)
	return bytes, err
}

func HexStringToBytes32(s string) (*[32]byte, error) {
	bytes, err := hex.DecodeString(s)
	if(err != nil || len(bytes) > 32){
		return nil, err
	}
	if len(bytes) != 32 {
		return nil, errors.New("string cannot be different than 32 bytes")
	}
	var bytesArr [32]byte
	copy(bytesArr[:], bytes[:32])
	return &bytesArr, nil
}