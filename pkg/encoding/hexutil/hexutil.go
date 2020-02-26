package hexutil

import (
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/OguzhanE/saltyrtc-server-go/pkg/base"
)

var (
	// ErrInvalidKeyLength ..
	ErrInvalidKeyLength = fmt.Errorf("invalid key length: key length must be:{%d}", base.KeyStringLength)
	// ErrInvalidPathLength ..
	ErrInvalidPathLength = fmt.Errorf("invalid path length: path length must be :{%d}", base.PathLength)
	// ErrInvalidPathChar ..
	ErrInvalidPathChar = fmt.Errorf("invalid path character: path characters should be valid hex char(0-f)")
	// ErrInvalidHexChar ..
	ErrInvalidHexChar = fmt.Errorf("invalid hex character: hex characters should be valid hex char(0-f)")
	// ErrOddHexLength ..
	ErrOddHexLength = fmt.Errorf("odd hex length: the length of the hex string should be even")
)

// IsValidHexKeyString validates key
func IsValidHexKeyString(key string) error {

	if len(key) != base.KeyStringLength {
		return ErrInvalidKeyLength
	}
	return IsValidHexString(key)
}

// IsValidHexPathString validates pathStr
func IsValidHexPathString(pathStr string) error {
	if len(pathStr) != base.PathLength {
		return ErrInvalidPathLength
	}
	err := IsValidHexString(pathStr)
	if err != nil {
		return ErrInvalidPathChar
	}
	return nil
}

// IsValidHexString validates s
func IsValidHexString(s string) error {
	if len(s)%2 == 1 {
		return ErrOddHexLength
	}
	for _, c := range s {
		isValid := (c >= 48 && c <= 57) || (c >= 65 && c <= 70) || (c >= 97 && c <= 102)
		if !isValid {
			return ErrInvalidHexChar
		}
	}
	return nil
}

// HexStringToBytes converts string to bytes
func HexStringToBytes(s string) ([]byte, error) {
	bytes, err := hex.DecodeString(s)
	return bytes, err
}

// HexStringToBytes32 converts string to [32]bytes
func HexStringToBytes32(s string) (*[32]byte, error) {
	bytes, err := hex.DecodeString(s)
	if err != nil || len(bytes) > 32 {
		return nil, err
	}
	if len(bytes) != 32 {
		return nil, errors.New("string length cannot be different than 32 bytes")
	}
	var bytesArr [32]byte
	copy(bytesArr[:], bytes[:32])
	return &bytesArr, nil
}
