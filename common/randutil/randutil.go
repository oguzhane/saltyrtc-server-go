package randutil


import (
	"crypto/rand"
	"encoding/binary"
)


func RandUint16() (uint16, error) {
	b := make([]byte, 2)
	_, err := rand.Read(b)
	if err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint16(b), nil
}

func RandUint32() (uint32, error) {
	b := make([]byte, 4)
	_, err := rand.Read(b)
	if err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint32(b), nil
}

func RandUint64() (uint64, error) {
	b := make([]byte, 8)
	_, err := rand.Read(b)
	if err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint64(b), nil
}


func RandBytes(bytesSize int) ([]byte, error) {
	b := make([]byte, bytesSize)
	_, err := rand.Read(b)
	return b, err
}