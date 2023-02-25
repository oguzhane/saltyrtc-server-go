package protocol

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDecodePayload(t *testing.T) {
	require := require.New(t)

	want, bts := newTestPayload()
	var got testPayload

	err := DecodePayload(bts, &got)

	require.Nil(err)
	require.Equal(want.X, got.X)
	require.Equal(want.Y, got.Y)
	require.Equal(want.Z, got.Z)
	require.Equal(want.W, got.W)
}

func TestEncodePayload(t *testing.T) {
	require := require.New(t)
	payload, want := newTestPayload()

	encoded, err := EncodePayload(payload)

	require.Nil(err)
	require.Equal(want, encoded)
}

func TestEncryptPayload(t *testing.T) {
	require := require.New(t)

	payload, _ := newTestPayload()
	encodedPayload, _ := EncodePayload(payload)

	nonce := []byte{230, 19, 176, 164, 122, 60, 130, 80, 169, 131, 175, 219, 62, 234, 207, 178, 131, 172, 149, 129, 191, 101, 5, 16}
	want := []byte{0xc8, 0x57, 0x55, 0x43, 0x12, 0x53, 0xc5, 0x25, 0xfd, 0x2b, 0x24, 0x96, 0x9b, 0x77, 0xfc, 0x3b, 0xfe, 0xc2, 0xb0, 0x9c, 0xb7, 0x7a, 0xe6, 0x9a, 0xb, 0xfe, 0x67, 0xa1, 0x36, 0xd6, 0xc4, 0x89, 0xa, 0x8d, 0x4f, 0xfd, 0x69, 0xd, 0x87, 0x60}

	clientKey := [32]uint8{0x8, 0x4f, 0x29, 0xc5, 0xc1, 0xde, 0x47, 0x92, 0x68, 0x5f, 0xf4, 0xdd, 0xf9, 0xc9, 0xc6, 0x42, 0x6b, 0x65, 0x64, 0x84, 0x4d, 0x87, 0x5a, 0x3a, 0x6, 0x9b, 0xfa, 0x7c, 0xbb, 0x82, 0x3f, 0x60}
	serverSessionSk := [32]uint8{0x2e, 0x0, 0xa, 0xf8, 0xba, 0x38, 0x57, 0xa4, 0x74, 0xbe, 0xaa, 0xbc, 0x9c, 0x43, 0x7d, 0x7b, 0x6c, 0xaa, 0xcf, 0x7f, 0xd, 0xd7, 0x8e, 0x68, 0x1a, 0x83, 0x40, 0x24, 0x73, 0xa8, 0x1, 0x85}

	got, err := EncryptPayload(clientKey, serverSessionSk, nonce, encodedPayload)

	require.Nil(err)
	require.Equal(want, got)
}

func TestSignKeys(t *testing.T) {
	require := require.New(t)

	clientKey := [32]uint8{0x8, 0x4f, 0x29, 0xc5, 0xc1, 0xde, 0x47, 0x92, 0x68, 0x5f, 0xf4, 0xdd, 0xf9, 0xc9, 0xc6, 0x42, 0x6b, 0x65, 0x64, 0x84, 0x4d, 0x87, 0x5a, 0x3a, 0x6, 0x9b, 0xfa, 0x7c, 0xbb, 0x82, 0x3f, 0x60}
	serverSessionPk := [32]uint8{0x62, 0x88, 0x55, 0x22, 0x5d, 0xdd, 0x88, 0xeb, 0x4d, 0xf0, 0x6f, 0xed, 0x6a, 0x2f, 0x7, 0xa7, 0x5b, 0xb2, 0x2, 0x49, 0xb2, 0x8f, 0x53, 0xcd, 0x63, 0x40, 0xdf, 0xff, 0x88, 0xb9, 0x0, 0x20}
	serverPermanentSk := [32]uint8{0x2e, 0x0, 0xa, 0xf8, 0xba, 0x38, 0x57, 0xa4, 0x74, 0xbe, 0xaa, 0xbc, 0x9c, 0x43, 0x7d, 0x7b, 0x6c, 0xaa, 0xcf, 0x7f, 0xd, 0xd7, 0x8e, 0x68, 0x1a, 0x83, 0x40, 0x24, 0x73, 0xa8, 0x1, 0x85}
	nonce := []byte{230, 19, 176, 164, 122, 60, 130, 80, 169, 131, 175, 219, 62, 234, 207, 178, 131, 172, 149, 129, 191, 101, 5, 16}
	want := []byte{0x3c, 0x3e, 0x3f, 0x39, 0x8f, 0x91, 0x89, 0x35, 0x1f, 0xf6, 0x24, 0xc5, 0x93, 0x13, 0x65, 0x69, 0x18, 0xeb, 0xb2, 0x2d, 0xfb, 0xb5, 0x7d, 0xd0, 0x1e, 0xaa, 0x7c, 0x29, 0x2f, 0x8d, 0x62, 0x77, 0x95, 0x3c, 0x4c, 0xb6, 0xd8, 0x23, 0x8e, 0x6e, 0xa6, 0xf2, 0x78, 0xab, 0x79, 0xcc, 0x66, 0x45, 0xb4, 0x14, 0x5, 0xd3, 0xfd, 0x71, 0xd4, 0xfe, 0x94, 0xdd, 0x9d, 0x55, 0x4a, 0x35, 0x37, 0x6f, 0x5a, 0xe2, 0x5b, 0xb2, 0x2, 0x42, 0xe3, 0x8e, 0xb2, 0xcc, 0xc0, 0x3e, 0x49, 0xcf, 0xa4, 0xb}

	got := SignKeys(clientKey, serverSessionPk, serverPermanentSk, nonce)
	require.Equal(want, got)
}

type testPayload struct {
	X string   `codec:"X"`
	Y []byte   `codec:"Y"`
	Z bool     `codec:"Z"`
	W []uint16 `codec:"W"`
}

func newTestPayload() (payload testPayload, bts []byte) {
	payload = testPayload{
		X: "test",
		Y: []byte{0x01, 0x02, 0x03},
		Z: true,
		W: []uint16{0x11, 0x12, 0x13},
	}
	bts = []byte{
		0x84, 0xa1, 0x57, 0x93, 0x11, 0x12,
		0x13, 0xa1, 0x58, 0xa4, 0x74, 0x65,
		0x73, 0x74, 0xa1, 0x59, 0xc4, 0x3,
		0x1, 0x2, 0x3, 0xa1, 0x5a, 0xc3,
	}
	return
}