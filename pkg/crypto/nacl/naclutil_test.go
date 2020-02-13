package nacl

import (
	"reflect"
	"testing"
)

func TestIsValidBoxPkBytes(t *testing.T) {
	tests := []struct {
		input  interface{}
		output bool
	}{
		{nil, false},
		{"aa", false},
		{4, false},
		{[]byte("16ead08196a9504c5a8a59ada8250057"), true},
	}
	for _, tt := range tests {
		result := IsValidBoxPkBytes(tt.input)
		if result != tt.output {
			t.Fail()
		}
	}
}

func TestConvertBoxPkToBytes(t *testing.T) {
	tests := []struct {
		input  interface{}
		output interface{}
	}{
		{nil, false},
		{"aa", false},
		{4, false},
		{[]byte("16ead08196a9504c5a8a59ada8250057"), []byte("16ead08196a9504c5a8a59ada8250057")},
	}
	for _, tt := range tests {
		bytes, err := ConvertBoxPkToBytes(tt.input)
		if isValid := err == nil; !reflect.DeepEqual(bytes, tt.output) && isValid != tt.output {
			t.Fail()
		}
	}
}

func TestCreateBoxPkFromBytes(t *testing.T) {
	tests := []struct {
		input  []byte
		output interface{}
	}{
		{[]byte(""), false},
		{[]byte("ea08"), false},
		{[]byte("16ead08196a9504c5a8a59ada8250057"), [32]byte{49, 54, 101, 97, 100, 48, 56, 49, 57, 54, 97, 57, 53, 48, 52, 99, 53, 97, 56, 97, 53, 57, 97, 100, 97, 56, 50, 53, 48, 48, 53, 55}},
	}
	for _, tt := range tests {
		bytes, err := CreateBoxPkFromBytes(tt.input)
		if isValid := err == nil; bytes != tt.output && isValid != tt.output {
			t.Fail()
		}
	}
}
