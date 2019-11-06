package hexutil

import (
	"reflect"
	"testing"
)

func TestIsValidHexKeyString(t *testing.T) {
	tests := []struct {
		input  string
		output bool
	}{
		{"", false},
		{"a", false},
		{"f72aadb4b5e303845ec20ab1fe4e463ce4909eef8145d9002bfd568ff3af5279", true},
		{"g72aadb4b5e303845ec20ab1fe4e463ce4909eef8145d9002bfd568ff3af5279", false},
		{"f72aadb4b5e303845ec20ab1fe4e463ce4909eef8145d9002bfd568ff3af5279a", false},
	}
	for _, tt := range tests {
		err := IsValidHexKeyString(tt.input)
		if isValid := err == nil; isValid != tt.output {
			t.Fail()
		}
	}
}

func TestIsValidHexPathString(t *testing.T) {
	tests := []struct {
		input  string
		output bool
	}{
		{"", false},
		{"a", false},
		{"f72aadb4b5e303845ec20ab1fe4e463ce4909eef8145d9002bfd568ff3af5279", true},
		{"g72aadb4b5e303845ec20ab1fe4e463ce4909eef8145d9002bfd568ff3af5279", false},
		{"f72aadb4b5e303845ec20ab1fe4e463ce4909eef8145d9002bfd568ff3af5279a", false},
	}
	for _, tt := range tests {
		err := IsValidHexPathString(tt.input)
		if isValid := err == nil; isValid != tt.output {
			t.Fail()
		}
	}
}

func TestIsValidHexString(t *testing.T) {
	tests := []struct {
		input  string
		output bool
	}{
		{"", true},
		{"a", false},
		{"f72aadb4b5e303845ec20ab1fe4e463ce4909eef8145d9002bfd568ff3af5279", true},
		{"g72aadb4b5e303845ec20ab1fe4e463ce4909eef8145d9002bfd568ff3af5279", false},
	}

	for _, tt := range tests {
		err := IsValidHexString(tt.input)
		if isValid := err == nil; isValid != tt.output {
			t.Fail()
		}
	}
}

func TestHexStringToBytes(t *testing.T) {
	tests := []struct {
		input  string
		output interface{}
	}{
		{"", []byte{}},
		{"aa", []byte{170}},
		{"aaa", false},
		{"gg", false},
		{"f72aadb4b5e303845ec20ab1fe4e463ce4909eef8145d9002bfd568ff3af5279", []byte{247, 42, 173, 180, 181, 227, 3, 132, 94, 194, 10, 177, 254, 78, 70, 60, 228, 144, 158, 239, 129, 69, 217, 0, 43, 253, 86, 143, 243, 175, 82, 121}},
	}

	for ii, tt := range tests {
		bytes, err := HexStringToBytes(tt.input)
		if isValid := err == nil; !reflect.DeepEqual(bytes, tt.output) && isValid != tt.output {
			t.Log(ii)
			t.Fatal()
		}
	}
}

func TestHexStringToBytes32(t *testing.T) {
	tests := []struct {
		input  string
		output interface{}
	}{
		{"", false},
		{"aa", false},
		{"aa", false},
		{"aaa", false},
		{"gg", false},
		{"f72aadb4b5e303845ec20ab1fe4e463ce4909eef8145d9002bfd568ff3af5279", [32]byte{247, 42, 173, 180, 181, 227, 3, 132, 94, 194, 10, 177, 254, 78, 70, 60, 228, 144, 158, 239, 129, 69, 217, 0, 43, 253, 86, 143, 243, 175, 82, 121}},
	}

	for ii, tt := range tests {
		bytes, err := HexStringToBytes32(tt.input)
		t.Logf("%v\n", bytes)
		if isValid := err == nil; *bytes != tt.output && isValid != tt.output {
			t.Log(ii)
			t.Fatal()
		}
	}
}
