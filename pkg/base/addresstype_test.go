package base

import (
	"testing"
)

func TestGetAddressTypeFromAddr(t *testing.T) {
	tests := []struct {
		input  AddressType
		output AddressType
	}{
		{0x00, Server},
		{0x01, Initiator},
		{0x02, Responder},
		{0xEE, Responder},
		{0xFE, Responder},
		{0xFF, Responder},
	}
	for _, tt := range tests {
		out := GetAddressTypeFromAddr(tt.input)
		if out != tt.output {
			t.Fatalf("bad:\nInput:\n%+v\nOutput:\n%#v\nExpected output:\n%#v", tt.input, out, tt.output)
		}
	}
}

func TestIsValidResponderAddressType(t *testing.T) {
	tests := []struct {
		input  AddressType
		output bool
	}{
		{0x00, false},
		{0x01, false},
		{0x02, true},
		{0xEE, true},
		{0xFE, true},
		{0xFF, true},
	}

	for _, tt := range tests {
		out := IsValidResponderAddressType(tt.input)
		if out != tt.output {
			t.Fatalf("bad:\nInput:\n%+v\nOutput:\n%#v\nExpected output:\n%#v", tt.input, out, tt.output)
		}
	}
}
