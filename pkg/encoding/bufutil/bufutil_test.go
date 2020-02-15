package bufutil

import (
	"fmt"
	"testing"
)

func TestUint16ToBytes(t *testing.T) {
	var num uint16 = 16
	bytes := BigEndian.Uint16ToBytes(num)
	bytesHex := fmt.Sprintf("%x", bytes)
	numHex := fmt.Sprintf("%04x", num)
	if bytesHex != numHex {
		t.Fatalf("expected %s but got %s", numHex, bytesHex)
	}
}

func TestUint32ToBytes(t *testing.T) {
	var num uint32 = 32
	bytes := BigEndian.Uint32ToBytes(num)
	bytesHex := fmt.Sprintf("%x", bytes)
	numHex := fmt.Sprintf("%08x", num)
	if bytesHex != numHex {
		t.Fatalf("expected %s but got %s", numHex, bytesHex)
	}
}

func TestUint64ToBytes(t *testing.T) {
	var num uint64 = 64
	bytes := BigEndian.Uint64ToBytes(num)
	bytesHex := fmt.Sprintf("%x", bytes)
	numHex := fmt.Sprintf("%016x", num)
	if bytesHex != numHex {
		t.Fatalf("expected %s but got %s", numHex, bytesHex)
	}
}
