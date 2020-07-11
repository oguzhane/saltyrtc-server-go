package protocol

// AddressType represents type of address
type AddressType = uint8

const (
	// Server represents address identifier for a Server
	Server AddressType = 0x00
	// Initiator represents address identifier for a Initiator
	Initiator AddressType = 0x01
	// Responder represents address identifier for a Responder
	Responder AddressType = 0xff
)

// GetAddressTypeFromAddr parses type of addr
func GetAddressTypeFromAddr(addr AddressType) AddressType {
	if addr > 0x01 {
		return Responder
	}
	if addr == 0x01 {
		return Initiator
	}
	return Server
}

// IsValidResponderAddressType checks if addr is valid address
func IsValidResponderAddressType(addr AddressType) bool {
	if addr > 0x01 && addr <= 0xff {
		return true
	}
	return false
}
