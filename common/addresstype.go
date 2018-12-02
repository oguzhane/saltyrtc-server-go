package common

type AddressType = uint8

const (
	Server    AddressType = 0x00
	Initiator AddressType = 0x01
	Responder AddressType = 0xff
)

func GetAddressTypeFromaAddr(addr AddressType) AddressType {
	if addr > 0x01 {
		return Responder
	}
	if addr == 0x01 {
		return Initiator
	}
	return Server
}

func IsValidResponderAddressType(addr AddressType) bool {
	if addr > 0x01 && addr <= 0xff {
		return true
	}
	return false
}
