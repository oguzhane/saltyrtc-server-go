package protocol

import (
	"errors"

	"github.com/OguzhanE/saltyrtc-server-go/pkg/crypto/nacl"
)

// IsValidYourCookieBytes checks if given pk is valid. length of pk must be equal to 16(CookieLength)
func IsValidYourCookieBytes(pk interface{}) bool {
	if pk == nil {
		return false
	}
	b, ok := pk.([]byte)
	if ok && len(b) == CookieLength {
		return true
	}
	return false
}

// ParseYourCookie parses given pk to your_cookie in bytes
func ParseYourCookie(pk interface{}) ([]byte, error) {
	if !IsValidYourCookieBytes(pk) {
		return nil, errors.New("invalid your_cookie")
	}
	b, _ := pk.([]byte)
	return b, nil
}

// IsValidSubprotocols checks if given subprotocols is valid. it must be type of []string
func IsValidSubprotocols(subprotocols interface{}) bool {
	if subprotocols == nil {
		return false
	}
	_, ok := subprotocols.([]string)
	return ok
}

// ParseSubprotocols parses given subprotocols to subprotocols as type of []string
func ParseSubprotocols(subprotocols interface{}) ([]string, error) {
	if !IsValidSubprotocols(subprotocols) {
		return nil, errors.New("invalid subprotocols")
	}
	val, _ := subprotocols.([]string)
	return val, nil
}

// IsValidPingInterval checks if given pingInterval is valid. it must be type of int and higher than 0
func IsValidPingInterval(pingInterval interface{}) bool {
	if pingInterval == nil {
		return false
	}
	v, ok := pingInterval.(int)
	if ok && v >= 0 {
		return true
	}
	return false
}

// ParsePingInterval parses given pingInterval as type of int
func ParsePingInterval(pingInterval interface{}) (int, error) {
	if !IsValidPingInterval(pingInterval) {
		return 0, errors.New("invalid ping_interval")
	}
	val, _ := pingInterval.(int)
	return val, nil
}

// IsValidYourKey checks if given yourKey is valid. It must be a valid public key of nacl box
func IsValidYourKey(yourKey interface{}) bool {
	return nacl.IsValidBoxPkBytes(yourKey)
}

// ParseYourKey parses yourKey. It creates nacl box public key in bytes
func ParseYourKey(yourKey interface{}) ([KeyBytesSize]byte, error) {
	yourKeyBytes, err := nacl.ConvertBoxPkToBytes(yourKey)
	if err != nil {
		var tmpArr [KeyBytesSize]byte
		return tmpArr, err
	}
	return nacl.CreateBoxPkFromBytes(yourKeyBytes)
}

// IsValidAddressID checks whether id is a valid address
func IsValidAddressID(id interface{}) bool {
	if id == nil {
		return false
	}
	_, ok := id.(AddressType)
	return ok
}

// ParseAddressID parses id to address of type
func ParseAddressID(id interface{}) (AddressType, error) {
	if !IsValidAddressID(id) {
		return 0, errors.New("invalid address id")
	}
	v, _ := id.(AddressType)
	return v, nil
}

// IsValidResponderAddressID returns true if id is a valid responder address
func IsValidResponderAddressID(id interface{}) bool {
	v, err := ParseAddressID(id)
	return err == nil && IsValidResponderAddressType(v)
}

// ParseResponderAddressID parses id as address of type
func ParseResponderAddressID(id interface{}) (AddressType, error) {
	if !IsValidResponderAddressID(id) {
		return 0, errors.New("invalid responder address id")
	}
	v, _ := id.(AddressType)
	return v, nil
}

// IsValidReasonCode checks if given reason valid
func IsValidReasonCode(reason interface{}) bool {
	if reason == nil {
		return false
	}
	v, ok := reason.(int)

	if ok &&
		v == CloseCodeGoingAway ||
		v == CloseCodeSubprotocolError ||
		(v >= CloseCodePathFullError && v <= CloseCodeInvalidKey) {
		return true
	}
	return false
}

// ParseReasonCode parses given reason as type of int
func ParseReasonCode(reason interface{}) (int, error) {
	if !IsValidReasonCode(reason) {
		return 0, errors.New("invalid reason code")
	}
	v, _ := reason.(int)
	return v, nil
}
