package msgutil

import (
	"errors"

	"github.com/OguzhanE/saltyrtc-server-go/pkg/base"
	"github.com/OguzhanE/saltyrtc-server-go/pkg/crypto/nacl"
)

// IsValidYourCookieBytes ..
func IsValidYourCookieBytes(pk interface{}) bool {
	if pk == nil {
		return false
	}
	b, ok := pk.([]byte)
	if ok && len(b) == base.CookieLength {
		return true
	}
	return false
}

// ParseYourCookie ..
func ParseYourCookie(pk interface{}) ([]byte, error) {
	if !IsValidYourCookieBytes(pk) {
		return nil, errors.New("invalid your_cookie")
	}
	b, _ := pk.([]byte)
	return b, nil
}

// IsValidSubprotocols ..
func IsValidSubprotocols(subprotocols interface{}) bool {
	if subprotocols == nil {
		return false
	}
	_, ok := subprotocols.([]string)
	return ok
}

// ParseSubprotocols ..
func ParseSubprotocols(subprotocols interface{}) ([]string, error) {
	if !IsValidSubprotocols(subprotocols) {
		return nil, errors.New("invalid subprotocols")
	}
	val, _ := subprotocols.([]string)
	return val, nil
}

// IsValidPingInterval ..
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

// ParsePingInterval ..
func ParsePingInterval(pingInterval interface{}) (int, error) {
	if !IsValidPingInterval(pingInterval) {
		return 0, errors.New("invalid ping_interval")
	}
	val, _ := pingInterval.(int)
	return val, nil
}

// IsValidYourKey ..
func IsValidYourKey(yourKey interface{}) bool {
	return nacl.IsValidBoxPkBytes(yourKey)
}

// ParseYourKey ..
func ParseYourKey(yourKey interface{}) ([base.KeyBytesSize]byte, error) {
	yourKeyBytes, err := nacl.ConvertBoxPkToBytes(yourKey)
	if err != nil {
		var tmpArr [base.KeyBytesSize]byte
		return tmpArr, err
	}
	return nacl.CreateBoxPkFromBytes(yourKeyBytes)
}

// IsValidAddressId ..
func IsValidAddressId(id interface{}) bool {
	if id == nil {
		return false
	}
	_, ok := id.(base.AddressType)
	return ok
}

// ParseAddressId ..
func ParseAddressId(id interface{}) (base.AddressType, error) {
	if !IsValidAddressId(id) {
		return 0, errors.New("Invalid address id")
	}
	v, _ := id.(base.AddressType)
	return v, nil
}

// IsValidResponderAddressId ..
func IsValidResponderAddressId(id interface{}) bool {
	v, err := ParseAddressId(id)
	return err == nil && base.IsValidResponderAddressType(v)
}

// ParseResponderAddressId ..
func ParseResponderAddressId(id interface{}) (base.AddressType, error) {
	if !IsValidResponderAddressId(id) {
		return 0, errors.New("Invalid responder address id")
	}
	v, _ := id.(base.AddressType)
	return v, nil
}

// IsValidReasonCode ..
func IsValidReasonCode(reason interface{}) bool {
	if reason == nil {
		return false
	}
	v, ok := reason.(int)

	if ok &&
		v == base.CloseCodeGoingAway ||
		v == base.CloseCodeSubprotocolError ||
		(v >= base.CloseCodePathFullError && v <= base.CloseCodeInvalidKey) {
		return true
	}
	return false
}

// ParseReasonCode ..
func ParseReasonCode(reason interface{}) (int, error) {
	if !IsValidReasonCode(reason) {
		return 0, errors.New("Invalid reason code")
	}
	v, _ := reason.(int)
	return v, nil
}
