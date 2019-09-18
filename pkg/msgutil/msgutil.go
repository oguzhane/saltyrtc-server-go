package msgutil

import (
	"errors"

	"github.com/OguzhanE/saltyrtc-server-go/pkg/base"
	"github.com/OguzhanE/saltyrtc-server-go/pkg/naclutil"
)

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

func ParseYourCookie(pk interface{}) ([]byte, error) {
	if !IsValidYourCookieBytes(pk) {
		return nil, errors.New("invalid your_cookie")
	}
	b, _ := pk.([]byte)
	return b, nil
}

func IsValidSubprotocols(subprotocols interface{}) bool {
	if subprotocols == nil {
		return false
	}
	_, ok := subprotocols.([]string)
	return ok
}

func ParseSubprotocols(subprotocols interface{}) ([]string, error) {
	if !IsValidSubprotocols(subprotocols) {
		return nil, errors.New("invalid subprotocols")
	}
	val, _ := subprotocols.([]string)
	return val, nil
}

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

func ParsePingInterval(pingInterval interface{}) (int, error) {
	if !IsValidPingInterval(pingInterval) {
		return 0, errors.New("invalid ping_interval")
	}
	val, _ := pingInterval.(int)
	return val, nil
}

func IsValidYourKey(yourKey interface{}) bool {
	return naclutil.IsValidBoxPkBytes(yourKey)
}

func ParseYourKey(yourKey interface{}) ([]byte, error) {
	return naclutil.ConvertBoxPkToBytes(yourKey)
}

func IsValidAddressId(id interface{}) bool {
	if id == nil {
		return false
	}
	_, ok := id.(base.AddressType)
	return ok
}

func ParseAddressId(id interface{}) (base.AddressType, error) {
	if !IsValidAddressId(id) {
		return 0, errors.New("Invalid address id")
	}
	v, _ := id.(base.AddressType)
	return v, nil
}

func IsValidResponderAddressId(id interface{}) bool {
	v, err := ParseAddressId(id)
	return err == nil && base.IsValidResponderAddressType(v)
}

func ParseResponderAddressId(id interface{}) (base.AddressType, error) {
	if !IsValidResponderAddressId(id) {
		return 0, errors.New("Invalid responder address id")
	}
	v, _ := id.(base.AddressType)
	return v, nil
}

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

func ParseReasonCode(reason interface{}) (int, error) {
	if !IsValidReasonCode(reason) {
		return 0, errors.New("Invalid reason code")
	}
	v, _ := reason.(int)
	return v, nil
}
