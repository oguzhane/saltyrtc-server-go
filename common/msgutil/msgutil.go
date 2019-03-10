package msgutil

import "errors"
import "github.com/oguzhane/saltyrtc-server-go/common/naclutil"

func IsValidYourCookieBytes(pk interface{}) bool {
	if pk == nil {
		return false
	}
	b, ok := pk.([]byte)
	if ok && len(b) == 16 {
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
