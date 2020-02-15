package core

import (
	"bufio"
	"bytes"
	"fmt"

	"github.com/OguzhanE/saltyrtc-server-go/pkg/base"

	"github.com/OguzhanE/saltyrtc-server-go/pkg/crypto/nacl"
	"github.com/OguzhanE/saltyrtc-server-go/pkg/msgutil"

	"golang.org/x/crypto/nacl/box"
)

// RawDataUnpacker ..
type RawDataUnpacker func(data []byte) (RawData, error)

// NonceReader ..
type NonceReader func() ([]byte, error)

// RawData ..
type RawData struct {
	Nonce   []byte
	Cookie  []byte
	Source  base.AddressType
	Dest    base.AddressType
	Csn     []byte
	Payload []byte
}

// UnpackRaw ..
func UnpackRaw(data []byte) (RawData, error) {
	if len(data) < base.DataLengthMin {
		return RawData{}, ErrMessageTooShort
	}
	nonce := data[:base.NonceLength]
	cookie := nonce[:base.CookieLength]
	var source base.AddressType = nonce[base.CookieLength:base.SourceUpperBound][0]
	var dest base.AddressType = nonce[base.SourceUpperBound:base.DestinationUpperBound][0]
	csn := nonce[base.DestinationUpperBound:base.CsnUpperBound]
	payload := data[base.NonceLength:]
	return RawData{
		Nonce:   nonce,
		Cookie:  cookie,
		Source:  source,
		Dest:    dest,
		Csn:     csn,
		Payload: payload,
	}, nil
}

// Pack encodes message and returns bytes data
func Pack(client *Client, src base.AddressType, dest base.AddressType,
	payloadPacker PayloadPacker) ([]byte, error) {
	if client.CombinedSequenceNumberOut.HasErrOverflowSentinel() {
		return nil, base.NewMessageFlowError("Cannot send any more messages, due to a sequence number counter overflow", ErrOverflowSentinel)
	}

	data := new(bytes.Buffer)
	dw := bufio.NewWriter(data)

	// pack nonce //
	dw.Write(client.CookieOut)
	dw.WriteByte(src)
	dw.WriteByte(dest)
	csnBytes, err := client.CombinedSequenceNumberOut.AsBytes()
	if err != nil {
		dw.Flush()
		return nil, err
	}
	dw.Write(csnBytes)
	// pack nonce //

	// pack payload //
	if payloadPacker != nil {
		payload, err := payloadPacker.Pack(client, (func() ([]byte, error) {
			err1 := dw.Flush()
			return data.Bytes(), err1
		}))
		if err != nil {
			dw.Flush()
			return nil, err
		}
		dw.Write(payload)
	} else { /*if there is no payloadPacker we will write empty (default) data. with that writing, we will have extra one byte(x\80) in payload field*/
		payload, err := encodePayload(map[string]interface{}{})
		if err != nil {
			dw.Flush()
			return nil, err
		}
		dw.Write(payload)
	}
	// pack payload //

	// end up by flushing
	err = dw.Flush()
	if err != nil {
		return nil, err
	}
	client.CombinedSequenceNumberOut.Increment()
	return data.Bytes(), nil
}

// Unpack decodes data and returns appropriate Message
func Unpack(client *Client, data []byte, rawDataUnpacker RawDataUnpacker) (message interface{}, resultError error) {
	rawData, err := rawDataUnpacker(data)
	if err != nil {
		return nil, err
	}
	deferWithGuard := base.NewEvalWithGuard(func() bool { return resultError == nil })
	defer deferWithGuard.Eval()

	// sourceType := base.GetAddressTypeFromAddr(source)
	destType := base.GetAddressTypeFromAddr(rawData.Dest)

	// Validate destination
	isToServer := destType == base.Server
	if typeVal, typeHasVal := client.GetType(); !isToServer && !(client.Authenticated && typeHasVal && typeVal != destType) {
		return nil, base.NewMessageFlowError(fmt.Sprintf("Not allowed to relay messages to 0x%x", rawData.Dest), ErrNotAllowedMessage)
	}

	// Validate source
	if client.Id != rawData.Source {
		return nil, base.NewMessageFlowError(fmt.Sprintf("Identities do not match, expected 0x%x, got 0x%x", client.Id, rawData.Source), ErrNotMatchedIdentities)
	}

	var chkUpSetCookieIn *base.CheckUp
	// Validate cookie
	if isToServer {
		if chkUpSetCookieIn = client.CheckAndSetCookieIn(rawData.Cookie); chkUpSetCookieIn.Err != nil {
			return nil, fmt.Errorf("Invalid cookie: 0x%x. err: %+v", rawData.Cookie, chkUpSetCookieIn.Err)
		}
		deferWithGuard.Push(func(prevGuard *func() bool) func() bool { chkUpSetCookieIn.Eval(); return *prevGuard })
	}

	// validate and increase csn
	if isToServer {
		csn, err := ParseCombinedSequenceNumber(rawData.Csn)
		if err != nil {
			return nil, err
		}
		if client.CombinedSequenceNumberIn == nil {
			if csn.GetOverflowNumber() != 0 {
				return nil, base.NewMessageFlowError("overflow number must be initialized with zero", ErrInvalidOverflowNumber)
			}
			client.CombinedSequenceNumberIn = csn
		} else {
			if client.CombinedSequenceNumberIn.HasErrOverflowSentinel() {
				return nil, base.NewMessageFlowError("Cannot receive any more messages, due to a sequence number counter overflow", ErrOverflowSentinel)
			}
			if !client.CombinedSequenceNumberIn.EqualsTo(csn) {
				return nil, base.NewMessageFlowError("invalid received sequence number", ErrNotExpectedCsn)
			}
		}
		deferWithGuard.Push(func(prevGuard *func() bool) func() bool {
			client.CombinedSequenceNumberIn.Increment()
			return *prevGuard
		})
	}
	if destType != base.Server {
		return NewRawMessage(rawData.Source, rawData.Dest, data), nil
	}

	var payload PayloadUnion
	decryptedPayload, err := decryptPayload(client, rawData.Nonce, rawData.Payload)
	decodeData := decryptedPayload
	if err != nil {
		decodeData = rawData.Payload
	}
	payload, err = decodePayload(decodeData)
	if err != nil {
		return nil, ErrCantDecodePayload
	}

	switch payload.Type {
	case base.ServerHello:
		if serverPk, err := nacl.ConvertBoxPkToBytes(payload.Key); err == nil {
			return NewServerHelloMessage(rawData.Source, rawData.Dest, serverPk), nil
		}
		return nil, NewPayloadFieldError(base.ServerHello, "key", err)
	case base.ClientHello:
		if clientPk, err := nacl.ConvertBoxPkToBytes(payload.Key); err == nil {
			return NewClientHelloMessage(rawData.Source, rawData.Dest, clientPk), nil
		}
		return nil, NewPayloadFieldError(base.ClientHello, "key", err)
	case base.ClientAuth:
		// your_cookie
		yourCookie, err := msgutil.ParseYourCookie(payload.YourCookie)
		if err != nil {
			return nil, NewPayloadFieldError(base.ClientAuth, "your_cookie", err)
		}

		// subprotocols
		subprotocols, err := msgutil.ParseSubprotocols(payload.Subprotocols)
		if err != nil {
			return nil, NewPayloadFieldError(base.ClientAuth, "subprotocols", err)
		}

		// your_key
		yourKey, err := msgutil.ParseYourKey(payload.YourKey)
		if err != nil {
			return nil, NewPayloadFieldError(base.ClientAuth, "your_key", err)
		}

		return NewClientAuthMessage(rawData.Source, rawData.Dest, yourCookie, subprotocols, payload.PingInterval, yourKey), nil
	case base.NewInitiator:
		return NewNewInitiatorMessage(rawData.Source, rawData.Dest), nil
	case base.NewResponder:
		id, err := msgutil.ParseAddressId(payload.Id)
		if err != nil {
			return nil, NewPayloadFieldError(base.NewResponder, "id", err)
		}
		return NewNewResponderMessage(rawData.Source, rawData.Dest, id), nil
	case base.DropResponder:
		id, err := msgutil.ParseAddressId(payload.Id)
		if err != nil || id <= base.Initiator {
			return nil, NewPayloadFieldError(base.DropResponder, "id", err)
		}
		reason, err := msgutil.ParseReasonCode(payload.Reason)
		if err != nil {
			return NewDropResponderMessageWithReason(rawData.Source, rawData.Dest, id, reason), nil
		}
		return NewDropResponderMessage(rawData.Source, rawData.Dest, id), nil
	default:
		return nil, NewPayloadFieldError(payload.Type, "type", ErrInvalidFieldValue)
	}
}

func signKeys(c *Client, nonce []byte) []byte {
	var nonceArr [base.NonceLength]byte
	copy(nonceArr[:], nonce[:base.NonceLength])
	var buf bytes.Buffer
	buf.Write(c.ServerSessionBox.Pk[:])
	buf.Write(c.ClientKey[:])
	return box.Seal(nil, buf.Bytes(), &nonceArr, &c.ClientKey, &c.ServerPermanentBox.Sk)
}
