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
func Pack(noncePacker NoncePacker, payloadPacker PayloadPacker) ([]byte, error) {
	csnOut := noncePacker.Csn()
	src := noncePacker.Src()
	dest := noncePacker.Dest()

	cookieOut, _ := noncePacker.Cookie()

	if csnOut.HasErrOverflowSentinel() {
		return nil, base.NewMessageFlowError("Cannot send any more messages, due to a sequence number counter overflow", ErrOverflowSentinel)
	}

	data := new(bytes.Buffer)
	dw := bufio.NewWriter(data)

	// pack nonce //
	dw.Write(cookieOut)
	dw.WriteByte(src)
	dw.WriteByte(dest)
	csnBytes, err := csnOut.AsBytes()
	if err != nil {
		dw.Flush()
		return nil, err
	}
	dw.Write(csnBytes)
	// pack nonce //

	// pack payload //
	if payloadPacker != nil {
		payload, err := payloadPacker.Pack((func() ([]byte, error) {
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
	csnOut.Increment()
	return data.Bytes(), nil
}

// Unpack decodes data and returns appropriate Message
func Unpack(nonceUnpacker NonceUnpacker, data []byte, rawDataUnpacker RawDataUnpacker) (message interface{}, resultError error) {
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
	if typeVal, typeHasVal := nonceUnpacker.Type(); !isToServer && !(nonceUnpacker.Authenticated() && typeHasVal && typeVal != destType) {
		return nil, base.NewMessageFlowError(fmt.Sprintf("Not allowed to relay messages to 0x%x", rawData.Dest), ErrNotAllowedMessage)
	}

	// Validate source
	if nonceUnpacker.Id() != rawData.Source {
		return nil, base.NewMessageFlowError(fmt.Sprintf("Identities do not match, expected 0x%x, got 0x%x", nonceUnpacker.Id(), rawData.Source), ErrNotMatchedIdentities)
	}

	// Validate cookie
	if isToServer {
		doCookieIn, err := nonceUnpacker.MakeCookieWriter(rawData.Cookie)
		if err != nil {
			return nil, fmt.Errorf("Invalid cookie: 0x%x. err: %+v", rawData.Cookie, err)
		}
		deferWithGuard.Push(func(prevGuard *func() bool) func() bool { doCookieIn(); return *prevGuard })
	}

	// validate and increase csn
	if isToServer {
		csn, err := ParseCombinedSequenceNumber(rawData.Csn)
		if err != nil {
			return nil, err
		}
		csnIn := nonceUnpacker.Csn()
		if csnIn == nil {
			if csn.GetOverflowNumber() != 0 {
				return nil, base.NewMessageFlowError("overflow number must be initialized with zero", ErrInvalidOverflowNumber)
			}
			nonceUnpacker.ReceiveCsn(csn)
			csnIn = csn
		} else {
			if csnIn.HasErrOverflowSentinel() {
				return nil, base.NewMessageFlowError("Cannot receive any more messages, due to a sequence number counter overflow", ErrOverflowSentinel)
			}
			if !csnIn.EqualsTo(csn) {
				return nil, base.NewMessageFlowError("invalid received sequence number", ErrNotExpectedCsn)
			}
		}
		deferWithGuard.Push(func(prevGuard *func() bool) func() bool {
			csnIn.Increment()
			return *prevGuard
		})
	}
	if destType != base.Server {
		return NewRawMessage(rawData.Source, rawData.Dest, data), nil
	}

	var payload PayloadUnion
	decryptedPayload, err := decryptPayload(nonceUnpacker.ClientKey(), nonceUnpacker.ServerSessionSk(), rawData.Nonce, rawData.Payload)
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
		return parseServerHello(&payload, &rawData)
	case base.ClientHello:
		return parseClientHello(&payload, &rawData)
	case base.ClientAuth:
		return parseClientAuth(&payload, &rawData)
	case base.NewInitiator:
		return parseNewInitiator(&rawData)
	case base.NewResponder:
		return parseNewResponder(&payload, &rawData)
	case base.DropResponder:
		return parseDropResponder(&payload, &rawData)
	default:
		return nil, NewPayloadFieldError(payload.Type, "type", ErrInvalidFieldValue)
	}
}

func parseServerHello(payload *PayloadUnion, rawData *RawData) (*ServerHelloMessage, error) {
	serverPk, err := nacl.ConvertBoxPkToBytes(payload.Key)
	if err != nil {
		return nil, NewPayloadFieldError(base.ServerHello, "key", err)
	}
	return NewServerHelloMessage(rawData.Source, rawData.Dest, serverPk), nil
}

func parseClientHello(payload *PayloadUnion, rawData *RawData) (*ClientHelloMessage, error) {
	clientPk, err := nacl.ConvertBoxPkToBytes(payload.Key)
	if err != nil {
		return nil, NewPayloadFieldError(base.ClientHello, "key", err)
	}
	return NewClientHelloMessage(rawData.Source, rawData.Dest, clientPk), nil
}

func parseClientAuth(payload *PayloadUnion, rawData *RawData) (*ClientAuthMessage, error) {
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
}

func parseNewInitiator(rawData *RawData) (*NewInitiatorMessage, error) {
	return NewNewInitiatorMessage(rawData.Source, rawData.Dest), nil
}

func parseNewResponder(payload *PayloadUnion, rawData *RawData) (*NewResponderMessage, error) {
	id, err := msgutil.ParseAddressId(payload.Id)
	if err != nil {
		return nil, NewPayloadFieldError(base.NewResponder, "id", err)
	}
	return NewNewResponderMessage(rawData.Source, rawData.Dest, id), nil
}

func parseDropResponder(payload *PayloadUnion, rawData *RawData) (*DropResponderMessage, error) {
	id, err := msgutil.ParseAddressId(payload.Id)
	if err != nil || id <= base.Initiator {
		return nil, NewPayloadFieldError(base.DropResponder, "id", err)
	}
	reason, err := msgutil.ParseReasonCode(payload.Reason)
	if err != nil {
		return NewDropResponderMessageWithReason(rawData.Source, rawData.Dest, id, reason), nil
	}
	return NewDropResponderMessage(rawData.Source, rawData.Dest, id), nil
}

func signKeys(clientKey [nacl.NaclKeyBytesSize]byte, serverSessionPk [nacl.NaclKeyBytesSize]byte, serverPermanentSk [nacl.NaclKeyBytesSize]byte, nonce []byte) []byte {
	var nonceArr [base.NonceLength]byte
	copy(nonceArr[:], nonce[:base.NonceLength])
	var buf bytes.Buffer
	buf.Write(serverSessionPk[:])
	buf.Write(clientKey[:])
	return box.Seal(nil, buf.Bytes(), &nonceArr, &clientKey, &serverPermanentSk)
}
