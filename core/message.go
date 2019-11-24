package core

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"

	"github.com/OguzhanE/saltyrtc-server-go/pkg/base"

	"github.com/OguzhanE/saltyrtc-server-go/pkg/msgutil"
	"github.com/OguzhanE/saltyrtc-server-go/pkg/naclutil"

	"github.com/ugorji/go/codec"
	"golang.org/x/crypto/nacl/box"
)

type PayloadUnion struct {
	Type               base.MessageType `codec:"type"`
	Key                []byte           `codec:"key,omitempty"`
	YourCookie         []byte           `codec:"your_cookie,omitempty"`
	Subprotocols       []string         `codec:"subprotocols,omitempty"`
	PingInterval       uint32           `codec:"ping_interval,omitempty"`
	YourKey            []byte           `codec:"your_key,omitempty"`
	InitiatorConnected bool             `codec:"initiator_connected,omitempty"`
	Responders         []uint8          `codec:"responders,omitempty"`
	SignedKeys         []byte           `codec:"signed_keys,omitempty"`
	Id                 interface{}      `codec:"id,omitempty"`
	Reason             int              `codec:"reason,omitempty"`
}

type NonceReader func() ([]byte, error)

type PayloadPacker interface {
	Pack(client *Client, nonceReader NonceReader) ([]byte, error)
}

type PayloadFieldError struct {
	Type  string
	Field string
	Err   error
}

// NewPayloadFieldError creates PayloadFieldError instance
func NewPayloadFieldError(payloadType string, field string, err error) *PayloadFieldError {
	return &PayloadFieldError{
		Type:  payloadType,
		Field: field,
		Err:   err,
	}
}

func (e *PayloadFieldError) Error() string {
	return e.Type + "." + e.Field + ": " + e.Err.Error()
}

var (
	// ErrNotAllowedMessage occurs when you are trying to relay a message to invalid dest
	ErrNotAllowedMessage = errors.New("not allowed message")
	// ErrNotMatchedIdentities occurs when you identities dont match for two different source
	ErrNotMatchedIdentities = errors.New("identities dont match")
	// ErrNotAuthenticatedClient occurs when you are trying to encrypt message
	ErrNotAuthenticatedClient = errors.New("client is not authenticated")
	// ErrMessageTooShort occurs when the length of message less than expected
	ErrMessageTooShort = errors.New("message is too short")
	// ErrCantDecodePayload occurs when try to decode payload
	ErrCantDecodePayload = errors.New("cant decode payload")
	// ErrFieldNotExist occurs when a field should exist but it doesnt
	ErrFieldNotExist = errors.New("field doesnt exist")
	// ErrInvalidFieldValue occurs when fiel value is not valid
	ErrInvalidFieldValue = errors.New("invalid field value")
	// ErrCantDecryptPayload occurs when try to decrypt payload
	ErrCantDecryptPayload = errors.New("cant decrypt payload")
)

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

func checkAllKeysExists(data *map[string]interface{}, correlationName string, keys ...string) error {
	for _, key := range keys {
		_, ok := (*data)[key]
		if !ok {
			return NewPayloadFieldError(correlationName, key, ErrFieldNotExist)
		}
	}
	return nil
}

type RawData struct {
	Nonce   []byte
	Cookie  []byte
	Source  base.AddressType
	Dest    base.AddressType
	Csn     []byte
	Payload []byte
}

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

type RawDataUnpacker func(data []byte) (RawData, error)

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
			return nil, fmt.Errorf("Invalid cookie: 0x%x. err: %#v", rawData.Cookie, chkUpSetCookieIn.Err)
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
		if serverPk, err := naclutil.ConvertBoxPkToBytes(payload.Key); err == nil {
			return NewServerHelloMessage(rawData.Source, rawData.Dest, serverPk), nil
		}
		return nil, NewPayloadFieldError(base.ServerHello, "key", err)
	case base.ClientHello:
		if clientPk, err := naclutil.ConvertBoxPkToBytes(payload.Key); err == nil {
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

func encodePayload(payload interface{}) ([]byte, error) {
	b := new(bytes.Buffer)
	bw := bufio.NewWriter(b)
	h := new(codec.MsgpackHandle)
	enc := codec.NewEncoder(bw, h)
	err := enc.Encode(payload)
	if err != nil {
		bw.Flush()
		return nil, err
	}
	err = bw.Flush()
	return b.Bytes(), err
}

func decodePayload(encodedPayload []byte) (PayloadUnion, error) {
	h := new(codec.MsgpackHandle)
	h.ErrorIfNoField = true
	dec := codec.NewDecoderBytes(encodedPayload, h)
	v := PayloadUnion{}
	err := dec.Decode(&v)
	return v, err
}

func encryptPayload(client *Client, nonce []byte, encodedPayload []byte) ([]byte, error) {
	var nonceArr [base.NonceLength]byte
	copy(nonceArr[:], nonce[:base.NonceLength])
	return box.Seal(nil, encodedPayload, &nonceArr, &client.ClientKey, &client.ServerSessionBox.Sk), nil
}

func decryptPayload(client *Client, nonce []byte, data []byte) ([]byte, error) {
	var nonceArr [base.NonceLength]byte
	copy(nonceArr[:], nonce[:base.NonceLength])
	decryptedData, ok := box.Open(nil, data, &nonceArr, &client.ClientKey, &client.ServerSessionBox.Sk)
	if !ok {
		return nil, ErrCantDecryptPayload
	}
	return decryptedData, nil
}

func signKeys(c *Client, nonce []byte) []byte {
	var nonceArr [base.NonceLength]byte
	copy(nonceArr[:], nonce[:base.NonceLength])
	var buf bytes.Buffer
	buf.Write(c.ServerSessionBox.Pk[:])
	buf.Write(c.ClientKey[:])
	return box.Seal(nil, buf.Bytes(), &nonceArr, &c.ClientKey, &c.ServerPermanentBox.Sk)
}

// BaseMessage //
type BaseMessage struct {
	src  base.AddressType
	dest base.AddressType
}

// BaseMessage //

// RawMessage //
type RawMessage struct {
	BaseMessage
	data []byte
	PayloadPacker
}

func NewRawMessage(src base.AddressType, dest base.AddressType, data []byte) *RawMessage {
	return &RawMessage{
		BaseMessage: BaseMessage{
			src:  src,
			dest: dest,
		},
		data: data,
	}
}

func (m *RawMessage) Pack(client *Client, nonceReader *NonceReader) ([]byte, error) {
	return m.data, nil
}

// RawMessage //

// ServerHelloMessage //
type ServerHelloMessage struct {
	BaseMessage
	PayloadPacker
	serverPublicKey []byte
}

func NewServerHelloMessage(src base.AddressType, dest base.AddressType, serverPublicKey []byte) *ServerHelloMessage {
	return &ServerHelloMessage{
		BaseMessage: BaseMessage{
			src:  src,
			dest: dest,
		},
		serverPublicKey: serverPublicKey,
	}
}

func (m *ServerHelloMessage) Pack(client *Client, nonceReader NonceReader) ([]byte, error) {
	payload := struct {
		Type base.MessageType `codec:"type"`
		Key  []byte           `codec:"key"`
	}{
		Type: base.ServerHello,
		Key:  m.serverPublicKey,
	}
	return encodePayload(payload)
}

// ServerHelloMessage //

// ClientHelloMessage //
type ClientHelloMessage struct {
	BaseMessage
	clientPublicKey []byte
}

func NewClientHelloMessage(src base.AddressType, dest base.AddressType, clientPublicKey []byte) *ClientHelloMessage {
	return &ClientHelloMessage{
		BaseMessage: BaseMessage{
			src:  src,
			dest: dest,
		},
		clientPublicKey: clientPublicKey,
	}
}

func (m *ClientHelloMessage) Pack(client *Client, nonceReader NonceReader) ([]byte, error) {
	payload := struct {
		Type base.MessageType `codec:"type"`
		Key  []byte           `codec:"key"`
	}{
		Type: base.ClientHello,
		Key:  m.clientPublicKey,
	}
	return encodePayload(payload)
}

// ClientHelloMessage //

// ClientAuthMessage //
type ClientAuthMessage struct {
	BaseMessage
	serverCookie []byte
	subprotocols []string
	pingInterval uint32
	serverKey    [base.KeyBytesSize]byte
}

func NewClientAuthMessage(src base.AddressType, dest base.AddressType, serverCookie []byte,
	subprotocols []string, pingInterval uint32, serverKey [base.KeyBytesSize]byte) *ClientAuthMessage {
	return &ClientAuthMessage{
		BaseMessage: BaseMessage{
			src:  src,
			dest: dest,
		},
		serverCookie: serverCookie,
		subprotocols: subprotocols,
		pingInterval: pingInterval,
		serverKey:    serverKey,
	}
}

func (m *ClientAuthMessage) Pack(client *Client, nonceReader NonceReader) ([]byte, error) {
	if !client.Authenticated {
		return nil, base.NewMessageFlowError("Cannot encrypt payload", ErrNotAuthenticatedClient)
	}
	payload := struct {
		Type         base.MessageType `codec:"type"`
		YourCookie   []byte           `codec:"your_cookie"`
		Subprotocols []string         `codec:"subprotocols"`
		PingInterval uint32           `codec:"ping_interval"`
		YourKey      [32]byte         `codec:"your_key"`
	}{
		Type:         base.ClientAuth,
		YourCookie:   m.serverCookie,
		Subprotocols: m.subprotocols,
		PingInterval: m.pingInterval,
		YourKey:      m.serverKey,
	}
	encodedPayload, err := encodePayload(payload)
	if err != nil {
		return nil, err
	}
	nonce, err := nonceReader()
	if err != nil {
		return nil, err
	}
	encryptedPayload, err := encryptPayload(client, nonce, encodedPayload)
	return encryptedPayload, err
}

// ClientAuthMessage //

// ServerAuthMessage //
type ServerAuthMessage struct {
	BaseMessage
	clientCookie       []byte
	signKeys           bool
	initiatorConnected bool
	responderIds       []base.AddressType
	towardsInitiator   bool
}

func NewServerAuthMessageForInitiator(src base.AddressType, dest base.AddressType, clientCookie []byte,
	signKeys bool, responderIds []base.AddressType) *ServerAuthMessage {
	return &ServerAuthMessage{
		BaseMessage: BaseMessage{
			src:  src,
			dest: dest,
		},
		clientCookie:     clientCookie,
		signKeys:         signKeys,
		responderIds:     responderIds,
		towardsInitiator: true,
	}
}

func NewServerAuthMessageForResponder(src base.AddressType, dest base.AddressType, clientCookie []byte,
	signKeys bool, initiatorConnected bool) *ServerAuthMessage {
	return &ServerAuthMessage{
		BaseMessage: BaseMessage{
			src:  src,
			dest: dest,
		},
		clientCookie:       clientCookie,
		signKeys:           signKeys,
		initiatorConnected: initiatorConnected,
		towardsInitiator:   false,
	}
}

func (m *ServerAuthMessage) Pack(client *Client, nonceReader NonceReader) ([]byte, error) {
	var payload interface{}
	nonce, err := nonceReader()
	if err != nil {
		return nil, err
	}

	if m.towardsInitiator {
		if m.signKeys {
			payload = struct {
				Type               base.MessageType `codec:"type"`
				YourCookie         []byte           `codec:"your_cookie"`
				InitiatorConnected bool             `codec:"initiator_connected"`
				SignedKeys         []byte           `codec:"signed_keys"`
			}{
				Type:               base.ServerAuth,
				YourCookie:         m.clientCookie,
				InitiatorConnected: m.initiatorConnected,
				SignedKeys:         signKeys(client, nonce),
			}
		} else {
			payload = struct {
				Type               base.MessageType `codec:"type"`
				YourCookie         []byte           `codec:"your_cookie"`
				InitiatorConnected bool             `codec:"initiator_connected"`
			}{
				Type:               base.ServerAuth,
				YourCookie:         m.clientCookie,
				InitiatorConnected: m.initiatorConnected,
			}
		}
	} else {
		if m.signKeys {
			payload = struct {
				Type       base.MessageType `codec:"type"`
				YourCookie []byte           `codec:"your_cookie"`
				Responders []uint8          `codec:"responders"`
				SignedKeys []byte           `codec:"signed_keys"`
			}{
				Type:       base.ServerAuth,
				YourCookie: m.clientCookie,
				Responders: m.responderIds,
				SignedKeys: signKeys(client, nonce),
			}
		} else {
			payload = struct {
				Type       base.MessageType `codec:"type"`
				YourCookie []byte           `codec:"your_cookie"`
				Responders []uint8          `codec:"responders"`
			}{
				Type:       base.ServerAuth,
				YourCookie: m.clientCookie,
				Responders: m.responderIds,
			}
		}
	}

	encodedPayload, err := encodePayload(payload)
	if err != nil {
		return nil, err
	}

	encryptedPayload, err := encryptPayload(client, nonce, encodedPayload)
	return encryptedPayload, err
}

// ServerAuthMessage //

// NewInitiatorMessage //
type NewInitiatorMessage struct {
	BaseMessage
}

func NewNewInitiatorMessage(src base.AddressType, dest base.AddressType) *NewInitiatorMessage {
	return &NewInitiatorMessage{
		BaseMessage: BaseMessage{
			src:  src,
			dest: dest,
		},
	}
}

func (m *NewInitiatorMessage) Pack(client *Client, nonceReader NonceReader) ([]byte, error) {
	payload := struct {
		Type base.MessageType `codec:"type"`
	}{
		Type: base.NewInitiator,
	}

	nonce, err := nonceReader()
	if err != nil {
		return nil, err
	}

	encodedPayload, err := encodePayload(payload)
	if err != nil {
		return nil, err
	}

	encryptedPayload, err := encryptPayload(client, nonce, encodedPayload)
	return encryptedPayload, err
}

// NewInitiatorMessage //

// NewResponderMessage //
type NewResponderMessage struct {
	BaseMessage
	responderId base.AddressType
}

func NewNewResponderMessage(src base.AddressType, dest base.AddressType, responderId base.AddressType) *NewResponderMessage {
	return &NewResponderMessage{
		BaseMessage: BaseMessage{
			src:  src,
			dest: dest,
		},
		responderId: responderId,
	}
}

func (m *NewResponderMessage) Pack(client *Client, nonceReader NonceReader) ([]byte, error) {
	payload := struct {
		Type base.MessageType `codec:"type"`
		Id   uint8            `codec:"id"`
	}{
		Type: base.NewResponder,
		Id:   m.responderId,
	}

	nonce, err := nonceReader()
	if err != nil {
		return nil, err
	}

	encodedPayload, err := encodePayload(payload)
	if err != nil {
		return nil, err
	}

	encryptedPayload, err := encryptPayload(client, nonce, encodedPayload)
	return encryptedPayload, err
}

// NewResponderMessage //

// DropResponderMessage //
type DropResponderMessage struct {
	BaseMessage
	responderId base.AddressType
	reason      int
}

func NewDropResponderMessage(src base.AddressType, dest base.AddressType, responderId base.AddressType) *DropResponderMessage {
	return NewDropResponderMessageWithReason(src, dest, responderId, base.CloseCodeDropByInitiator)
}

func NewDropResponderMessageWithReason(src base.AddressType, dest base.AddressType, responderId base.AddressType, reason int) *DropResponderMessage {
	return &DropResponderMessage{
		BaseMessage: BaseMessage{
			src:  src,
			dest: dest,
		},
		responderId: responderId,
		reason:      reason,
	}
}

func (m *DropResponderMessage) Pack(client *Client, nonceReader NonceReader) ([]byte, error) {
	payload := struct {
		Type   base.MessageType `codec:"type"`
		Id     uint8            `codec:"id"`
		Reason int              `codec:"reason"`
	}{
		Type:   base.DropResponder,
		Id:     m.responderId,
		Reason: m.reason,
	}

	nonce, err := nonceReader()
	if err != nil {
		return nil, err
	}

	encodedPayload, err := encodePayload(payload)
	if err != nil {
		return nil, err
	}

	encryptedPayload, err := encryptPayload(client, nonce, encodedPayload)
	return encryptedPayload, err
}

// DropResponderMessage //

// SendErrorMessage //
type SendErrorMessage struct {
	BaseMessage
	messageId []byte
}

func NewSendErrorMessage(src base.AddressType, dest base.AddressType, messageId []byte) *SendErrorMessage {
	return &SendErrorMessage{
		BaseMessage: BaseMessage{
			src:  src,
			dest: dest,
		},
		messageId: messageId,
	}
}

func (m *SendErrorMessage) Pack(client *Client, nonceReader NonceReader) ([]byte, error) {
	payload := struct {
		Type base.MessageType `codec:"type"`
		Id   []byte           `codec:"id"`
	}{
		Type: base.SendError,
		Id:   m.messageId,
	}

	nonce, err := nonceReader()
	if err != nil {
		return nil, err
	}

	encodedPayload, err := encodePayload(payload)
	if err != nil {
		return nil, err
	}

	encryptedPayload, err := encryptPayload(client, nonce, encodedPayload)
	return encryptedPayload, err
}

// SendErrorMessage //

// DisconnectedMessage //
type DisconnectedMessage struct {
	BaseMessage
	clientId []byte
}

func NewDisconnectedMessage(src base.AddressType, dest base.AddressType, clientId []byte) *DisconnectedMessage {
	return &DisconnectedMessage{
		BaseMessage: BaseMessage{
			src:  src,
			dest: dest,
		},
		clientId: clientId,
	}
}

func (m *DisconnectedMessage) Pack(client *Client, nonceReader NonceReader) ([]byte, error) {

	payload := struct {
		Type base.MessageType `codec:"type"`
		Id   []byte           `codec:"id"`
	}{
		Type: base.Disconnected,
		Id:   m.clientId,
	}

	nonce, err := nonceReader()
	if err != nil {
		return nil, err
	}

	encodedPayload, err := encodePayload(payload)
	if err != nil {
		return nil, err
	}

	encryptedPayload, err := encryptPayload(client, nonce, encodedPayload)
	return encryptedPayload, err
}

// DisconnectedMessage //
