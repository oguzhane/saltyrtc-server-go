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

type PayloadFieldError struct {
	Type  string
	Field string
	Err   error
}

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

type payloadPacker func(readNonce func() ([]byte, error)) ([]byte, error)

func Pack(client *Client, src base.AddressType, dest base.AddressType,
	packPayload payloadPacker) ([]byte, error) {
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
	if packPayload != nil {
		payload, err := packPayload(func() ([]byte, error) {
			err1 := dw.Flush()
			return data.Bytes(), err1
		})
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
			return fmt.Errorf("%s doesnt exist for %s", key, correlationName)
		}
	}
	return nil
}

func Unpack(client *Client, data []byte) (message BaseMessage, resultError error) {
	deferWithGuard := base.NewEvalWithGuard(func() bool { return resultError == nil })
	defer deferWithGuard.Eval()

	if len(data) < base.DataLengthMin {
		return nil, ErrMessageTooShort
	}
	nonce := data[:base.NonceLength]
	cookie := nonce[:base.CookieLength]
	var source base.AddressType = nonce[base.CookieLength:base.SourceUpperBound][0]
	var dest base.AddressType = nonce[base.SourceUpperBound:base.DestinationUpperBound][0]
	csnBytes := nonce[base.DestinationUpperBound:base.CsnUpperBound]
	// sourceType := base.GetAddressTypeFromAddr(source)
	destType := base.GetAddressTypeFromAddr(dest)

	// Validate destination
	isToServer := destType == base.Server
	if typeVal, typeHasVal := client.GetType(); !isToServer && !(client.Authenticated && typeHasVal && typeVal != destType) {
		return nil, base.NewMessageFlowError(fmt.Sprintf("Not allowed to relay messages to 0x%x", dest), ErrNotAllowedMessage)
	}

	// Validate source
	if client.Id != source {
		return nil, base.NewMessageFlowError(fmt.Sprintf("Identities do not match, expected 0x%x, got 0x%x", client.Id, source), ErrNotMatchedIdentities)
	}

	var chkUpSetCookieIn *base.CheckUp
	// Validate cookie
	if isToServer {
		if chkUpSetCookieIn = client.CheckAndSetCookieIn(cookie); chkUpSetCookieIn.Err != nil {
			return nil, fmt.Errorf("Invalid cookie: 0x%x", cookie)
		}
		deferWithGuard.Push(func(prevGuard *func() bool) func() bool { chkUpSetCookieIn.Eval(); return *prevGuard })
	}

	// validate and increase csn
	if isToServer {
		csn, err := ParseCombinedSequenceNumber(csnBytes)
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
	var payload map[string]interface{}
	if destType == base.Server {
		payloadRecv := data[base.NonceLength:]
		decryptedPayload, err := decryptPayload(client, nonce, payloadRecv)
		decodeData := decryptedPayload
		if err != nil {
			decodeData = payloadRecv
		}
		payload, err = decodePayload(decodeData)
		if err != nil {
			return nil, ErrCantDecodePayload
		}
		_type, ok := payload["type"]
		if !ok {
			return nil, NewPayloadFieldError("", "type", ErrFieldNotExist)
		}

		switch _type {
		case "server-hello":
			// check keys
			if err := checkAllKeysExists(&payload, "server-hello", "key"); err != nil {
				return nil, err
			}

			keyVal, _ := payload["key"]
			if serverPk, err := naclutil.ConvertBoxPkToBytes(keyVal); err == nil {
				return NewServerHelloMessage(source, dest, serverPk), nil
			}
			return nil, NewPayloadFieldError("server-hello", "key", err)
		case "client-hello":
			// check keys
			if err := checkAllKeysExists(&payload, "client-hello", "key"); err != nil {
				return nil, err
			}

			keyVal, _ := payload["key"]
			if clientPk, err := naclutil.ConvertBoxPkToBytes(keyVal); err == nil {
				return NewClientHelloMessage(source, dest, clientPk), nil
			}
			return nil, NewPayloadFieldError("client-hello", "key", err)
		case "client-auth":
			// check keys
			if err := checkAllKeysExists(&payload, "client-auth", "your_cookie", "subprotocols", "ping_interval", "your_key"); err != nil {
				return nil, err
			}

			// your_cookie
			yourCookieVal, _ := payload["your_cookie"]
			yourCookie, err := msgutil.ParseYourCookie(yourCookieVal)
			if err != nil {
				return nil, NewPayloadFieldError("client-auth", "your_cookie", err)
			}

			// subprotocols
			subprotocolsVal, _ := payload["subprotocols"]
			subprotocols, err := msgutil.ParseSubprotocols(subprotocolsVal)
			if err != nil {
				return nil, NewPayloadFieldError("client-auth", "subprotocols", err)
			}

			// ping_interval
			pingIntervalVal, _ := payload["ping_interval"]
			pingInterval, err := msgutil.ParsePingInterval(pingIntervalVal)
			if err != nil {
				return nil, NewPayloadFieldError("client-auth", "ping_interval", err)
			}

			// your_key
			yourKeyVal, _ := payload["your_key"]
			yourKey, err := msgutil.ParseYourKey(yourKeyVal)
			if err != nil {
				return nil, NewPayloadFieldError("client-auth", "your_key", err)
			}

			return NewClientAuthMessage(source, dest, yourCookie, subprotocols, uint32(pingInterval), yourKey), nil
		case "new-initiator":
			return NewNewInitiatorMessage(source, dest), nil
		case "new-responder":
			// check keys
			if err := checkAllKeysExists(&payload, "new-responder", "id"); err != nil {
				return nil, err
			}

			id, err := msgutil.ParseAddressId(payload["id"])
			if err != nil {
				return nil, NewPayloadFieldError("new-responder", "id", err)
			}
			return NewNewResponderMessage(source, dest, id), nil
		case "drop-responder":
			// check keys
			if err := checkAllKeysExists(&payload, "drop-responder", "id"); err != nil {
				return nil, err
			}

			id, err := msgutil.ParseAddressId(payload["id"])
			if err != nil || id <= base.Initiator {
				return nil, NewPayloadFieldError("drop-responder", "id", err)
			}
			reasonVal, ok := payload["reason"]
			if ok {
				reason, err := msgutil.ParseReasonCode(reasonVal)
				if err != nil {
					return nil, NewPayloadFieldError("drop-responder", "reason", err)
				}
				return NewDropResponderMessageWithReason(source, dest, id, reason), nil
			}
			return NewDropResponderMessage(source, dest, id), nil
		default:
			return nil, NewPayloadFieldError(fmt.Sprintf("%v", _type), "type", ErrInvalidFieldValue)
		}

	} else {
		return NewRawMessage(source, dest, data), nil
	}
}

func encodePayload(payload map[string]interface{}) ([]byte, error) {
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

func decodePayload(encodedPayload []byte) (map[string]interface{}, error) {
	h := new(codec.MsgpackHandle)
	dec := codec.NewDecoderBytes(encodedPayload, h)
	v := make(map[string]interface{})
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

type BaseMessagePacker interface {
	Pack(client *Client) ([]byte, error)
}

type BaseMessage interface {
	GetSourceType() base.AddressType
	GetDestinationType() base.AddressType
}

// baseMessage //
type baseMessage struct {
	src  base.AddressType
	dest base.AddressType
}

// baseMessage //

// RawMessage //
type RawMessage struct {
	BaseMessage
	baseMessage
	data []byte
}

func NewRawMessage(src base.AddressType, dest base.AddressType, data []byte) *RawMessage {
	return &RawMessage{
		baseMessage: baseMessage{
			src:  src,
			dest: dest,
		},
		data: data,
	}
}

func (m *RawMessage) Pack(client *Client) ([]byte, error) {
	return m.data, nil
}

func (m *RawMessage) GetSourceType() base.AddressType {
	return base.GetAddressTypeFromAddr(m.src)
}
func (m *RawMessage) GetDestinationType() base.AddressType {
	return base.GetAddressTypeFromAddr(m.dest)
}

// RawMessage //

// ServerHelloMessage //
type ServerHelloMessage struct {
	baseMessage
	serverPublicKey []byte
}

func NewServerHelloMessage(src base.AddressType, dest base.AddressType, serverPublicKey []byte) *ServerHelloMessage {
	return &ServerHelloMessage{
		baseMessage: baseMessage{
			src:  src,
			dest: dest,
		},
		serverPublicKey: serverPublicKey,
	}
}

func (m *ServerHelloMessage) Pack(client *Client) ([]byte, error) {
	return Pack(client, m.src, m.dest, func(readNonce func() ([]byte, error)) ([]byte, error) {
		payload := map[string]interface{}{
			"type": []byte(base.ServerHello),
			"key":  m.serverPublicKey,
		}
		return encodePayload(payload)
	})
}

func (m *ServerHelloMessage) GetSourceType() base.AddressType {
	return base.GetAddressTypeFromAddr(m.src)
}
func (m *ServerHelloMessage) GetDestinationType() base.AddressType {
	return base.GetAddressTypeFromAddr(m.dest)
}

// ServerHelloMessage //

// ClientHelloMessage //
type ClientHelloMessage struct {
	baseMessage
	clientPublicKey []byte
}

func NewClientHelloMessage(src base.AddressType, dest base.AddressType, clientPublicKey []byte) *ClientHelloMessage {
	return &ClientHelloMessage{
		baseMessage: baseMessage{
			src:  src,
			dest: dest,
		},
		clientPublicKey: clientPublicKey,
	}
}

func (m *ClientHelloMessage) Pack(client *Client) ([]byte, error) {
	return Pack(client, m.src, m.dest, func(readNonce func() ([]byte, error)) ([]byte, error) {
		payload := map[string]interface{}{
			"type": []byte(base.ClientHello),
			"key":  m.clientPublicKey,
		}
		return encodePayload(payload)
	})
}

func (m *ClientHelloMessage) GetSourceType() base.AddressType {
	return base.GetAddressTypeFromAddr(m.src)
}
func (m *ClientHelloMessage) GetDestinationType() base.AddressType {
	return base.GetAddressTypeFromAddr(m.dest)
}

// ClientHelloMessage //

// ClientAuthMessage //
type ClientAuthMessage struct {
	baseMessage
	serverCookie []byte
	subprotocols []string
	pingInterval uint32
	serverKey    [base.KeyBytesSize]byte
}

func NewClientAuthMessage(src base.AddressType, dest base.AddressType, serverCookie []byte,
	subprotocols []string, pingInterval uint32, serverKey [base.KeyBytesSize]byte) *ClientAuthMessage {
	return &ClientAuthMessage{
		baseMessage: baseMessage{
			src:  src,
			dest: dest,
		},
		serverCookie: serverCookie,
		subprotocols: subprotocols,
		pingInterval: pingInterval,
		serverKey:    serverKey,
	}
}

func (m *ClientAuthMessage) Pack(client *Client) ([]byte, error) {
	if !client.Authenticated {
		return nil, base.NewMessageFlowError("Cannot encrypt payload", ErrNotAuthenticatedClient)
	}
	return Pack(client, m.src, m.dest, func(readNonce func() ([]byte, error)) ([]byte, error) {
		payload := map[string]interface{}{
			"type":          base.ClientAuth,
			"your_cookie":   m.serverCookie,
			"subprotocols":  m.subprotocols,
			"ping_interval": m.pingInterval,
		}
		payload["your_key"] = m.serverKey
		encodedPayload, err := encodePayload(payload)
		if err != nil {
			return nil, err
		}
		nonce, err := readNonce()
		if err != nil {
			return nil, err
		}
		encryptedPayload, err := encryptPayload(client, nonce, encodedPayload)
		return encryptedPayload, err
	})
}

func (m *ClientAuthMessage) GetSourceType() base.AddressType {
	return base.GetAddressTypeFromAddr(m.src)
}
func (m *ClientAuthMessage) GetDestinationType() base.AddressType {
	return base.GetAddressTypeFromAddr(m.dest)
}

// ClientAuthMessage //

// ServerAuthMessage //
type ServerAuthMessage struct {
	baseMessage
	clientCookie       []byte
	signKeys           bool
	initiatorConnected bool
	responderIds       []base.AddressType
	towardsInitiator   bool
}

func NewServerAuthMessageForInitiator(src base.AddressType, dest base.AddressType, clientCookie []byte,
	signKeys bool, responderIds []base.AddressType) *ServerAuthMessage {
	return &ServerAuthMessage{
		baseMessage: baseMessage{
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
		baseMessage: baseMessage{
			src:  src,
			dest: dest,
		},
		clientCookie:       clientCookie,
		signKeys:           signKeys,
		initiatorConnected: initiatorConnected,
		towardsInitiator:   false,
	}
}

func (m *ServerAuthMessage) Pack(client *Client) ([]byte, error) {
	return Pack(client, m.src, m.dest, func(readNonce func() ([]byte, error)) ([]byte, error) {
		payload := map[string]interface{}{
			"type":        base.ServerAuth,
			"your_cookie": m.clientCookie,
		}
		if m.towardsInitiator {
			payload["initiator_connected"] = m.initiatorConnected
		} else {
			payload["responders"] = m.responderIds
		}

		nonce, err := readNonce()
		if err != nil {
			return nil, err
		}

		if m.signKeys {
			payload["signed_keys"] = signKeys(client, nonce)
		}

		encodedPayload, err := encodePayload(payload)
		if err != nil {
			return nil, err
		}

		encryptedPayload, err := encryptPayload(client, nonce, encodedPayload)
		return encryptedPayload, err
	})
}

func (m *ServerAuthMessage) GetSourceType() base.AddressType {
	return base.GetAddressTypeFromAddr(m.src)
}
func (m *ServerAuthMessage) GetDestinationType() base.AddressType {
	return base.GetAddressTypeFromAddr(m.dest)
}

// ServerAuthMessage //

// NewInitiatorMessage //
type NewInitiatorMessage struct {
	baseMessage
}

func NewNewInitiatorMessage(src base.AddressType, dest base.AddressType) *NewInitiatorMessage {
	return &NewInitiatorMessage{
		baseMessage: baseMessage{
			src:  src,
			dest: dest,
		},
	}
}

func (m *NewInitiatorMessage) Pack(client *Client) ([]byte, error) {
	return Pack(client, m.src, m.dest, func(readNonce func() ([]byte, error)) ([]byte, error) {
		payload := map[string]interface{}{
			"type": base.NewInitiator,
		}

		nonce, err := readNonce()
		if err != nil {
			return nil, err
		}

		encodedPayload, err := encodePayload(payload)
		if err != nil {
			return nil, err
		}

		encryptedPayload, err := encryptPayload(client, nonce, encodedPayload)
		return encryptedPayload, err
	})
}

func (m *NewInitiatorMessage) GetSourceType() base.AddressType {
	return base.GetAddressTypeFromAddr(m.src)
}
func (m *NewInitiatorMessage) GetDestinationType() base.AddressType {
	return base.GetAddressTypeFromAddr(m.dest)
}

// NewInitiatorMessage //

// NewResponderMessage //
type NewResponderMessage struct {
	baseMessage
	responderId base.AddressType
}

func NewNewResponderMessage(src base.AddressType, dest base.AddressType, responderId base.AddressType) *NewResponderMessage {
	return &NewResponderMessage{
		baseMessage: baseMessage{
			src:  src,
			dest: dest,
		},
		responderId: responderId,
	}
}

func (m *NewResponderMessage) Pack(client *Client) ([]byte, error) {
	return Pack(client, m.src, m.dest, func(readNonce func() ([]byte, error)) ([]byte, error) {
		payload := map[string]interface{}{
			"type": base.NewResponder,
			"id":   m.responderId,
		}

		nonce, err := readNonce()
		if err != nil {
			return nil, err
		}

		encodedPayload, err := encodePayload(payload)
		if err != nil {
			return nil, err
		}

		encryptedPayload, err := encryptPayload(client, nonce, encodedPayload)
		return encryptedPayload, err
	})
}

func (m *NewResponderMessage) GetSourceType() base.AddressType {
	return base.GetAddressTypeFromAddr(m.src)
}
func (m *NewResponderMessage) GetDestinationType() base.AddressType {
	return base.GetAddressTypeFromAddr(m.dest)
}

// NewResponderMessage //

// DropResponderMessage //
type DropResponderMessage struct {
	baseMessage
	responderId base.AddressType
	reason      int
}

func NewDropResponderMessage(src base.AddressType, dest base.AddressType, responderId base.AddressType) *DropResponderMessage {
	return NewDropResponderMessageWithReason(src, dest, responderId, base.CloseCodeDropByInitiator)
}

func NewDropResponderMessageWithReason(src base.AddressType, dest base.AddressType, responderId base.AddressType, reason int) *DropResponderMessage {
	return &DropResponderMessage{
		baseMessage: baseMessage{
			src:  src,
			dest: dest,
		},
		responderId: responderId,
		reason:      reason,
	}
}

func (m *DropResponderMessage) Pack(client *Client) ([]byte, error) {
	return Pack(client, m.src, m.dest, func(readNonce func() ([]byte, error)) ([]byte, error) {
		payload := map[string]interface{}{
			"type":   base.DropResponder,
			"id":     m.responderId,
			"reason": m.reason,
		}

		nonce, err := readNonce()
		if err != nil {
			return nil, err
		}

		encodedPayload, err := encodePayload(payload)
		if err != nil {
			return nil, err
		}

		encryptedPayload, err := encryptPayload(client, nonce, encodedPayload)
		return encryptedPayload, err
	})
}

func (m *DropResponderMessage) GetSourceType() base.AddressType {
	return base.GetAddressTypeFromAddr(m.src)
}
func (m *DropResponderMessage) GetDestinationType() base.AddressType {
	return base.GetAddressTypeFromAddr(m.dest)
}

// DropResponderMessage //

// SendErrorMessage //
type SendErrorMessage struct {
	baseMessage
	messageId []byte
}

func NewSendErrorMessage(src base.AddressType, dest base.AddressType, messageId []byte) *SendErrorMessage {
	return &SendErrorMessage{
		baseMessage: baseMessage{
			src:  src,
			dest: dest,
		},
		messageId: messageId,
	}
}

func (m *SendErrorMessage) Pack(client *Client) ([]byte, error) {
	return Pack(client, m.src, m.dest, func(readNonce func() ([]byte, error)) ([]byte, error) {
		payload := map[string]interface{}{
			"type": base.SendError,
			"id":   m.messageId,
		}

		nonce, err := readNonce()
		if err != nil {
			return nil, err
		}

		encodedPayload, err := encodePayload(payload)
		if err != nil {
			return nil, err
		}

		encryptedPayload, err := encryptPayload(client, nonce, encodedPayload)
		return encryptedPayload, err
	})
}

func (m *SendErrorMessage) GetSourceType() base.AddressType {
	return base.GetAddressTypeFromAddr(m.src)
}
func (m *SendErrorMessage) GetDestinationType() base.AddressType {
	return base.GetAddressTypeFromAddr(m.dest)
}

// SendErrorMessage //

// DisconnectedMessage //
type DisconnectedMessage struct {
	baseMessage
	clientId []byte
}

func NewDisconnectedMessage(src base.AddressType, dest base.AddressType, clientId []byte) *DisconnectedMessage {
	return &DisconnectedMessage{
		baseMessage: baseMessage{
			src:  src,
			dest: dest,
		},
		clientId: clientId,
	}
}

func (m *DisconnectedMessage) Pack(client *Client) ([]byte, error) {
	return Pack(client, m.src, m.dest, func(readNonce func() ([]byte, error)) ([]byte, error) {
		payload := map[string]interface{}{
			"type": base.Disconnected,
			"id":   m.clientId,
		}

		nonce, err := readNonce()
		if err != nil {
			return nil, err
		}

		encodedPayload, err := encodePayload(payload)
		if err != nil {
			return nil, err
		}

		encryptedPayload, err := encryptPayload(client, nonce, encodedPayload)
		return encryptedPayload, err
	})
}

func (m *DisconnectedMessage) GetSourceType() base.AddressType {
	return base.GetAddressTypeFromAddr(m.src)
}
func (m *DisconnectedMessage) GetDestinationType() base.AddressType {
	return base.GetAddressTypeFromAddr(m.dest)
}

// DisconnectedMessage //
