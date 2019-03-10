package message

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"

	"github.com/oguzhane/saltyrtc-server-go/common"
	"github.com/oguzhane/saltyrtc-server-go/common/msgutil"
	"github.com/oguzhane/saltyrtc-server-go/common/naclutil"

	"github.com/oguzhane/saltyrtc-server-go/core"
	"github.com/ugorji/go/codec"
	"golang.org/x/crypto/nacl/box"
)

type payloadPacker func(readNonce func() ([]byte, error)) ([]byte, error)

func Pack(client *core.Client, src common.AddressType, dest common.AddressType,
	packPayload payloadPacker) ([]byte, error) {
	if client.CombinedSequenceNumberOut.HasErrOverflowSentinel() {
		return nil, common.NewMessageFlowError("Cannot send any more messages, due to a sequence number counter overflow")
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

func Unpack(client *core.Client, data []byte) (BaseMessage, error) {
	if len(data) < 25 {
		return nil, errors.New("Message is too short")
	}
	nonce := data[:24]
	cookie := nonce[:16]
	var source common.AddressType = nonce[16:17][0]
	var dest common.AddressType = nonce[17:18][0]
	csnBytes := nonce[18:24]
	sourceType := common.GetAddressTypeFromaAddr(source)
	destType := common.GetAddressTypeFromaAddr(dest)

	// Validate destination
	isToServer := destType == common.Server
	if typeHasVal, typeVal := client.GetType(); !isToServer && !(client.Authenticated && typeHasVal && typeVal != destType) {
		return nil, common.NewMessageFlowError(fmt.Sprintf("Not allowed to relay messages to 0x%x", dest))
	}

	// Validate source
	if client.Id != source {
		return nil, common.NewMessageFlowError(fmt.Sprintf("Identities do not match, expected 0x%x, got 0x%x", client.Id, source))
	}

	// Validate cookie
	if isToServer && client.SetCookieIn(cookie) != nil {
		return nil, errors.New(fmt.Sprintf("Invalid cookie: 0x%x", cookie))
	}

	// validate and increase csn
	if isToServer {
		csn, err := core.ParseCombinedSequenceNumber(csnBytes)
		if err != nil {
			return nil, err
		}
		if client.CombinedSequenceNumberIn == nil {
			if csn.GetOverflowNumber() != 0 {
				return nil, errors.New("Invalid overflow number. It must be initialized with zero")
			}
			client.CombinedSequenceNumberIn = csn
		} else {
			if client.CombinedSequenceNumberIn.HasErrOverflowSentinel() {
				return nil, common.NewMessageFlowError("Cannot receive any more messages, due to a sequence number counter overflow")
			}
			if !client.CombinedSequenceNumberIn.EqualsTo(csn) {
				return nil, errors.New("Received sequence number doesn't match with expected one")
			}
		}
		client.CombinedSequenceNumberIn.Increment()
	}
	var payload map[string]interface{}
	if destType == common.Server {
		payloadRecv := data[24:]
		decryptedPayload, err := decryptPayload(client, nonce, payloadRecv)
		decodeData := decryptedPayload
		if err != nil {
			decodeData = payloadRecv
		}
		payload, err = decodePayload(decodeData)
		if err != nil {
			return nil, errors.New("Payload cannot be decoded")
		}
		_type, ok := payload["type"]
		if !ok {
			return nil, errors.New("Payload doesn't have 'type' field")
		}

		switch _type {
		case "server-hello":
			keyVal, ok := payload["key"]
			if serverPk, err := naclutil.ConvertBoxPkToBytes(keyVal); err == nil {
				return NewServerHelloMessage(source, dest, serverPk), nil
			}
			return nil, errors.New("server-hello#key is invalid")
		case "client-hello":
			keyVal, _ := payload["key"]
			if clientPk, err := naclutil.ConvertBoxPkToBytes(keyVal); err == nil {
				return NewClientHelloMessage(source, dest, clientPk), nil
			}
			return nil, errors.New("client-hello#key is invalid")
		case "client-auth":
			yourCookieVal, ok := payload["your_cookie"]
			if !ok {
				return nil, errors.New("client-auth#your_cookie cannot be found")
			}
			yourCookie, err := msgutil.ParseYourCookie(yourCookieVal)
			if err != nil {
				return nil, errors.New("client-auth#your_cookie is invalid")
			}

			subprotocolsVal, ok := payload["subprotocols"]
			var subprotocols []string
			if ok {
				subprotocols, err = msgutil.ParseSubprotocols(subprotocolsVal)
				if err != nil {
					return nil, errors.New("client-auth#subprotocols is invalid")
				}
			}

			pingIntervalVal, ok := payload["ping_interval"]
			var pingInterval int
			if ok {
				pingInterval, err = msgutil.ParsePingInterval(pingIntervalVal)
				if err != nil {
					return nil, errors.New("client-auth#ping_interval is invalid")
				}
			}

			yourKeyVal, ok := payload["your_key"]
			var yourKey []byte
			if ok {
				yourKey, err = msgutil.ParseYourKey(yourKeyVal)
				if err != nil {
					return nil, errors.New("client-auth#your_key is invalid")
				}
			}
			return NewClientAuthMessage(source, dest, yourCookie, subprotocols, uint32(pingInterval), yourKey), nil
		case "new-initiator":
		case "new-responder":
		case "drop-responder":
		case "send-error":
		default:
			return nil, errors.New("Payload doesn't have valid 'type' field")
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

func encryptPayload(client *core.Client, nonce []byte, encodedPayload []byte) ([]byte, error) {
	var nonceArr [24]byte
	copy(nonceArr[:], nonce[:24])
	return box.Seal(nil, encodedPayload, &nonceArr, &client.ClientKey, &client.ServerSessionBox.Sk), nil
}

func decryptPayload(client *core.Client, nonce []byte, data []byte) ([]byte, error) {
	var nonceArr [24]byte
	copy(nonceArr[:], nonce[:24])
	decryptedData, ok := box.Open(nil, data, &nonceArr, &client.ClientKey, &client.ServerSessionBox.Sk)
	if !ok {
		return nil, errors.New("Could not decrypt payload")
	}
	return decryptedData, nil
}

func signKeys(c *core.Client, nonce []byte) []byte {
	var nonceArr [24]byte
	copy(nonceArr[:], nonce[:24])
	var buf bytes.Buffer
	buf.Write(c.ServerSessionBox.Pk[:])
	buf.Write(c.ClientKey[:])
	return box.Seal(nil, buf.Bytes(), &nonceArr, &c.ClientKey, &c.ServerPermanentBox.Sk)
}

type BaseMessagePacker interface {
	Pack(client *core.Client) ([]byte, error)
}

type BaseMessage interface {
	GetSource() common.AddressType
	SetSource(src common.AddressType)
	GetDestination() common.AddressType
	SetDestination(dst common.AddressType)
	GetSourceType() common.AddressType
	GetDestinationType() common.AddressType
}

// baseMessage //
type baseMessage struct {
	src  common.AddressType
	dest common.AddressType
}

// baseMessage //

// RawMessage //
type RawMessage struct {
	BaseMessage
	baseMessage
	data []byte
}

func NewRawMessage(src common.AddressType, dest common.AddressType, data []byte) *RawMessage {
	return &RawMessage{
		baseMessage: baseMessage{
			src:  src,
			dest: dest,
		},
		data: data,
	}
}

func (m *RawMessage) Pack(client *core.Client) ([]byte, error) {
	return m.data, nil
}

func (m *RawMessage) GetSource() common.AddressType {
	return m.src
}
func (m *RawMessage) SetSource(src common.AddressType) {
	m.src = src
}
func (m *RawMessage) GetDestination() common.AddressType {
	return m.dest
}
func (m *RawMessage) SetDestination(dst common.AddressType) {
	m.dest = dst
}
func (m *RawMessage) GetSourceType() common.AddressType {
	return common.GetAddressTypeFromaAddr(m.src)
}
func (m *RawMessage) GetDestinationType() common.AddressType {
	return common.GetAddressTypeFromaAddr(m.dest)
}

// RawMessage //

// ServerHelloMessage //
type ServerHelloMessage struct {
	baseMessage
	serverPublicKey []byte
}

func NewServerHelloMessage(src common.AddressType, dest common.AddressType, serverPublicKey []byte) *ServerHelloMessage {
	return &ServerHelloMessage{
		baseMessage: baseMessage{
			src:  src,
			dest: dest,
		},
		serverPublicKey: serverPublicKey,
	}
}

func (m *ServerHelloMessage) Pack(client *core.Client) ([]byte, error) {
	return Pack(client, m.src, m.dest, func(readNonce func() ([]byte, error)) ([]byte, error) {
		payload := map[string]interface{}{
			"type": []byte(common.ServerHello),
			"key":  m.serverPublicKey,
		}
		return encodePayload(payload)
	})
}

func (m *ServerHelloMessage) GetSource() common.AddressType {
	return m.src
}
func (m *ServerHelloMessage) SetSource(src common.AddressType) {
	m.src = src
}
func (m *ServerHelloMessage) GetDestination() common.AddressType {
	return m.dest
}
func (m *ServerHelloMessage) SetDestination(dst common.AddressType) {
	m.dest = dst
}
func (m *ServerHelloMessage) GetSourceType() common.AddressType {
	return common.GetAddressTypeFromaAddr(m.src)
}
func (m *ServerHelloMessage) GetDestinationType() common.AddressType {
	return common.GetAddressTypeFromaAddr(m.dest)
}

// ServerHelloMessage //

// ClientHelloMessage //
type ClientHelloMessage struct {
	baseMessage
	clientPublicKey []byte
}

func NewClientHelloMessage(src common.AddressType, dest common.AddressType, clientPublicKey []byte) *ClientHelloMessage {
	return &ClientHelloMessage{
		baseMessage: baseMessage{
			src:  src,
			dest: dest,
		},
		clientPublicKey: clientPublicKey,
	}
}

func (m *ClientHelloMessage) Pack(client *core.Client) ([]byte, error) {
	return Pack(client, m.src, m.dest, func(readNonce func() ([]byte, error)) ([]byte, error) {
		payload := map[string]interface{}{
			"type": []byte(common.ClientHello),
			"key":  m.clientPublicKey,
		}
		return encodePayload(payload)
	})
}

func (m *ClientHelloMessage) GetSource() common.AddressType {
	return m.src
}
func (m *ClientHelloMessage) SetSource(src common.AddressType) {
	m.src = src
}
func (m *ClientHelloMessage) GetDestination() common.AddressType {
	return m.dest
}
func (m *ClientHelloMessage) SetDestination(dst common.AddressType) {
	m.dest = dst
}
func (m *ClientHelloMessage) GetSourceType() common.AddressType {
	return common.GetAddressTypeFromaAddr(m.src)
}
func (m *ClientHelloMessage) GetDestinationType() common.AddressType {
	return common.GetAddressTypeFromaAddr(m.dest)
}

// ClientHelloMessage //

// ClientAuthMessage //
type ClientAuthMessage struct {
	baseMessage
	serverCookie []byte
	subprotocols []string
	pingInterval uint32
	serverKey    []byte
}

func NewClientAuthMessage(src common.AddressType, dest common.AddressType, serverCookie []byte,
	subprotocols []string, pingInterval uint32, serverKey []byte) *ClientAuthMessage {
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

func (m *ClientAuthMessage) Pack(client *core.Client) ([]byte, error) {
	if !client.Authenticated {
		return nil, common.NewMessageFlowError("Cannot encrypt payload")
	}
	return Pack(client, m.src, m.dest, func(readNonce func() ([]byte, error)) ([]byte, error) {
		payload := map[string]interface{}{
			"type":          common.ClientAuth,
			"your_cookie":   m.serverCookie,
			"subprotocols":  m.subprotocols,
			"ping_interval": m.pingInterval,
		}
		if m.serverKey != nil {
			payload["your_key"] = m.serverKey
		}
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

func (m *ClientAuthMessage) GetSource() common.AddressType {
	return m.src
}
func (m *ClientAuthMessage) SetSource(src common.AddressType) {
	m.src = src
}
func (m *ClientAuthMessage) GetDestination() common.AddressType {
	return m.dest
}
func (m *ClientAuthMessage) SetDestination(dst common.AddressType) {
	m.dest = dst
}
func (m *ClientAuthMessage) GetSourceType() common.AddressType {
	return common.GetAddressTypeFromaAddr(m.src)
}
func (m *ClientAuthMessage) GetDestinationType() common.AddressType {
	return common.GetAddressTypeFromaAddr(m.dest)
}

// ClientAuthMessage //

// ServerAuthMessage //
type ServerAuthMessage struct {
	baseMessage
	clientCookie       []byte
	signKeys           bool
	initiatorConnected bool
	responderIds       []common.AddressType
	towardsInitiator   bool
}

func NewServerAuthMessageForInitiator(src common.AddressType, dest common.AddressType, clientCookie []byte,
	signKeys bool, responderIds []common.AddressType) *ServerAuthMessage {
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

func NewServerAuthMessageForResponder(src common.AddressType, dest common.AddressType, clientCookie []byte,
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

func (m *ServerAuthMessage) Pack(client *core.Client) ([]byte, error) {
	return Pack(client, m.src, m.dest, func(readNonce func() ([]byte, error)) ([]byte, error) {
		payload := map[string]interface{}{
			"type":        common.ServerAuth,
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

func (m *ServerAuthMessage) GetSource() common.AddressType {
	return m.src
}
func (m *ServerAuthMessage) SetSource(src common.AddressType) {
	m.src = src
}
func (m *ServerAuthMessage) GetDestination() common.AddressType {
	return m.dest
}
func (m *ServerAuthMessage) SetDestination(dst common.AddressType) {
	m.dest = dst
}
func (m *ServerAuthMessage) GetSourceType() common.AddressType {
	return common.GetAddressTypeFromaAddr(m.src)
}
func (m *ServerAuthMessage) GetDestinationType() common.AddressType {
	return common.GetAddressTypeFromaAddr(m.dest)
}

// ServerAuthMessage //

// NewInitiatorMessage //
type NewInitiatorMessage struct {
	baseMessage
}

func NewNewInitiatorMessage(src common.AddressType, dest common.AddressType) *NewInitiatorMessage {
	return &NewInitiatorMessage{
		baseMessage: baseMessage{
			src:  src,
			dest: dest,
		},
	}
}

func (m *NewInitiatorMessage) Pack(client *core.Client) ([]byte, error) {
	return Pack(client, m.src, m.dest, func(readNonce func() ([]byte, error)) ([]byte, error) {
		payload := map[string]interface{}{
			"type": common.NewInitiator,
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

func (m *NewInitiatorMessage) GetSource() common.AddressType {
	return m.src
}
func (m *NewInitiatorMessage) SetSource(src common.AddressType) {
	m.src = src
}
func (m *NewInitiatorMessage) GetDestination() common.AddressType {
	return m.dest
}
func (m *NewInitiatorMessage) SetDestination(dst common.AddressType) {
	m.dest = dst
}
func (m *NewInitiatorMessage) GetSourceType() common.AddressType {
	return common.GetAddressTypeFromaAddr(m.src)
}
func (m *NewInitiatorMessage) GetDestinationType() common.AddressType {
	return common.GetAddressTypeFromaAddr(m.dest)
}

// NewInitiatorMessage //

// NewResponderMessage //
type NewResponderMessage struct {
	baseMessage
	responderId common.AddressType
}

func NewNewResponderMessage(src common.AddressType, dest common.AddressType, responderId common.AddressType) *NewResponderMessage {
	return &NewResponderMessage{
		baseMessage: baseMessage{
			src:  src,
			dest: dest,
		},
		responderId: responderId,
	}
}

func (m *NewResponderMessage) Pack(client *core.Client) ([]byte, error) {
	return Pack(client, m.src, m.dest, func(readNonce func() ([]byte, error)) ([]byte, error) {
		payload := map[string]interface{}{
			"type": common.NewResponder,
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

func (m *NewResponderMessage) GetSource() common.AddressType {
	return m.src
}
func (m *NewResponderMessage) SetSource(src common.AddressType) {
	m.src = src
}
func (m *NewResponderMessage) GetDestination() common.AddressType {
	return m.dest
}
func (m *NewResponderMessage) SetDestination(dst common.AddressType) {
	m.dest = dst
}
func (m *NewResponderMessage) GetSourceType() common.AddressType {
	return common.GetAddressTypeFromaAddr(m.src)
}
func (m *NewResponderMessage) GetDestinationType() common.AddressType {
	return common.GetAddressTypeFromaAddr(m.dest)
}

// NewResponderMessage //

// DropResponderMessage //
type DropResponderMessage struct {
	baseMessage
	responderId common.AddressType
	reason      int
}

func NewDropResponderMessage(src common.AddressType, dest common.AddressType, responderId common.AddressType) *DropResponderMessage {
	return NewDropResponderMessageWithReason(src, dest, responderId, common.CloseCodeDropByInitiator)
}

func NewDropResponderMessageWithReason(src common.AddressType, dest common.AddressType, responderId common.AddressType, reason int) *DropResponderMessage {
	return &DropResponderMessage{
		baseMessage: baseMessage{
			src:  src,
			dest: dest,
		},
		responderId: responderId,
		reason:      reason,
	}
}

func (m *DropResponderMessage) Pack(client *core.Client) ([]byte, error) {
	return Pack(client, m.src, m.dest, func(readNonce func() ([]byte, error)) ([]byte, error) {
		payload := map[string]interface{}{
			"type":   common.DropResponder,
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

func (m *DropResponderMessage) GetSource() common.AddressType {
	return m.src
}
func (m *DropResponderMessage) SetSource(src common.AddressType) {
	m.src = src
}
func (m *DropResponderMessage) GetDestination() common.AddressType {
	return m.dest
}
func (m *DropResponderMessage) SetDestination(dst common.AddressType) {
	m.dest = dst
}
func (m *DropResponderMessage) GetSourceType() common.AddressType {
	return common.GetAddressTypeFromaAddr(m.src)
}
func (m *DropResponderMessage) GetDestinationType() common.AddressType {
	return common.GetAddressTypeFromaAddr(m.dest)
}

// DropResponderMessage //

// SendErrorMessage //
type SendErrorMessage struct {
	baseMessage
	messageId []byte
}

func NewSendErrorMessage(src common.AddressType, dest common.AddressType, messageId []byte) *SendErrorMessage {
	return &SendErrorMessage{
		baseMessage: baseMessage{
			src:  src,
			dest: dest,
		},
		messageId: messageId,
	}
}

func (m *SendErrorMessage) Pack(client *core.Client) ([]byte, error) {
	return Pack(client, m.src, m.dest, func(readNonce func() ([]byte, error)) ([]byte, error) {
		payload := map[string]interface{}{
			"type": common.SendError,
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

func (m *SendErrorMessage) GetSource() common.AddressType {
	return m.src
}
func (m *SendErrorMessage) SetSource(src common.AddressType) {
	m.src = src
}
func (m *SendErrorMessage) GetDestination() common.AddressType {
	return m.dest
}
func (m *SendErrorMessage) SetDestination(dst common.AddressType) {
	m.dest = dst
}
func (m *SendErrorMessage) GetSourceType() common.AddressType {
	return common.GetAddressTypeFromaAddr(m.src)
}
func (m *SendErrorMessage) GetDestinationType() common.AddressType {
	return common.GetAddressTypeFromaAddr(m.dest)
}

// SendErrorMessage //

// DisconnectedMessage //
type DisconnectedMessage struct {
	baseMessage
	clientId []byte
}

func NewDisconnectedMessage(src common.AddressType, dest common.AddressType, clientId []byte) *DisconnectedMessage {
	return &DisconnectedMessage{
		baseMessage: baseMessage{
			src:  src,
			dest: dest,
		},
		clientId: clientId,
	}
}

func (m *DisconnectedMessage) Pack(client *core.Client) ([]byte, error) {
	return Pack(client, m.src, m.dest, func(readNonce func() ([]byte, error)) ([]byte, error) {
		payload := map[string]interface{}{
			"type": common.Disconnected,
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

func (m *DisconnectedMessage) GetSource() common.AddressType {
	return m.src
}
func (m *DisconnectedMessage) SetSource(src common.AddressType) {
	m.src = src
}
func (m *DisconnectedMessage) GetDestination() common.AddressType {
	return m.dest
}
func (m *DisconnectedMessage) SetDestination(dst common.AddressType) {
	m.dest = dst
}
func (m *DisconnectedMessage) GetSourceType() common.AddressType {
	return common.GetAddressTypeFromaAddr(m.src)
}
func (m *DisconnectedMessage) GetDestinationType() common.AddressType {
	return common.GetAddressTypeFromaAddr(m.dest)
}

// DisconnectedMessage //
