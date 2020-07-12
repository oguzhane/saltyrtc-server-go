package protocol

import (
	"github.com/OguzhanE/saltyrtc-server-go/pkg/crypto/nacl"
)

// MessageType is used to represent type of a message
type MessageType = string

const (
	// ServerHello ..
	ServerHello MessageType = "server-hello"
	// ClientHello ..
	ClientHello MessageType = "client-hello"
	// ClientAuth ..
	ClientAuth MessageType = "client-auth"
	// ServerAuth ..
	ServerAuth MessageType = "server-auth"
	// NewResponder ..
	NewResponder MessageType = "new-responder"
	// NewInitiator ..
	NewInitiator MessageType = "new-initiator"
	// DropResponder ..
	DropResponder MessageType = "drop-responder"
	// SendError ..
	SendError MessageType = "send-error"
	// Disconnected ..
	Disconnected MessageType = "disconnected"
)

type BasicEncodingOpts struct {
	ClientKey       [32]byte
	ServerSessionSk [32]byte
	Nonce           []byte
}

type ServerAuthEncodingOpts struct {
	ServerPermanentSk [nacl.NaclKeyBytesSize]byte
	ClientKey         [nacl.NaclKeyBytesSize]byte
	ServerSessionSk   [nacl.NaclKeyBytesSize]byte
	ServerSessionPk   [nacl.NaclKeyBytesSize]byte
	Nonce             []byte
}

// BaseMessage //
type BaseMessage struct {
	Src  AddressType
	Dest AddressType
}

// BaseMessage //

// ClientHelloMessage //
type ClientHelloMessage struct {
	BaseMessage
	ClientPublicKey []byte
}

// NewClientHelloMessage ..
func NewClientHelloMessage(src AddressType, dest AddressType, clientPublicKey []byte) *ClientHelloMessage {
	return &ClientHelloMessage{
		BaseMessage: BaseMessage{
			Src:  src,
			Dest: dest,
		},
		ClientPublicKey: clientPublicKey,
	}
}

// MarshalPayload ..
func (m *ClientHelloMessage) MarshalPayload() ([]byte, error) {
	payload := struct {
		Type MessageType `codec:"type"`
		Key  []byte      `codec:"key"`
	}{
		Type: ClientHello,
		Key:  m.ClientPublicKey,
	}
	return EncodePayload(payload)
}

// ClientHelloMessage //

// RawMessage //
type RawMessage struct {
	BaseMessage
	Data []byte
}

// NewRawMessage ..
func NewRawMessage(src AddressType, dest AddressType, data []byte) *RawMessage {
	return &RawMessage{
		BaseMessage: BaseMessage{
			Src:  src,
			Dest: dest,
		},
		Data: data,
	}
}

// MarshalPayload ..
func (m *RawMessage) MarshalPayload() ([]byte, error) {
	return m.Data, nil
}

// RawMessage //

// ServerHelloMessage //
type ServerHelloMessage struct {
	BaseMessage
	serverPublicKey []byte
}

// NewServerHelloMessage ..
func NewServerHelloMessage(src AddressType, dest AddressType, serverPublicKey []byte) *ServerHelloMessage {
	return &ServerHelloMessage{
		BaseMessage: BaseMessage{
			Src:  src,
			Dest: dest,
		},
		serverPublicKey: serverPublicKey,
	}
}

// MarshalPayload ..
func (m *ServerHelloMessage) MarshalPayload() ([]byte, error) {
	payload := struct {
		Type MessageType `codec:"type"`
		Key  []byte      `codec:"key"`
	}{
		Type: ServerHello,
		Key:  m.serverPublicKey,
	}
	return EncodePayload(payload)
}

// ServerHelloMessage //

// ClientAuthMessage //
type ClientAuthMessage struct {
	BaseMessage
	ServerCookie []byte
	Subprotocols []string
	PingInterval uint32
	ServerKey    [KeyBytesSize]byte

	EncodingOpts BasicEncodingOpts
}

// NewClientAuthMessage ..
func NewClientAuthMessage(src AddressType, dest AddressType, serverCookie []byte,
	subprotocols []string, pingInterval uint32, serverKey [KeyBytesSize]byte) *ClientAuthMessage {
	msg := &ClientAuthMessage{
		BaseMessage: BaseMessage{
			Src:  src,
			Dest: dest,
		},
		ServerCookie: serverCookie,
		Subprotocols: subprotocols,
		PingInterval: pingInterval,
		ServerKey:    serverKey,
	}

	return msg
}

// MarshalPayload ..
func (m *ClientAuthMessage) MarshalPayload() ([]byte, error) {
	payload := struct {
		Type         MessageType `codec:"type"`
		YourCookie   []byte      `codec:"your_cookie"`
		Subprotocols []string    `codec:"subprotocols"`
		PingInterval uint32      `codec:"ping_interval"`
		YourKey      [32]byte    `codec:"your_key"`
	}{
		Type:         ClientAuth,
		YourCookie:   m.ServerCookie,
		Subprotocols: m.Subprotocols,
		PingInterval: m.PingInterval,
		YourKey:      m.ServerKey,
	}
	encodedPayload, err := EncodePayload(payload)
	if err != nil {
		return nil, err
	}

	encryptedPayload, err := EncryptPayload(m.EncodingOpts.ClientKey, m.EncodingOpts.ServerSessionSk, m.EncodingOpts.Nonce, encodedPayload)
	return encryptedPayload, err
}

// ClientAuthMessage //

// ServerAuthMessage //
type ServerAuthMessage struct {
	BaseMessage
	clientCookie       []byte
	signKeys           bool
	initiatorConnected bool
	responderIds       []AddressType
	towardsInitiator   bool

	EncodingOpts ServerAuthEncodingOpts
}

// NewServerAuthMessageForInitiator ..
func NewServerAuthMessageForInitiator(src AddressType, dest AddressType, clientCookie []byte,
	signKeys bool, responderIds []AddressType) *ServerAuthMessage {
	msg := &ServerAuthMessage{
		BaseMessage: BaseMessage{
			Src:  src,
			Dest: dest,
		},
		clientCookie:     clientCookie,
		signKeys:         signKeys,
		responderIds:     responderIds,
		towardsInitiator: true,
	}
	return msg
}

// NewServerAuthMessageForResponder ..
func NewServerAuthMessageForResponder(src AddressType, dest AddressType, clientCookie []byte,
	signKeys bool, initiatorConnected bool) *ServerAuthMessage {
	msg := &ServerAuthMessage{
		BaseMessage: BaseMessage{
			Src:  src,
			Dest: dest,
		},
		clientCookie:       clientCookie,
		signKeys:           signKeys,
		initiatorConnected: initiatorConnected,
		towardsInitiator:   false,
	}
	return msg
}

// MarshalPayload ...
func (m ServerAuthMessage) MarshalPayload() ([]byte, error) {
	var payload interface{}

	if !m.towardsInitiator {
		if m.signKeys {
			payload = struct {
				Type               MessageType `codec:"type"`
				YourCookie         []byte      `codec:"your_cookie"`
				InitiatorConnected bool        `codec:"initiator_connected"`
				SignedKeys         []byte      `codec:"signed_keys"`
			}{
				Type:               ServerAuth,
				YourCookie:         m.clientCookie,
				InitiatorConnected: m.initiatorConnected,
				SignedKeys:         SignKeys(m.EncodingOpts.ClientKey, m.EncodingOpts.ServerSessionPk, m.EncodingOpts.ServerPermanentSk, m.EncodingOpts.Nonce),
			}
		} else {
			payload = struct {
				Type               MessageType `codec:"type"`
				YourCookie         []byte      `codec:"your_cookie"`
				InitiatorConnected bool        `codec:"initiator_connected"`
			}{
				Type:               ServerAuth,
				YourCookie:         m.clientCookie,
				InitiatorConnected: m.initiatorConnected,
			}
		}
	} else {

		responderArr := make([]uint16, len(m.responderIds))
		for i, v := range m.responderIds {
			responderArr[i] = uint16(v)
		}

		if m.signKeys {
			payload = struct {
				Type       MessageType `codec:"type"`
				YourCookie []byte      `codec:"your_cookie"`
				Responders []uint16    `codec:"responders"`
				SignedKeys []byte      `codec:"signed_keys"`
			}{
				Type:       ServerAuth,
				YourCookie: m.clientCookie,
				Responders: responderArr,
				SignedKeys: SignKeys(m.EncodingOpts.ClientKey, m.EncodingOpts.ServerSessionPk, m.EncodingOpts.ServerPermanentSk, m.EncodingOpts.Nonce),
			}
		} else {
			payload = struct {
				Type       MessageType `codec:"type"`
				YourCookie []byte      `codec:"your_cookie"`
				Responders []uint16    `codec:"responders"`
			}{
				Type:       ServerAuth,
				YourCookie: m.clientCookie,
				Responders: responderArr,
			}
		}
	}

	encodedPayload, err := EncodePayload(payload)
	if err != nil {
		return nil, err
	}

	encryptedPayload, err := EncryptPayload(m.EncodingOpts.ClientKey, m.EncodingOpts.ServerSessionSk, m.EncodingOpts.Nonce, encodedPayload)
	return encryptedPayload, err
}

// ServerAuthMessage //

// NewInitiatorMessage //
type NewInitiatorMessage struct {
	BaseMessage

	clientKey       [KeyBytesSize]byte
	serverSessionSk [KeyBytesSize]byte

	EncodingOpts BasicEncodingOpts
}

// NewNewInitiatorMessage ..
func NewNewInitiatorMessage(src AddressType, dest AddressType) *NewInitiatorMessage {
	msg := &NewInitiatorMessage{
		BaseMessage: BaseMessage{
			Src:  src,
			Dest: dest,
		},
	}

	return msg
}

// MarshalPayload ..
func (m *NewInitiatorMessage) MarshalPayload() ([]byte, error) {
	payload := struct {
		Type MessageType `codec:"type"`
	}{
		Type: NewInitiator,
	}

	encodedPayload, err := EncodePayload(payload)
	if err != nil {
		return nil, err
	}

	encryptedPayload, err := EncryptPayload(m.EncodingOpts.ClientKey, m.EncodingOpts.ServerSessionSk, m.EncodingOpts.Nonce, encodedPayload)
	return encryptedPayload, err
}

// NewInitiatorMessage //

// NewResponderMessage //
type NewResponderMessage struct {
	BaseMessage
	responderID AddressType

	EncodingOpts BasicEncodingOpts
}

// NewNewResponderMessage ..
func NewNewResponderMessage(src AddressType, dest AddressType, responderID AddressType) *NewResponderMessage {
	msg := &NewResponderMessage{
		BaseMessage: BaseMessage{
			Src:  src,
			Dest: dest,
		},
		responderID: responderID,
	}
	return msg
}

// MarshalPayload ..
func (m *NewResponderMessage) MarshalPayload() ([]byte, error) {
	payload := struct {
		Type MessageType `codec:"type"`
		ID   uint8       `codec:"id"`
	}{
		Type: NewResponder,
		ID:   m.responderID,
	}

	encodedPayload, err := EncodePayload(payload)
	if err != nil {
		return nil, err
	}

	encryptedPayload, err := EncryptPayload(m.EncodingOpts.ClientKey, m.EncodingOpts.ServerSessionSk, m.EncodingOpts.Nonce, encodedPayload)
	return encryptedPayload, err
}

// NewResponderMessage //

// DropResponderMessage //
type DropResponderMessage struct {
	BaseMessage
	ResponderID AddressType
	Reason      int

	EncodingOpts BasicEncodingOpts
}

// NewDropResponderMessage ..
func NewDropResponderMessage(src AddressType, dest AddressType, responderID AddressType) *DropResponderMessage {
	return NewDropResponderMessageWithReason(src, dest, responderID, CloseCodeDropByInitiator)
}

// NewDropResponderMessageWithReason ..
func NewDropResponderMessageWithReason(src AddressType, dest AddressType, responderID AddressType, reason int) *DropResponderMessage {
	msg := &DropResponderMessage{
		BaseMessage: BaseMessage{
			Src:  src,
			Dest: dest,
		},
		ResponderID: responderID,
		Reason:      reason,
	}
	return msg
}

// MarshalPayload returns the bytes encoding of m
func (m *DropResponderMessage) MarshalPayload() ([]byte, error) {
	payload := struct {
		Type   MessageType `codec:"type"`
		ID     uint8       `codec:"id"`
		Reason int         `codec:"reason"`
	}{
		Type:   DropResponder,
		ID:     m.ResponderID,
		Reason: m.Reason,
	}

	encodedPayload, err := EncodePayload(payload)
	if err != nil {
		return nil, err
	}

	encryptedPayload, err := EncryptPayload(m.EncodingOpts.ClientKey, m.EncodingOpts.ServerSessionSk, m.EncodingOpts.Nonce, encodedPayload)
	return encryptedPayload, err
}

// DropResponderMessage //

// DisconnectedMessage //
type DisconnectedMessage struct {
	BaseMessage
	clientID AddressType

	EncodingOpts BasicEncodingOpts
}

// NewDisconnectedMessage ..
func NewDisconnectedMessage(src AddressType, dest AddressType, clientID AddressType) *DisconnectedMessage {
	msg := &DisconnectedMessage{
		BaseMessage: BaseMessage{
			Src:  src,
			Dest: dest,
		},
		clientID: clientID,
	}
	return msg
}

// MarshalPayload ..
func (m *DisconnectedMessage) MarshalPayload() ([]byte, error) {

	payload := struct {
		Type MessageType `codec:"type"`
		ID   uint8       `codec:"id"`
	}{
		Type: Disconnected,
		ID:   m.clientID,
	}

	encodedPayload, err := EncodePayload(payload)
	if err != nil {
		return nil, err
	}

	encryptedPayload, err := EncryptPayload(m.EncodingOpts.ClientKey, m.EncodingOpts.ServerSessionSk, m.EncodingOpts.Nonce, encodedPayload)
	return encryptedPayload, err
}

// DisconnectedMessage //

// SendErrorMessage //
/*
type SendErrorMessage struct {
	BaseMessage
	messageId       []byte
	clientKey       [KeyBytesSize]byte
	serverSessionSk [KeyBytesSize]byte
}

// NewSendErrorMessage ..
func NewSendErrorMessage(src AddressType, dest AddressType, messageId []byte, opts ...func(*SendErrorMessage)) *SendErrorMessage {
	msg := &SendErrorMessage{
		BaseMessage: BaseMessage{
			src:  src,
			dest: dest,
		},
		messageId: messageId,
	}
	for _, opt := range opts {
		opt(msg)
	}
	return msg
}

// Pack ..
func (m *SendErrorMessage) Pack(nonceReader NonceReader) ([]byte, error) {
	payload := struct {
		Type MessageType `codec:"type"`
		Id   []byte           `codec:"id"`
	}{
		Type: SendError,
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

	encryptedPayload, err := EncryptPayload(m.clientKey, m.serverSessionSk, nonce, encodedPayload)
	return encryptedPayload, err
}
*/
// SendErrorMessage //
