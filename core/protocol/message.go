package protocol

import (
	"github.com/OguzhanE/saltyrtc-server-go/pkg/base"
	"github.com/OguzhanE/saltyrtc-server-go/pkg/crypto/nacl"
)

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
		Type base.MessageType `codec:"type"`
		Key  []byte           `codec:"key"`
	}{
		Type: base.ClientHello,
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
		Type base.MessageType `codec:"type"`
		Key  []byte           `codec:"key"`
	}{
		Type: base.ServerHello,
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
	ServerKey    [base.KeyBytesSize]byte

	EncodingOpts struct {
		ClientKey       [base.KeyBytesSize]byte
		ServerSessionSk [base.KeyBytesSize]byte
		Nonce           []byte
	}
}

// NewClientAuthMessage ..
func NewClientAuthMessage(src AddressType, dest AddressType, serverCookie []byte,
	subprotocols []string, pingInterval uint32, serverKey [base.KeyBytesSize]byte) *ClientAuthMessage {
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
		Type         base.MessageType `codec:"type"`
		YourCookie   []byte           `codec:"your_cookie"`
		Subprotocols []string         `codec:"subprotocols"`
		PingInterval uint32           `codec:"ping_interval"`
		YourKey      [32]byte         `codec:"your_key"`
	}{
		Type:         base.ClientAuth,
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

	EncodingOpts struct {
		ServerPermanentSk [nacl.NaclKeyBytesSize]byte
		ClientKey         [nacl.NaclKeyBytesSize]byte
		ServerSessionSk   [nacl.NaclKeyBytesSize]byte
		ServerSessionPk   [nacl.NaclKeyBytesSize]byte
		Nonce             []byte
	}
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
				Type               base.MessageType `codec:"type"`
				YourCookie         []byte           `codec:"your_cookie"`
				InitiatorConnected bool             `codec:"initiator_connected"`
				SignedKeys         []byte           `codec:"signed_keys"`
			}{
				Type:               base.ServerAuth,
				YourCookie:         m.clientCookie,
				InitiatorConnected: m.initiatorConnected,
				SignedKeys:         SignKeys(m.EncodingOpts.ClientKey, m.EncodingOpts.ServerSessionPk, m.EncodingOpts.ServerPermanentSk, m.EncodingOpts.Nonce),
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

		responderArr := make([]uint16, len(m.responderIds))
		for i, v := range m.responderIds {
			responderArr[i] = uint16(v)
		}

		if m.signKeys {
			payload = struct {
				Type       base.MessageType `codec:"type"`
				YourCookie []byte           `codec:"your_cookie"`
				Responders []uint16         `codec:"responders"`
				SignedKeys []byte           `codec:"signed_keys"`
			}{
				Type:       base.ServerAuth,
				YourCookie: m.clientCookie,
				Responders: responderArr,
				SignedKeys: SignKeys(m.EncodingOpts.ClientKey, m.EncodingOpts.ServerSessionPk, m.EncodingOpts.ServerPermanentSk, m.EncodingOpts.Nonce),
			}
		} else {
			payload = struct {
				Type       base.MessageType `codec:"type"`
				YourCookie []byte           `codec:"your_cookie"`
				Responders []uint16         `codec:"responders"`
			}{
				Type:       base.ServerAuth,
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

	clientKey       [base.KeyBytesSize]byte
	serverSessionSk [base.KeyBytesSize]byte

	EncodingOpts struct {
		ClientKey       [base.KeyBytesSize]byte
		ServerSessionSk [base.KeyBytesSize]byte
		Nonce           []byte
	}
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
		Type base.MessageType `codec:"type"`
	}{
		Type: base.NewInitiator,
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
	responderId AddressType

	EncodingOpts struct {
		ClientKey       [base.KeyBytesSize]byte
		ServerSessionSk [base.KeyBytesSize]byte
		Nonce           []byte
	}
}

// NewNewResponderMessage ..
func NewNewResponderMessage(src AddressType, dest AddressType, responderId AddressType) *NewResponderMessage {
	msg := &NewResponderMessage{
		BaseMessage: BaseMessage{
			Src:  src,
			Dest: dest,
		},
		responderId: responderId,
	}
	return msg
}

// MarshalPayload ..
func (m *NewResponderMessage) MarshalPayload() ([]byte, error) {
	payload := struct {
		Type base.MessageType `codec:"type"`
		Id   uint8            `codec:"id"`
	}{
		Type: base.NewResponder,
		Id:   m.responderId,
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
	ResponderId AddressType
	Reason      int

	EncodingOpts struct {
		ClientKey       [base.KeyBytesSize]byte
		ServerSessionSk [base.KeyBytesSize]byte
		Nonce           []byte
	}
}

// NewDropResponderMessage ..
func NewDropResponderMessage(src AddressType, dest AddressType, responderId AddressType) *DropResponderMessage {
	return NewDropResponderMessageWithReason(src, dest, responderId, base.CloseCodeDropByInitiator)
}

// NewDropResponderMessageWithReason ..
func NewDropResponderMessageWithReason(src AddressType, dest AddressType, responderId AddressType, reason int) *DropResponderMessage {
	msg := &DropResponderMessage{
		BaseMessage: BaseMessage{
			Src:  src,
			Dest: dest,
		},
		ResponderId: responderId,
		Reason:      reason,
	}
	return msg
}

func (m *DropResponderMessage) MarshalPayload() ([]byte, error) {
	payload := struct {
		Type   base.MessageType `codec:"type"`
		Id     uint8            `codec:"id"`
		Reason int              `codec:"reason"`
	}{
		Type:   base.DropResponder,
		Id:     m.ResponderId,
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
	clientId []byte

	EncodingOpts struct {
		ClientKey       [base.KeyBytesSize]byte
		ServerSessionSk [base.KeyBytesSize]byte
		Nonce           []byte
	}
}

// NewDisconnectedMessage ..
func NewDisconnectedMessage(src AddressType, dest AddressType, clientId []byte) *DisconnectedMessage {
	msg := &DisconnectedMessage{
		BaseMessage: BaseMessage{
			Src:  src,
			Dest: dest,
		},
		clientId: clientId,
	}
	return msg
}

// MarshalPayload ..
func (m *DisconnectedMessage) MarshalPayload() ([]byte, error) {

	payload := struct {
		Type base.MessageType `codec:"type"`
		Id   []byte           `codec:"id"`
	}{
		Type: base.Disconnected,
		Id:   m.clientId,
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
	clientKey       [base.KeyBytesSize]byte
	serverSessionSk [base.KeyBytesSize]byte
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

	encryptedPayload, err := EncryptPayload(m.clientKey, m.serverSessionSk, nonce, encodedPayload)
	return encryptedPayload, err
}
*/
// SendErrorMessage //
