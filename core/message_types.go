package core

import (
	"github.com/OguzhanE/saltyrtc-server-go/pkg/base"
	"github.com/OguzhanE/saltyrtc-server-go/pkg/crypto/nacl"
)

// CookieGetter ..
type CookieGetter interface {
	Cookie() ([]byte, error)
}

// LazyCookieWriter ..
type LazyCookieWriter interface {
	MakeCookieWriter(cookie []byte) (Do func(), err error)
}

// CsnGetter ..
type CsnGetter interface {
	Csn() *CombinedSequenceNumber
}

// CsnReceiver ..
type CsnReceiver interface {
	ReceiveCsn(csn *CombinedSequenceNumber)
}

// NoncePacker ..
type NoncePacker interface {
	Src() base.AddressType
	Dest() base.AddressType
	CsnGetter
	CookieGetter
}

// NonceUnpacker ..
type NonceUnpacker interface {
	Type() (base.AddressType, bool)
	Authenticated() bool
	Id() base.AddressType
	ClientKey() [nacl.NaclKeyBytesSize]byte
	ServerSessionSk() [nacl.NaclKeyBytesSize]byte
	CsnGetter
	CsnReceiver
	LazyCookieWriter
}

// BaseMessage //
type BaseMessage struct {
	src  base.AddressType
	dest base.AddressType
}

// BaseMessage //

// ClientHelloMessage //
type ClientHelloMessage struct {
	BaseMessage
	clientPublicKey []byte
}

// NewClientHelloMessage ..
func NewClientHelloMessage(src base.AddressType, dest base.AddressType, clientPublicKey []byte) *ClientHelloMessage {
	return &ClientHelloMessage{
		BaseMessage: BaseMessage{
			src:  src,
			dest: dest,
		},
		clientPublicKey: clientPublicKey,
	}
}

// Pack ..
func (m *ClientHelloMessage) Pack(nonceReader NonceReader) ([]byte, error) {
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

// RawMessage //
type RawMessage struct {
	BaseMessage
	data []byte
	PayloadPacker
}

// NewRawMessage ..
func NewRawMessage(src base.AddressType, dest base.AddressType, data []byte) *RawMessage {
	return &RawMessage{
		BaseMessage: BaseMessage{
			src:  src,
			dest: dest,
		},
		data: data,
	}
}

// Pack ..
func (m *RawMessage) Pack(nonceReader *NonceReader) ([]byte, error) {
	return m.data, nil
}

// RawMessage //

// ServerHelloMessage //
type ServerHelloMessage struct {
	BaseMessage
	PayloadPacker
	serverPublicKey []byte
}

// NewServerHelloMessage ..
func NewServerHelloMessage(src base.AddressType, dest base.AddressType, serverPublicKey []byte) *ServerHelloMessage {
	return &ServerHelloMessage{
		BaseMessage: BaseMessage{
			src:  src,
			dest: dest,
		},
		serverPublicKey: serverPublicKey,
	}
}

// Pack ..
func (m *ServerHelloMessage) Pack(nonceReader NonceReader) ([]byte, error) {
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

// ClientAuthMessage //
type ClientAuthMessage struct {
	BaseMessage
	serverCookie    []byte
	subprotocols    []string
	pingInterval    uint32
	serverKey       [base.KeyBytesSize]byte
	clientKey       [base.KeyBytesSize]byte
	serverSessionSk [base.KeyBytesSize]byte
}

// NewClientAuthMessage ..
func NewClientAuthMessage(src base.AddressType, dest base.AddressType, serverCookie []byte,
	subprotocols []string, pingInterval uint32, serverKey [base.KeyBytesSize]byte, opts ...func(*ClientAuthMessage)) *ClientAuthMessage {
	msg := &ClientAuthMessage{
		BaseMessage: BaseMessage{
			src:  src,
			dest: dest,
		},
		serverCookie: serverCookie,
		subprotocols: subprotocols,
		pingInterval: pingInterval,
		serverKey:    serverKey,
	}
	for _, opt := range opts {
		opt(msg)
	}
	return msg
}

// Pack ..
func (m *ClientAuthMessage) Pack(nonceReader NonceReader) ([]byte, error) {
	// if !client.Authenticated {
	// 	return nil, base.NewMessageFlowError("Cannot encrypt payload", ErrNotAuthenticatedClient)
	// }
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
	encryptedPayload, err := encryptPayload(m.clientKey, m.serverSessionSk, nonce, encodedPayload)
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
	serverPermanentSk  [nacl.NaclKeyBytesSize]byte
	clientKey          [nacl.NaclKeyBytesSize]byte
	serverSessionSk    [nacl.NaclKeyBytesSize]byte
	serverSessionPk    [nacl.NaclKeyBytesSize]byte
}

// NewServerAuthMessageForInitiator ..
func NewServerAuthMessageForInitiator(src base.AddressType, dest base.AddressType, clientCookie []byte,
	signKeys bool, responderIds []base.AddressType, opts ...func(*ServerAuthMessage)) *ServerAuthMessage {
	msg := &ServerAuthMessage{
		BaseMessage: BaseMessage{
			src:  src,
			dest: dest,
		},
		clientCookie:     clientCookie,
		signKeys:         signKeys,
		responderIds:     responderIds,
		towardsInitiator: true,
	}
	for _, opt := range opts {
		opt(msg)
	}
	return msg
}

// NewServerAuthMessageForResponder ..
func NewServerAuthMessageForResponder(src base.AddressType, dest base.AddressType, clientCookie []byte,
	signKeys bool, initiatorConnected bool, opts ...func(*ServerAuthMessage)) *ServerAuthMessage {
	msg := &ServerAuthMessage{
		BaseMessage: BaseMessage{
			src:  src,
			dest: dest,
		},
		clientCookie:       clientCookie,
		signKeys:           signKeys,
		initiatorConnected: initiatorConnected,
		towardsInitiator:   false,
	}
	for _, opt := range opts {
		opt(msg)
	}
	return msg
}

// Pack ..
func (m *ServerAuthMessage) Pack(nonceReader NonceReader) ([]byte, error) {
	var payload interface{}
	nonce, err := nonceReader()
	if err != nil {
		return nil, err
	}

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
				SignedKeys:         signKeys(m.clientKey, m.serverSessionPk, m.serverPermanentSk, nonce),
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
				SignedKeys: signKeys(m.clientKey, m.serverSessionPk, m.serverPermanentSk, nonce),
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

	encodedPayload, err := encodePayload(payload)
	if err != nil {
		return nil, err
	}

	encryptedPayload, err := encryptPayload(m.clientKey, m.serverSessionSk, nonce, encodedPayload)
	return encryptedPayload, err
}

// ServerAuthMessage //

// NewInitiatorMessage //
type NewInitiatorMessage struct {
	BaseMessage
	clientKey       [base.KeyBytesSize]byte
	serverSessionSk [base.KeyBytesSize]byte
}

// NewNewInitiatorMessage ..
func NewNewInitiatorMessage(src base.AddressType, dest base.AddressType, opts ...func(*NewInitiatorMessage)) *NewInitiatorMessage {
	msg := &NewInitiatorMessage{
		BaseMessage: BaseMessage{
			src:  src,
			dest: dest,
		},
	}

	for _, opt := range opts {
		opt(msg)
	}

	return msg
}

// Pack ..
func (m *NewInitiatorMessage) Pack(nonceReader NonceReader) ([]byte, error) {
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

	encryptedPayload, err := encryptPayload(m.clientKey, m.serverSessionSk, nonce, encodedPayload)
	return encryptedPayload, err
}

// NewInitiatorMessage //

// NewResponderMessage //
type NewResponderMessage struct {
	BaseMessage
	responderId     base.AddressType
	clientKey       [base.KeyBytesSize]byte
	serverSessionSk [base.KeyBytesSize]byte
}

// NewNewResponderMessage ..
func NewNewResponderMessage(src base.AddressType, dest base.AddressType, responderId base.AddressType, opts ...func(*NewResponderMessage)) *NewResponderMessage {
	msg := &NewResponderMessage{
		BaseMessage: BaseMessage{
			src:  src,
			dest: dest,
		},
		responderId: responderId,
	}
	for _, opt := range opts {
		opt(msg)
	}
	return msg
}

// Pack ..
func (m *NewResponderMessage) Pack(nonceReader NonceReader) ([]byte, error) {
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

	encryptedPayload, err := encryptPayload(m.clientKey, m.serverSessionSk, nonce, encodedPayload)
	return encryptedPayload, err
}

// NewResponderMessage //

// DropResponderMessage //
type DropResponderMessage struct {
	BaseMessage
	responderId     base.AddressType
	reason          int
	clientKey       [base.KeyBytesSize]byte
	serverSessionSk [base.KeyBytesSize]byte
}

// NewDropResponderMessage ..
func NewDropResponderMessage(src base.AddressType, dest base.AddressType, responderId base.AddressType, opts ...func(*DropResponderMessage)) *DropResponderMessage {
	return NewDropResponderMessageWithReason(src, dest, responderId, base.CloseCodeDropByInitiator, opts...)
}

// NewDropResponderMessageWithReason ..
func NewDropResponderMessageWithReason(src base.AddressType, dest base.AddressType, responderId base.AddressType, reason int, opts ...func(*DropResponderMessage)) *DropResponderMessage {
	msg := &DropResponderMessage{
		BaseMessage: BaseMessage{
			src:  src,
			dest: dest,
		},
		responderId: responderId,
		reason:      reason,
	}

	for _, opt := range opts {
		opt(msg)
	}
	return msg
}

// Pack ..
func (m *DropResponderMessage) Pack(nonceReader NonceReader) ([]byte, error) {
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

	encryptedPayload, err := encryptPayload(m.clientKey, m.serverSessionSk, nonce, encodedPayload)
	return encryptedPayload, err
}

// DropResponderMessage //

// SendErrorMessage //
type SendErrorMessage struct {
	BaseMessage
	messageId       []byte
	clientKey       [base.KeyBytesSize]byte
	serverSessionSk [base.KeyBytesSize]byte
}

// NewSendErrorMessage ..
func NewSendErrorMessage(src base.AddressType, dest base.AddressType, messageId []byte, opts ...func(*SendErrorMessage)) *SendErrorMessage {
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

	encryptedPayload, err := encryptPayload(m.clientKey, m.serverSessionSk, nonce, encodedPayload)
	return encryptedPayload, err
}

// SendErrorMessage //

// DisconnectedMessage //
type DisconnectedMessage struct {
	BaseMessage
	clientId        []byte
	clientKey       [base.KeyBytesSize]byte
	serverSessionSk [base.KeyBytesSize]byte
}

// NewDisconnectedMessage ..
func NewDisconnectedMessage(src base.AddressType, dest base.AddressType, clientId []byte, opts ...func(*DisconnectedMessage)) *DisconnectedMessage {
	msg := &DisconnectedMessage{
		BaseMessage: BaseMessage{
			src:  src,
			dest: dest,
		},
		clientId: clientId,
	}
	for _, opt := range opts {
		opt(msg)
	}
	return msg
}

// Pack ..
func (m *DisconnectedMessage) Pack(nonceReader NonceReader) ([]byte, error) {

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

	encryptedPayload, err := encryptPayload(m.clientKey, m.serverSessionSk, nonce, encodedPayload)
	return encryptedPayload, err
}

// DisconnectedMessage //
