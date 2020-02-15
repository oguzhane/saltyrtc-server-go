package core

import "github.com/OguzhanE/saltyrtc-server-go/pkg/base"

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

// ClientAuthMessage //
type ClientAuthMessage struct {
	BaseMessage
	serverCookie []byte
	subprotocols []string
	pingInterval uint32
	serverKey    [base.KeyBytesSize]byte
}

// NewClientAuthMessage ..
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

// Pack ..
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

// NewServerAuthMessageForInitiator ..
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

// NewServerAuthMessageForResponder ..
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

// Pack ..
func (m *ServerAuthMessage) Pack(client *Client, nonceReader NonceReader) ([]byte, error) {
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
				SignedKeys: signKeys(client, nonce),
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

	encryptedPayload, err := encryptPayload(client, nonce, encodedPayload)
	return encryptedPayload, err
}

// ServerAuthMessage //

// NewInitiatorMessage //
type NewInitiatorMessage struct {
	BaseMessage
}

// NewNewInitiatorMessage ..
func NewNewInitiatorMessage(src base.AddressType, dest base.AddressType) *NewInitiatorMessage {
	return &NewInitiatorMessage{
		BaseMessage: BaseMessage{
			src:  src,
			dest: dest,
		},
	}
}

// Pack ..
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

// NewNewResponderMessage ..
func NewNewResponderMessage(src base.AddressType, dest base.AddressType, responderId base.AddressType) *NewResponderMessage {
	return &NewResponderMessage{
		BaseMessage: BaseMessage{
			src:  src,
			dest: dest,
		},
		responderId: responderId,
	}
}

// Pack ..
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

// NewDropResponderMessage ..
func NewDropResponderMessage(src base.AddressType, dest base.AddressType, responderId base.AddressType) *DropResponderMessage {
	return NewDropResponderMessageWithReason(src, dest, responderId, base.CloseCodeDropByInitiator)
}

// NewDropResponderMessageWithReason ..
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

// Pack ..
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

// NewSendErrorMessage ..
func NewSendErrorMessage(src base.AddressType, dest base.AddressType, messageId []byte) *SendErrorMessage {
	return &SendErrorMessage{
		BaseMessage: BaseMessage{
			src:  src,
			dest: dest,
		},
		messageId: messageId,
	}
}

// Pack ..
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

// NewDisconnectedMessage ..
func NewDisconnectedMessage(src base.AddressType, dest base.AddressType, clientId []byte) *DisconnectedMessage {
	return &DisconnectedMessage{
		BaseMessage: BaseMessage{
			src:  src,
			dest: dest,
		},
		clientId: clientId,
	}
}

// Pack ..
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
