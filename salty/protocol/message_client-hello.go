package protocol

// ClientHelloMessage ..
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
