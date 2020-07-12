package protocol

// ServerHelloMessage ..
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
