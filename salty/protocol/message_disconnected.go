package protocol

// DisconnectedMessage ..
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
