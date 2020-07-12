package protocol

// NewResponderMessage ..
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
