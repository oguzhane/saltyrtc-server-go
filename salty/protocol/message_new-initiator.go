package protocol

// NewInitiatorMessage ..
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
