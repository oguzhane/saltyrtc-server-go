package protocol

// DropResponderMessage ..
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
