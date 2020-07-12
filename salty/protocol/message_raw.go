package protocol

// RawMessage ..
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
