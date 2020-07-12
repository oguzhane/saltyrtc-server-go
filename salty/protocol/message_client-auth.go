package protocol

// ClientAuthMessage ..
type ClientAuthMessage struct {
	BaseMessage
	ServerCookie []byte
	Subprotocols []string
	PingInterval uint32
	ServerKey    [KeyBytesSize]byte

	EncodingOpts BasicEncodingOpts
}

// NewClientAuthMessage ..
func NewClientAuthMessage(src AddressType, dest AddressType, serverCookie []byte,
	subprotocols []string, pingInterval uint32, serverKey [KeyBytesSize]byte) *ClientAuthMessage {
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
		Type         MessageType `codec:"type"`
		YourCookie   []byte      `codec:"your_cookie"`
		Subprotocols []string    `codec:"subprotocols"`
		PingInterval uint32      `codec:"ping_interval"`
		YourKey      [32]byte    `codec:"your_key"`
	}{
		Type:         ClientAuth,
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
