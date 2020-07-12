package protocol

import "github.com/OguzhanE/saltyrtc-server-go/pkg/crypto/nacl"

// ServerAuthEncodingOpts is options for encoding of server auth messsage
type ServerAuthEncodingOpts struct {
	ServerPermanentSk [nacl.NaclKeyBytesSize]byte
	ClientKey         [nacl.NaclKeyBytesSize]byte
	ServerSessionSk   [nacl.NaclKeyBytesSize]byte
	ServerSessionPk   [nacl.NaclKeyBytesSize]byte
	Nonce             []byte
}

// ServerAuthMessage ..
type ServerAuthMessage struct {
	BaseMessage
	clientCookie       []byte
	signKeys           bool
	initiatorConnected bool
	responderIds       []AddressType
	towardsInitiator   bool

	EncodingOpts ServerAuthEncodingOpts
}

// NewServerAuthMessageForInitiator ..
func NewServerAuthMessageForInitiator(src AddressType, dest AddressType, clientCookie []byte,
	signKeys bool, responderIds []AddressType) *ServerAuthMessage {
	msg := &ServerAuthMessage{
		BaseMessage: BaseMessage{
			Src:  src,
			Dest: dest,
		},
		clientCookie:     clientCookie,
		signKeys:         signKeys,
		responderIds:     responderIds,
		towardsInitiator: true,
	}
	return msg
}

// NewServerAuthMessageForResponder ..
func NewServerAuthMessageForResponder(src AddressType, dest AddressType, clientCookie []byte,
	signKeys bool, initiatorConnected bool) *ServerAuthMessage {
	msg := &ServerAuthMessage{
		BaseMessage: BaseMessage{
			Src:  src,
			Dest: dest,
		},
		clientCookie:       clientCookie,
		signKeys:           signKeys,
		initiatorConnected: initiatorConnected,
		towardsInitiator:   false,
	}
	return msg
}

// MarshalPayload ...
func (m ServerAuthMessage) MarshalPayload() ([]byte, error) {
	var payload interface{}

	if !m.towardsInitiator {
		if m.signKeys {
			payload = struct {
				Type               MessageType `codec:"type"`
				YourCookie         []byte      `codec:"your_cookie"`
				InitiatorConnected bool        `codec:"initiator_connected"`
				SignedKeys         []byte      `codec:"signed_keys"`
			}{
				Type:               ServerAuth,
				YourCookie:         m.clientCookie,
				InitiatorConnected: m.initiatorConnected,
				SignedKeys:         SignKeys(m.EncodingOpts.ClientKey, m.EncodingOpts.ServerSessionPk, m.EncodingOpts.ServerPermanentSk, m.EncodingOpts.Nonce),
			}
		} else {
			payload = struct {
				Type               MessageType `codec:"type"`
				YourCookie         []byte      `codec:"your_cookie"`
				InitiatorConnected bool        `codec:"initiator_connected"`
			}{
				Type:               ServerAuth,
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
				Type       MessageType `codec:"type"`
				YourCookie []byte      `codec:"your_cookie"`
				Responders []uint16    `codec:"responders"`
				SignedKeys []byte      `codec:"signed_keys"`
			}{
				Type:       ServerAuth,
				YourCookie: m.clientCookie,
				Responders: responderArr,
				SignedKeys: SignKeys(m.EncodingOpts.ClientKey, m.EncodingOpts.ServerSessionPk, m.EncodingOpts.ServerPermanentSk, m.EncodingOpts.Nonce),
			}
		} else {
			payload = struct {
				Type       MessageType `codec:"type"`
				YourCookie []byte      `codec:"your_cookie"`
				Responders []uint16    `codec:"responders"`
			}{
				Type:       ServerAuth,
				YourCookie: m.clientCookie,
				Responders: responderArr,
			}
		}
	}

	encodedPayload, err := EncodePayload(payload)
	if err != nil {
		return nil, err
	}

	encryptedPayload, err := EncryptPayload(m.EncodingOpts.ClientKey, m.EncodingOpts.ServerSessionSk, m.EncodingOpts.Nonce, encodedPayload)
	return encryptedPayload, err
}
