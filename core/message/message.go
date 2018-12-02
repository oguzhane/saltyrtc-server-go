package message

import (
	"github.com/oguzhane/saltyrtc-server-go/core"
	"github.com/oguzhane/saltyrtc-server-go/common"	
	"bufio"
	"bytes"
	"github.com/ugorji/go/codec"
	"golang.org/x/crypto/nacl/box"
)

type payloadPacker func(readNonce func() ([]byte, error)) ([]byte, error)

func Pack(client *core.Client, src common.AddressType, dest common.AddressType, 
	packPayload payloadPacker) ([]byte, error) {
	if client.CombinedSequenceNumberOut.HasErrOverflowSentinel() {
		return nil, common.NewMessageFlowError("Cannot send any more messages, due to a sequence number counter overflow")
	}

	data := new(bytes.Buffer)
	dw := bufio.NewWriter(data)
	
	// pack nonce //
	dw.Write(client.CookieOut)
	dw.WriteByte(src)
	dw.WriteByte(dest)
	csnBytes, err := client.CombinedSequenceNumberOut.AsBytes()
	if err != nil {
		dw.Flush()
		return nil, err
	}
	dw.Write(csnBytes)
	// pack nonce //

	// pack payload //
	if packPayload != nil{
		payload, err := packPayload(func()([]byte, error){
			err1 := dw.Flush()
			return data.Bytes(), err1
		})
		if err != nil {
			dw.Flush()
			return nil, err
		}
		dw.Write(payload)
	}
	// pack payload //

	// end up by flushing
	err = dw.Flush()
	if err != nil {
		return nil, err
	}
	client.CombinedSequenceNumberOut.Increment()
	return data.Bytes(), nil
}

// func Unpack(client *core.Client, data []byte) []byte {

// }

func encodePayload(payload map[string]interface{}) ([]byte, error) {
	b := new(bytes.Buffer)
	bw := bufio.NewWriter(b)
	h := new(codec.MsgpackHandle)
	enc := codec.NewEncoder(bw, h)
	err := enc.Encode(payload)
	if err != nil{
		bw.Flush()
		return nil, err
	}
	err = bw.Flush()
	return b.Bytes(), err
}

func encryptPayload(client *core.Client, nonce []byte, encodedPayload []byte) ([]byte, error){
	var nonceArr [24]byte
	copy(nonceArr[:], nonce[:24])
	return box.Seal(nil, encodedPayload, &nonceArr, &client.ClientKey, &client.ServerSessionBox.Sk), nil
}

func signKeys(c *core.Client, nonce []byte) []byte{
	var nonceArr [24]byte
	copy(nonceArr[:], nonce[:24])
	var buf bytes.Buffer
	buf.Write(c.ServerSessionBox.Pk[:])
	buf.Write(c.ClientKey[:])
	return box.Seal(nil, buf.Bytes(), &nonceArr, &c.ClientKey, &c.ServerPermanentBox.Sk)
}

type BaseMessagePacker interface{
	Pack(client *core.Client) ([]byte, error)
}

// baseMessage //
type baseMessage struct{
	src common.AddressType
	dest common.AddressType
	sourceType common.AddressType
	destType common.AddressType
}
// baseMessage //

// RawMessage //
type RawMessage struct {
	baseMessage
	data []byte
}

func NewRawMessage(src common.AddressType, dest common.AddressType, data []byte) *RawMessage {
	return &RawMessage{
		baseMessage:baseMessage{
			src:src,
			dest:dest,
			sourceType: common.GetAddressTypeFromaAddr(src),
			destType: common.GetAddressTypeFromaAddr(dest),
		},
		data:data,
	}
}

func (m *RawMessage) Pack(client *core.Client) ([]byte, error) {
	return m.data, nil
}
// RawMessage //

// ServerHelloMessage //
type ServerHelloMessage struct {
	baseMessage
	serverPublicKey []byte
}

func (m *ServerHelloMessage) NewServerHelloMessage(src common.AddressType, dest common.AddressType, serverPublicKey []byte) *ServerHelloMessage {
	return &ServerHelloMessage{
		baseMessage:baseMessage{
			src:src,
			dest:dest,
			sourceType: common.GetAddressTypeFromaAddr(src),
			destType: common.GetAddressTypeFromaAddr(dest),
		},
		serverPublicKey:serverPublicKey,
	}
}

func (m *ServerHelloMessage) Pack(client *core.Client) ([] byte, error) {
	return Pack(client, m.src, m.dest, func(readNonce func() ([]byte, error)) ([]byte, error){
		payload := map[string]interface{}{
			"type":[]byte(common.ServerHello),
			"key":m.serverPublicKey,
		}
		return encodePayload(payload)
	})
}
// ServerHelloMessage //

// ClientHelloMessage //
type ClientHelloMessage struct{
	baseMessage
	clientPublicKey []byte
}

func (m *ClientHelloMessage) NewClientHelloMessage(src common.AddressType, dest common.AddressType, clientPublicKey []byte) *ClientHelloMessage {
	return &ClientHelloMessage{
		baseMessage:baseMessage{
			src:src,
			dest:dest,
			sourceType: common.GetAddressTypeFromaAddr(src),
			destType: common.GetAddressTypeFromaAddr(dest),
		},
		clientPublicKey:clientPublicKey,
	}
}

func (m *ClientHelloMessage) Pack(client *core.Client) ([]byte, error) {
	return Pack(client, m.src, m.dest, func(readNonce func() ([]byte, error)) ([]byte, error){
		payload := map[string]interface{}{
			"type":[]byte(common.ClientHello),
			"key":m.clientPublicKey,
		}
		return encodePayload(payload)
	})
}
// ClientHelloMessage //

// ClientAuthMessage //
type ClientAuthMessage struct{
	baseMessage
	serverCookie []byte
	subprotocols []string
	pingInterval uint32
	serverKey []byte
}

func (c *ClientAuthMessage) NewClientAuthMessage(src common.AddressType, dest common.AddressType, serverCookie []byte, 
												subprotocols []string, pingInterval uint32, serverKey []byte) *ClientAuthMessage {
	return &ClientAuthMessage{
		baseMessage:baseMessage{
			src:src,
			dest:dest,
			sourceType: common.GetAddressTypeFromaAddr(src),
			destType: common.GetAddressTypeFromaAddr(dest),
		},
		serverCookie: serverCookie,
		subprotocols: subprotocols,
		pingInterval: pingInterval,
		serverKey: serverKey,		
	}
}

func (m *ClientAuthMessage) Pack(client *core.Client) ([]byte, error) { 
	if !client.Authenticated{
		return nil, common.NewMessageFlowError("Cannot encrypt payload")
	}
	return Pack(client, m.src, m.dest, func(readNonce func() ([]byte, error)) ([]byte, error){
		payload := map[string]interface{}{
			"type": common.ClientAuth,
			"your_cookie": m.serverCookie,
			"subprotocols": m.subprotocols,
			"ping_interval":m.pingInterval,
		}
		if m.serverKey != nil {
			payload["your_key"] = m.serverKey
		}
		encodedPayload, err := encodePayload(payload)
		if err != nil {
			return nil, err 
		}
		nonce, err := readNonce()
		if err != nil {
			return nil, err 
		}
		encryptedPayload, err := encryptPayload(client, nonce, encodedPayload)
		return encryptedPayload, err
	})
}
// ClientAuthMessage //

// ServerAuthMessage //
type ServerAuthMessage struct{
	baseMessage
	clientCookie []byte
	signKeys bool
	initiatorConnected bool
	responderIds []common.AddressType
	towardsInitiator bool
}

func NewServerAuthMessageForInitiator(src common.AddressType, dest common.AddressType, clientCookie []byte,
									signKeys bool, responderIds []common.AddressType) *ServerAuthMessage {
	return &ServerAuthMessage {
		baseMessage:baseMessage{
			src:src,
			dest:dest,
			sourceType: common.GetAddressTypeFromaAddr(src),
			destType: common.GetAddressTypeFromaAddr(dest),
		},
		clientCookie: clientCookie,
		signKeys: signKeys,
		responderIds: responderIds,
		towardsInitiator:true,
	}
}

func NewServerAuthMessageForResponder(src common.AddressType, dest common.AddressType, clientCookie []byte,
									signKeys bool, initiatorConnected bool) *ServerAuthMessage {
	return &ServerAuthMessage {
		baseMessage:baseMessage{
			src:src,
			dest:dest,
			sourceType: common.GetAddressTypeFromaAddr(src),
			destType: common.GetAddressTypeFromaAddr(dest),
		},
		clientCookie: clientCookie,
		signKeys: signKeys,
		initiatorConnected:initiatorConnected,
		towardsInitiator:false,
	}
}

func (m *ServerAuthMessage) Pack(client *core.Client) ([]byte, error) {
	return Pack(client, m.src, m.dest, func(readNonce func() ([]byte, error)) ([]byte, error){
		payload := map[string]interface{}{
			"type": common.ServerAuth,
			"your_cookie": m.clientCookie,
		}
		if m.towardsInitiator {
			payload["initiator_connected"]=m.initiatorConnected
		} else {
			payload["responders"]=m.responderIds
		}
		
		nonce, err := readNonce()
		if err != nil {
			return nil, err 
		}
		
		if m.signKeys {
			payload["signed_keys"] = signKeys(client, nonce)
		}

		encodedPayload, err := encodePayload(payload)
		if err != nil {
			return nil, err 
		}

		encryptedPayload, err := encryptPayload(client, nonce, encodedPayload)
		return encryptedPayload, err
	})
}
// ServerAuthMessage //

// NewInitiatorMessage //
type NewInitiatorMessage struct {
	baseMessage
}

func NewNewInitiatorMessage(src common.AddressType, dest common.AddressType) *NewInitiatorMessage {
	return &NewInitiatorMessage{
		baseMessage:baseMessage{
			src:src,
			dest:dest,
			sourceType: common.GetAddressTypeFromaAddr(src),
			destType: common.GetAddressTypeFromaAddr(dest),
		},
	}
}

func (m *NewInitiatorMessage) Pack(client *core.Client) ([]byte, error){
	return Pack(client, m.src, m.dest, func(readNonce func() ([]byte, error)) ([]byte, error){
		payload := map[string]interface{}{
			"type": common.NewInitiator,
		}
		
		nonce, err := readNonce()
		if err != nil {
			return nil, err 
		}
		
		encodedPayload, err := encodePayload(payload)
		if err != nil {
			return nil, err 
		}

		encryptedPayload, err := encryptPayload(client, nonce, encodedPayload)
		return encryptedPayload, err
	})
}
// NewInitiatorMessage //

// NewResponderMessage //
type NewResponderMessage struct {
	baseMessage
	responderId common.AddressType
}

func NewNewResponderMessage(src common.AddressType, dest common.AddressType, responderId common.AddressType) *NewResponderMessage {
	return &NewResponderMessage{
		baseMessage:baseMessage{
			src:src,
			dest:dest,
			sourceType: common.GetAddressTypeFromaAddr(src),
			destType: common.GetAddressTypeFromaAddr(dest),
		},
		responderId: responderId,
	}
}

func (m *NewResponderMessage) Pack(client *core.Client) ([]byte, error){
	return Pack(client, m.src, m.dest, func(readNonce func() ([]byte, error)) ([]byte, error){
		payload := map[string]interface{}{
			"type": common.NewResponder,
			"id": m.responderId,
		}
		
		nonce, err := readNonce()
		if err != nil {
			return nil, err 
		}
		
		encodedPayload, err := encodePayload(payload)
		if err != nil {
			return nil, err 
		}

		encryptedPayload, err := encryptPayload(client, nonce, encodedPayload)
		return encryptedPayload, err
	})
}
// NewResponderMessage //

// DropResponderMessage //
type DropResponderMessage struct {
	baseMessage
	responderId common.AddressType
	reason int
}

func NewDropResponderMessage(src common.AddressType, dest common.AddressType, responderId common.AddressType) *DropResponderMessage {
	return NewDropResponderMessageWithReason(src, dest, responderId, common.CloseCodeDropByInitiator)
}

func NewDropResponderMessageWithReason(src common.AddressType, dest common.AddressType, responderId common.AddressType, reason int) *DropResponderMessage {
	return &DropResponderMessage{
		baseMessage:baseMessage{
			src:src,
			dest:dest,
			sourceType: common.GetAddressTypeFromaAddr(src),
			destType: common.GetAddressTypeFromaAddr(dest),
		},
		responderId: responderId,
		reason: reason,
	}
}

func (m *DropResponderMessage) Pack(client *core.Client) ([]byte, error){
	return Pack(client, m.src, m.dest, func(readNonce func() ([]byte, error)) ([]byte, error){
		payload := map[string]interface{}{
			"type": common.DropResponder,
			"id": m.responderId,
			"reason": m.reason,
		}
		
		nonce, err := readNonce()
		if err != nil {
			return nil, err 
		}
		
		encodedPayload, err := encodePayload(payload)
		if err != nil {
			return nil, err 
		}

		encryptedPayload, err := encryptPayload(client, nonce, encodedPayload)
		return encryptedPayload, err
	})
}
// DropResponderMessage //

// SendErrorMessage //
type SendErrorMessage struct {
	baseMessage
	messageId []byte
}

func NewSendErrorMessage(src common.AddressType, dest common.AddressType, messageId []byte) *SendErrorMessage {
	return &SendErrorMessage{
		baseMessage:baseMessage{
			src:src,
			dest:dest,
			sourceType: common.GetAddressTypeFromaAddr(src),
			destType: common.GetAddressTypeFromaAddr(dest),
		},
		messageId:messageId,
	}
}

func (m *SendErrorMessage) Pack(client *core.Client) ([]byte, error){
	return Pack(client, m.src, m.dest, func(readNonce func() ([]byte, error)) ([]byte, error){
		payload := map[string]interface{}{
			"type": common.SendError,
			"id": m.messageId,
		}
		
		nonce, err := readNonce()
		if err != nil {
			return nil, err 
		}
		
		encodedPayload, err := encodePayload(payload)
		if err != nil {
			return nil, err 
		}

		encryptedPayload, err := encryptPayload(client, nonce, encodedPayload)
		return encryptedPayload, err
	})
}
// SendErrorMessage //

// DisconnectedMessage //
type DisconnectedMessage struct {
	baseMessage
	clientId []byte
}

func NewDisconnectedMessage(src common.AddressType, dest common.AddressType, clientId []byte) *DisconnectedMessage {
	return &DisconnectedMessage{
		baseMessage:baseMessage{
			src:src,
			dest:dest,
			sourceType: common.GetAddressTypeFromaAddr(src),
			destType: common.GetAddressTypeFromaAddr(dest),
		},
		clientId:clientId,
	}
}

func (m *DisconnectedMessage) Pack(client *core.Client) ([]byte, error){
	return Pack(client, m.src, m.dest, func(readNonce func() ([]byte, error)) ([]byte, error){
		payload := map[string]interface{}{
			"type": common.Disconnected,
			"id": m.clientId,
		}
		
		nonce, err := readNonce()
		if err != nil {
			return nil, err 
		}
		
		encodedPayload, err := encodePayload(payload)
		if err != nil {
			return nil, err 
		}

		encryptedPayload, err := encryptPayload(client, nonce, encodedPayload)
		return encryptedPayload, err
	})
}
// DisconnectedMessage //