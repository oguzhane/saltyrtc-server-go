package protocol

import (
	"bufio"
	"bytes"
	"errors"

	"github.com/OguzhanE/saltyrtc-server-go/pkg/crypto/nacl"
	"github.com/ugorji/go/codec"
	"golang.org/x/crypto/nacl/box"
)

var (
	// ErrNotAllowedMessage occurs when you are trying to relay a message to invalid dest
	ErrNotAllowedMessage = errors.New("not allowed message")
	// ErrNotMatchedIdentities occurs when you identities dont match for two different source
	ErrNotMatchedIdentities = errors.New("identities dont match")
	// ErrNotAuthenticatedClient occurs when you are trying to encrypt message
	ErrNotAuthenticatedClient = errors.New("client is not authenticated")
	// ErrMessageTooShort occurs when the length of message less than expected
	ErrMessageTooShort = errors.New("message is too short")
	// ErrCantDecodePayload occurs when try to decode payload
	ErrCantDecodePayload = errors.New("cant decode payload")
	// ErrFieldNotExist occurs when a field should exist but it doesnt
	ErrFieldNotExist = errors.New("field doesnt exist")
	// ErrInvalidFieldValue occurs when fiel value is not valid
	ErrInvalidFieldValue = errors.New("invalid field value")
	// ErrCantDecryptPayload occurs when try to decrypt payload
	ErrCantDecryptPayload = errors.New("cant decrypt payload")
)

// DecodePayload decodes encodedPayload into v
func DecodePayload(encodedPayload []byte, v interface{}) error {
	h := new(codec.MsgpackHandle) // todo: allocate on stack??
	h.WriteExt = true
	h.ErrorIfNoField = true
	dec := codec.NewDecoderBytes(encodedPayload, h)
	err := dec.Decode(v)
	return err
}

// DecryptPayload returns decrypted data in bytes
func DecryptPayload(clientKey [nacl.NaclKeyBytesSize]byte, serverSessionSk [nacl.NaclKeyBytesSize]byte, nonce []byte, data []byte) ([]byte, error) {
	var nonceArr [NonceLength]byte
	copy(nonceArr[:], nonce[:NonceLength])
	decryptedData, ok := box.Open(nil, data, &nonceArr, &clientKey, &serverSessionSk)
	if !ok {
		return nil, ErrCantDecryptPayload
	}
	return decryptedData, nil
}

// EncodePayload returns encoded of payload in bytes
func EncodePayload(payload interface{}) ([]byte, error) {
	b := new(bytes.Buffer)
	bw := bufio.NewWriter(b)
	h := new(codec.MsgpackHandle)
	h.WriteExt = true
	enc := codec.NewEncoder(bw, h)
	err := enc.Encode(payload)
	if err != nil {
		bw.Flush()
		return nil, err
	}
	err = bw.Flush()
	return b.Bytes(), err
}

// EncryptPayload encryptes payload as bytes
func EncryptPayload(clientKey [nacl.NaclKeyBytesSize]byte, serverSessionSk [nacl.NaclKeyBytesSize]byte, nonce []byte, encodedPayload []byte) ([]byte, error) {
	var nonceArr [NonceLength]byte
	copy(nonceArr[:], nonce[:NonceLength])
	return box.Seal(nil, encodedPayload, &nonceArr, &clientKey, &serverSessionSk), nil
}

// SignKeys seals nonce with client and server keys to bytes
func SignKeys(clientKey [nacl.NaclKeyBytesSize]byte, serverSessionPk [nacl.NaclKeyBytesSize]byte, serverPermanentSk [nacl.NaclKeyBytesSize]byte, nonce []byte) []byte {
	var nonceArr [NonceLength]byte
	copy(nonceArr[:], nonce[:NonceLength])
	var buf bytes.Buffer
	buf.Write(serverSessionPk[:])
	buf.Write(clientKey[:])
	return box.Seal(nil, buf.Bytes(), &nonceArr, &clientKey, &serverPermanentSk)
}

type payloadUnion struct {
	Type               MessageType `codec:"type"`
	Key                []byte      `codec:"key,omitempty"`
	YourCookie         []byte      `codec:"your_cookie,omitempty"`
	Subprotocols       []string    `codec:"subprotocols,omitempty"`
	PingInterval       uint32      `codec:"ping_interval,omitempty"`
	YourKey            []byte      `codec:"your_key,omitempty"`
	InitiatorConnected bool        `codec:"initiator_connected,omitempty"`
	Responders         []uint16    `codec:"responders,omitempty"`
	SignedKeys         []byte      `codec:"signed_keys,omitempty"`
	ID                 interface{} `codec:"id,omitempty"`
	Reason             int         `codec:"reason,omitempty"`
}

// PayloadFieldError represents an error correlated to a particular field
type PayloadFieldError struct {
	Type  string
	Field string
	Err   error
}

// NewPayloadFieldError creates PayloadFieldError instance
func NewPayloadFieldError(payloadType string, field string, err error) *PayloadFieldError {
	return &PayloadFieldError{
		Type:  payloadType,
		Field: field,
		Err:   err,
	}
}

// Error ..
func (e *PayloadFieldError) Error() string {
	return e.Type + "." + e.Field + ": " + e.Err.Error()
}
