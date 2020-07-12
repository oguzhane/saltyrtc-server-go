package protocol

import (
	"fmt"
	"io"

	"github.com/OguzhanE/saltyrtc-server-go/pkg/crypto/nacl"
)

const (
	// KeyBitSize represents the size of a key in bits
	KeyBitSize = 256
	// KeyBytesSize represents the size of a key in bytes
	KeyBytesSize = 32
	// KeyStringLength represents the size of a key in string
	KeyStringLength = 64
	// PathLength is length of a path in string
	PathLength = KeyStringLength
)

const (
	// DataLengthMin minimum length of data (nonce + payload)
	DataLengthMin = 25
	// NonceLength is length of nonce in bytes
	NonceLength = 24
	// CookieLength is length of cookie in bytes
	CookieLength = 16
	// SourceLength is length of source client in bytes
	SourceLength = 1
	// SourceUpperBound is CookieLength + SourceLength
	SourceUpperBound = CookieLength + SourceLength
	// DestinationLength is length of destination client
	DestinationLength = 1
	// DestinationUpperBound is SourceUpperBound + DestinationLength
	DestinationUpperBound = SourceUpperBound + DestinationLength
	// CsnUpperBound is upper bound of combined sequence number
	CsnUpperBound = NonceLength
)

const (
	// SubprotocolSaltyRTCv1 default protocol identifier: "v1.saltyrtc.org"
	SubprotocolSaltyRTCv1 = "v1.saltyrtc.org"
)

const (
	// HeaderSize is size of header
	HeaderSize = 24
)

var (
	// ErrHeaderLengthUnexpected occurs when header does not match with expected length
	ErrHeaderLengthUnexpected = fmt.Errorf("header error: unexpected header length bytes")
)

// Frame represents combination of header and payload
type Frame struct {
	Header  Header
	Payload []byte
}

// Header represents fields in header of a frame
type Header struct {
	Cookie []byte // 16 byte
	Csn    []byte // 2+4 byte
	Src    uint8  // 1 byte
	Dest   uint8  // 1 byte
}

// WriteHeader writes header binary representation into w.
func WriteHeader(w io.Writer, h Header) error {
	bts := make([]byte, HeaderSize)
	copy(bts[:16], h.Cookie)
	bts[16] = h.Src
	bts[17] = h.Dest
	copy(bts[18:], h.Csn)
	w.Write(bts)
	return nil
}

// WriteFrame writes frame binary representation into w.
func WriteFrame(w io.Writer, f Frame) error {
	err := WriteHeader(w, f.Header)
	if err != nil {
		return err
	}
	_, err = w.Write(f.Payload)
	return err
}

// ReadHeader reads a frame header from r.
func ReadHeader(r io.Reader) (h Header, err error) {
	bts := make([]byte, HeaderSize)

	_, err = io.ReadFull(r, bts)
	if err != nil {
		return
	}

	h.Cookie = bts[:16]
	h.Src = bts[16]
	h.Dest = bts[17]
	h.Csn = bts[18:]
	return
}

// ReadFrame reads a frame from r.
func ReadFrame(r io.Reader) (f Frame, err error) {
	f.Header, err = ReadHeader(r)
	if err != nil {
		return
	}

	for {
		bts := make([]byte, 512)
		nn := 0
		nn, err = io.ReadFull(r, bts)
		if err == io.ErrUnexpectedEOF || nn < 512 {
			f.Payload = append(f.Payload[:], bts[:nn]...)
			break
		}
		if err != nil {
			return
		}
		f.Payload = append(f.Payload, bts[:nn]...)
	}
	return
}

// ReadFrameWithSize reads a fixed size frame from r.
func ReadFrameWithSize(r io.Reader, n int) (f Frame, err error) {
	f.Header, err = ReadHeader(r)
	if err != nil {
		return
	}

	nn := n - HeaderSize
	f.Payload = make([]byte, nn)
	_, err = io.ReadFull(r, f.Payload)
	return
}

// ParseHeader parses b into h.
func ParseHeader(b []byte) (h Header, err error) {
	if len(b) < HeaderSize {
		err = ErrHeaderLengthUnexpected
		return
	}

	h.Cookie = b[:16]
	h.Src = b[16]
	h.Dest = b[17]
	h.Csn = b[18:HeaderSize]
	return
}

// ExtractNonce extracts nonce from b
func ExtractNonce(b []byte) (n []byte, err error) {
	if len(b) < HeaderSize {
		err = ErrHeaderLengthUnexpected
		return
	}

	n = b[:HeaderSize]
	return
}

// MakeNonce makes bytes of nonce from h
func MakeNonce(h Header) (bts []byte) {
	bts = make([]byte, HeaderSize)
	copy((bts[:16]), h.Cookie)
	bts[16] = h.Src
	bts[17] = h.Dest
	copy(bts[18:HeaderSize], h.Csn)
	return
}

// ParseFrame parses b into f.
func ParseFrame(b []byte) (f Frame, err error) {
	f.Header, err = ParseHeader(b)
	if err != nil {
		return
	}

	f.Payload = b[HeaderSize:]
	return
}

// PayloadWriter writes payload into w
type PayloadWriter interface {
	WritePayload(w io.Writer) error
}

// PayloadUnmarshaler ..
type PayloadUnmarshaler interface {
	UnmarshalPayload([]byte) error
}

// PayloadMarshaler ..
type PayloadMarshaler interface {
	MarshalPayload() ([]byte, error)
}

// UnmarshalMessage ..
func UnmarshalMessage(f Frame) (msg interface{}, err error) {
	payload := payloadUnion{}
	errp := DecodePayload(f.Payload, &payload)
	if errp != nil {
		err = ErrCantDecodePayload
		return
	}
	switch payload.Type {
	case ServerHello:
		return parseServerHello(payload, f)
	case ClientHello:
		return parseClientHello(payload, f)
	case ClientAuth:
		return parseClientAuth(payload, f)
	case NewInitiator:
		return parseNewInitiator(payload, f)
	case NewResponder:
		return parseNewResponder(payload, f)
	case DropResponder:
		return parseDropResponder(payload, f)
	default:
		return nil, NewPayloadFieldError(payload.Type, "type", ErrInvalidFieldValue)
	}
}

func parseServerHello(p payloadUnion, f Frame) (*ServerHelloMessage, error) {
	serverPk, err := nacl.ConvertBoxPkToBytes(p.Key)
	if err != nil {
		return nil, NewPayloadFieldError(ServerHello, "key", err)
	}
	return NewServerHelloMessage(f.Header.Src, f.Header.Dest, serverPk), nil
}

func parseClientHello(p payloadUnion, f Frame) (*ClientHelloMessage, error) {
	clientPk, err := nacl.ConvertBoxPkToBytes(p.Key)
	if err != nil {
		return nil, NewPayloadFieldError(ClientHello, "key", err)
	}
	return NewClientHelloMessage(f.Header.Src, f.Header.Dest, clientPk), nil
}

func parseClientAuth(p payloadUnion, f Frame) (*ClientAuthMessage, error) {
	// your_cookie
	yourCookie, err := ParseYourCookie(p.YourCookie)
	if err != nil {
		return nil, NewPayloadFieldError(ClientAuth, "your_cookie", err)
	}
	// subprotocols
	subprotocols, err := ParseSubprotocols(p.Subprotocols)
	if err != nil {
		return nil, NewPayloadFieldError(ClientAuth, "subprotocols", err)
	}
	// your_key
	yourKey, err := ParseYourKey(p.YourKey)
	if err != nil {
		return nil, NewPayloadFieldError(ClientAuth, "your_key", err)
	}
	return NewClientAuthMessage(f.Header.Src, f.Header.Dest, yourCookie, subprotocols, p.PingInterval, yourKey), nil
}

func parseNewInitiator(p payloadUnion, f Frame) (*NewInitiatorMessage, error) {
	return NewNewInitiatorMessage(f.Header.Src, f.Header.Dest), nil
}

func parseNewResponder(p payloadUnion, f Frame) (*NewResponderMessage, error) {
	id, err := ParseAddressID(p.ID)
	if err != nil {
		return nil, NewPayloadFieldError(NewResponder, "id", err)
	}
	return NewNewResponderMessage(f.Header.Src, f.Header.Dest, id), nil
}

func parseDropResponder(p payloadUnion, f Frame) (*DropResponderMessage, error) {
	id, err := ParseAddressID(p.ID)
	if err != nil || id <= Initiator {
		return nil, NewPayloadFieldError(DropResponder, "id", err)
	}
	reason, err := ParseReasonCode(p.Reason)
	if err != nil {
		return NewDropResponderMessageWithReason(f.Header.Src, f.Header.Dest, id, reason), nil
	}
	return NewDropResponderMessage(f.Header.Src, f.Header.Dest, id), nil
}
