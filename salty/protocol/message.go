package protocol

// MessageType is used to represent type of a message
type MessageType = string

const (
	// ServerHello ..
	ServerHello MessageType = "server-hello"
	// ClientHello ..
	ClientHello MessageType = "client-hello"
	// ClientAuth ..
	ClientAuth MessageType = "client-auth"
	// ServerAuth ..
	ServerAuth MessageType = "server-auth"
	// NewResponder ..
	NewResponder MessageType = "new-responder"
	// NewInitiator ..
	NewInitiator MessageType = "new-initiator"
	// DropResponder ..
	DropResponder MessageType = "drop-responder"
	// SendError ..
	SendError MessageType = "send-error"
	// Disconnected ..
	Disconnected MessageType = "disconnected"
)

// BasicEncodingOpts is options for encoding with basic fields
type BasicEncodingOpts struct {
	ClientKey       [32]byte
	ServerSessionSk [32]byte
	Nonce           []byte
}

// BaseMessage ..
type BaseMessage struct {
	Src  AddressType
	Dest AddressType
}
