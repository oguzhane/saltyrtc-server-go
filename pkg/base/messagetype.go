package base

type MessageType string

const (
	ServerHello   MessageType = "server-hello"
	ClientHello   MessageType = "client-hello"
	ClientAuth    MessageType = "client-auth"
	ServerAuth    MessageType = "server-auth"
	NewResponder  MessageType = "new-responder"
	NewInitiator  MessageType = "new-initiator"
	DropResponder MessageType = "drop-responder"
	SendError     MessageType = "send-error"
	Disconnected  MessageType = "disconnected"
)
