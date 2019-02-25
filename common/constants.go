package common

const (
	KeyBitSize      = 256
	KeyBytesSize    = 32
	KeyStringLength = 64
	PathLength      = KeyStringLength
)

const (
	CloseCodeGoingAway                = 1001
	CloseCodeSubprotocolError         = 1002
	CloseCodePathFullError            = 3000
	CloseCodeProtocolError            = 3001
	CloseCodeInternalError            = 3002
	CloseCodeHandover                 = 3003
	CloseCodeDropByInitiator          = 3004
	CloseCodeInitiatorCouldNotDecrypt = 3005
	CloseCodeNoSharedTasks            = 3006
	CloseCodeInvalidKey               = 3007
)

const (
	RelayTimeout             uint32 = 30
	KeepAliveIntervalMin     uint32 = 1
	KeepAliveIntervalDefault uint32 = 3600
	KeepAliveTimeout         uint32 = 30
)
