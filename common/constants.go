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

const (
	DataLengthMin         = 25
	NonceLength           = 24
	CookieLength          = 16
	SourceLength          = 1
	SourceUpperBound      = CookieLength + SourceLength
	DestinationLength     = 1
	DestinationUpperBound = SourceUpperBound + DestinationLength
	CsnUpperBound         = NonceLength
)

const (
	SubprotocolSaltyRTCv1 = "v1.saltyrtc.org"
)
