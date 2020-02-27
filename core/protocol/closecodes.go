package protocol

const (
	CloseCodeNormalClosure            = 1000
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
	CloseCodeTimeout                  = 3008
)
