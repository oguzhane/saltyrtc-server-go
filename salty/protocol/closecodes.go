package protocol

const (
	// CloseCodeNormalClosure is Normal closure (WebSocket internal close code)
	CloseCodeNormalClosure = 1000
	// CloseCodeGoingAway is Going Away (WebSocket internal close code)
	CloseCodeGoingAway = 1001
	// CloseCodeSubprotocolError is Protocol Error (WebSocket internal close code)
	CloseCodeSubprotocolError = 1002
	// CloseCodePathFullError is Path Full
	CloseCodePathFullError = 3000
	// CloseCodeProtocolError is Protocol Error
	CloseCodeProtocolError = 3001
	// CloseCodeInternalError is Internal Error
	CloseCodeInternalError = 3002
	// CloseCodeHandover is Handover of the Signalling Channel
	CloseCodeHandover = 3003
	// CloseCodeDropByInitiator is  Dropped by Initiator
	CloseCodeDropByInitiator = 3004
	// CloseCodeInitiatorCouldNotDecrypt is Initiator Could Not Decrypt
	CloseCodeInitiatorCouldNotDecrypt = 3005
	// CloseCodeNoSharedTasks is No Shared Task Found
	CloseCodeNoSharedTasks = 3006
	// CloseCodeInvalidKey is Invalid Key
	CloseCodeInvalidKey = 3007
	// CloseCodeTimeout is Timeout
	CloseCodeTimeout = 3008
)
