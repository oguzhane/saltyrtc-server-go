package salty

import (
	prot "github.com/OguzhanE/saltyrtc-server-go/salty/protocol"
	ws "github.com/gobwas/ws"
)

// CloseFrameNormalClosure //
var CloseFrameNormalClosure = compileCloseFrame(prot.CloseCodeNormalClosure, "")

// CloseFrameGoingAway //
var CloseFrameGoingAway = compileCloseFrame(prot.CloseCodeGoingAway, "")

// CloseFrameSubprotocolError //
var CloseFrameSubprotocolError = compileCloseFrame(prot.CloseCodeSubprotocolError, "")

// CloseFramePathFullError //
var CloseFramePathFullError = compileCloseFrame(prot.CloseCodePathFullError, "")

// CloseFrameProtocolError //
var CloseFrameProtocolError = compileCloseFrame(prot.CloseCodeProtocolError, "")

// CloseFrameInternalError //
var CloseFrameInternalError = compileCloseFrame(prot.CloseCodeInternalError, "")

// CloseFrameHandover //
var CloseFrameHandover = compileCloseFrame(prot.CloseCodeHandover, "")

// CloseFrameDropByInitiator //
var CloseFrameDropByInitiator = compileCloseFrame(prot.CloseCodeDropByInitiator, "")

// CloseFrameInitiatorCouldNotDecrypt //
var CloseFrameInitiatorCouldNotDecrypt = compileCloseFrame(prot.CloseCodeInitiatorCouldNotDecrypt, "")

// CloseFrameNoSharedTasks //
var CloseFrameNoSharedTasks = compileCloseFrame(prot.CloseCodeNoSharedTasks, "")

// CloseFrameInvalidKey //
var CloseFrameInvalidKey = compileCloseFrame(prot.CloseCodeInvalidKey, "")

// CloseFrameTimeout //
var CloseFrameTimeout = compileCloseFrame(prot.CloseCodeTimeout, "")

func getCloseFrameByCode(code int, defaultFrame []byte) (closeFrame []byte) {
	switch code {
	case prot.CloseCodeNormalClosure:
		closeFrame = CloseFrameNormalClosure
		break
	case prot.CloseCodeGoingAway:
		closeFrame = CloseFrameGoingAway
		break
	case prot.CloseCodeSubprotocolError:
		closeFrame = CloseFrameSubprotocolError
		break
	case prot.CloseCodePathFullError:
		closeFrame = CloseFramePathFullError
		break
	case prot.CloseCodeProtocolError:
		closeFrame = CloseFrameProtocolError
		break
	case prot.CloseCodeInternalError:
		closeFrame = CloseFrameInternalError
		break
	case prot.CloseCodeHandover:
		closeFrame = CloseFrameHandover
		break
	case prot.CloseCodeDropByInitiator:
		closeFrame = CloseFrameDropByInitiator
		break
	case prot.CloseCodeInitiatorCouldNotDecrypt:
		closeFrame = CloseFrameSubprotocolError
		break
	case prot.CloseCodeNoSharedTasks:
		closeFrame = CloseFrameNoSharedTasks
		break
	case prot.CloseCodeInvalidKey:
		closeFrame = CloseFrameInvalidKey
		break
	case prot.CloseCodeTimeout:
		closeFrame = CloseFrameTimeout
		break
	default:
		closeFrame = defaultFrame
	}
	return
}

func compileCloseFrame(code int, reason string) []byte {
	return ws.MustCompileFrame(
		ws.NewCloseFrame(ws.NewCloseFrameBody(
			ws.StatusAbnormalClosure, reason,
		)),
	)
}
