package core

import (
	"errors"
	"net"
	"reflect"
	"syscall"

	"github.com/OguzhanE/saltyrtc-server-go/pkg/base"
	ws "github.com/gobwas/ws"
)

// CloseFrameNormalClosure //
var CloseFrameNormalClosure = buildCloseFrame(base.CloseCodeNormalClosure, "")

// CloseFrameGoingAway //
var CloseFrameGoingAway = buildCloseFrame(base.CloseCodeGoingAway, "")

// CloseFrameSubprotocolError //
var CloseFrameSubprotocolError = buildCloseFrame(base.CloseCodeSubprotocolError, "")

// CloseFramePathFullError //
var CloseFramePathFullError = buildCloseFrame(base.CloseCodePathFullError, "")

// CloseFrameProtocolError //
var CloseFrameProtocolError = buildCloseFrame(base.CloseCodeProtocolError, "")

// CloseFrameInternalError //
var CloseFrameInternalError = buildCloseFrame(base.CloseCodeInternalError, "")

// CloseFrameHandover //
var CloseFrameHandover = buildCloseFrame(base.CloseCodeHandover, "")

// CloseFrameDropByInitiator //
var CloseFrameDropByInitiator = buildCloseFrame(base.CloseCodeDropByInitiator, "")

// CloseFrameInitiatorCouldNotDecrypt //
var CloseFrameInitiatorCouldNotDecrypt = buildCloseFrame(base.CloseCodeInitiatorCouldNotDecrypt, "")

// CloseFrameNoSharedTasks //
var CloseFrameNoSharedTasks = buildCloseFrame(base.CloseCodeNoSharedTasks, "")

// CloseFrameInvalidKey //
var CloseFrameInvalidKey = buildCloseFrame(base.CloseCodeInvalidKey, "")

// CloseFrameTimeout //
var CloseFrameTimeout = buildCloseFrame(base.CloseCodeTimeout, "")

// Conn ..
type Conn struct {
	fd         int              // file descriptor
	sa         syscall.Sockaddr // remote socket address
	opened     bool             // connection opened event fired
	addrIndex  int              // index of listening address
	remoteAddr net.Addr         // remote addr
	loop       *loop            // connected loop
	netConn    net.Conn
	upgraded   bool // upgraded to ws protocol
	client     *Client
	closed     bool
}

func socketFD(conn net.Conn) int {
	//tls := reflect.TypeOf(conn.UnderlyingConn()) == reflect.TypeOf(&tls.Conn{})
	// Extract the file descriptor associated with the connection
	//connVal := reflect.Indirect(reflect.ValueOf(conn)).FieldByName("conn").Elem()
	tcpConn := reflect.Indirect(reflect.ValueOf(conn)).FieldByName("conn")
	//if tls {
	//	tcpConn = reflect.Indirect(tcpConn.Elem())
	//}
	fdVal := tcpConn.FieldByName("fd")
	pfdVal := reflect.Indirect(fdVal).FieldByName("pfd")

	return int(pfdVal.FieldByName("Sysfd").Int())
}

func buildCloseFrame(code int, reason string) []byte {
	return ws.MustCompileFrame(
		ws.NewCloseFrame(ws.NewCloseFrameBody(
			ws.StatusAbnormalClosure, reason,
		)),
	)
}

func (c *Conn) Close(preWrite []byte, modRW bool) error {
	if c.closed {
		return errors.New("connection already closed")
	}
	if modRW {
		c.loop.poll.ModReadWrite(c.fd)
		defer c.loop.poll.ModRead(c.fd)
	}
	loopCloseConn(c.loop, c, preWrite)
	c.closed = true
	return nil
}

func getCloseFrameByCode(code int, defaultFrame []byte) (closeFrame []byte) {
	switch code {
	case base.CloseCodeNormalClosure:
		closeFrame = CloseFrameNormalClosure
		break
	case base.CloseCodeGoingAway:
		closeFrame = CloseFrameGoingAway
		break
	case base.CloseCodeSubprotocolError:
		closeFrame = CloseFrameSubprotocolError
		break
	case base.CloseCodePathFullError:
		closeFrame = CloseFramePathFullError
		break
	case base.CloseCodeProtocolError:
		closeFrame = CloseFrameProtocolError
		break
	case base.CloseCodeInternalError:
		closeFrame = CloseFrameInternalError
		break
	case base.CloseCodeHandover:
		closeFrame = CloseFrameHandover
		break
	case base.CloseCodeDropByInitiator:
		closeFrame = CloseFrameDropByInitiator
		break
	case base.CloseCodeInitiatorCouldNotDecrypt:
		closeFrame = CloseFrameSubprotocolError
		break
	case base.CloseCodeNoSharedTasks:
		closeFrame = CloseFrameNoSharedTasks
		break
	case base.CloseCodeInvalidKey:
		closeFrame = CloseFrameInvalidKey
		break
	case base.CloseCodeTimeout:
		closeFrame = CloseFrameTimeout
		break
	default:
		closeFrame = defaultFrame
	}
	return
}
