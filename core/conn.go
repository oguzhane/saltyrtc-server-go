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
var CloseFrameNormalClosure = compileCloseFrame(base.CloseCodeNormalClosure, "")

// CloseFrameGoingAway //
var CloseFrameGoingAway = compileCloseFrame(base.CloseCodeGoingAway, "")

// CloseFrameSubprotocolError //
var CloseFrameSubprotocolError = compileCloseFrame(base.CloseCodeSubprotocolError, "")

// CloseFramePathFullError //
var CloseFramePathFullError = compileCloseFrame(base.CloseCodePathFullError, "")

// CloseFrameProtocolError //
var CloseFrameProtocolError = compileCloseFrame(base.CloseCodeProtocolError, "")

// CloseFrameInternalError //
var CloseFrameInternalError = compileCloseFrame(base.CloseCodeInternalError, "")

// CloseFrameHandover //
var CloseFrameHandover = compileCloseFrame(base.CloseCodeHandover, "")

// CloseFrameDropByInitiator //
var CloseFrameDropByInitiator = compileCloseFrame(base.CloseCodeDropByInitiator, "")

// CloseFrameInitiatorCouldNotDecrypt //
var CloseFrameInitiatorCouldNotDecrypt = compileCloseFrame(base.CloseCodeInitiatorCouldNotDecrypt, "")

// CloseFrameNoSharedTasks //
var CloseFrameNoSharedTasks = compileCloseFrame(base.CloseCodeNoSharedTasks, "")

// CloseFrameInvalidKey //
var CloseFrameInvalidKey = compileCloseFrame(base.CloseCodeInvalidKey, "")

// CloseFrameTimeout //
var CloseFrameTimeout = compileCloseFrame(base.CloseCodeTimeout, "")

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

// Close ..
func (c *Conn) Close(preWrite []byte) error {
	if c.closed {
		return errors.New("connection already closed")
	}
	c.loop.poll.ModDetach(c.fd)
	loopCloseConn(c.loop, c, preWrite)
	c.closed = true
	return nil
}

// Write ..
func (c *Conn) Write(p []byte) (int, error) {
	return c.netConn.Write(p)
}

// Read ..
func (c *Conn) Read(p []byte) (int, error) {
	return syscall.Read(c.fd, p)
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

func compileCloseFrame(code int, reason string) []byte {
	return ws.MustCompileFrame(
		ws.NewCloseFrame(ws.NewCloseFrameBody(
			ws.StatusAbnormalClosure, reason,
		)),
	)
}
