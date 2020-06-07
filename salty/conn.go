package salty

import (
	"crypto/tls"
	"errors"
	"net"
	"reflect"
	"syscall"
	"unsafe"

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
	nopConn    *nopConn
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
	// tlsConn, _ := c.netConn.(*tls.Conn)
	// tls.Server()
	// tlsConn.SetReadDeadline(time.Now().Add(1000 * time.Microsecond))
	return c.netConn.Read(p)
	// return syscall.Read(c.fd, p)
}

func socketFD(conn net.Conn) (int, net.Conn) {
	tlsConn, ok := conn.(*tls.Conn)
	if ok {
		conn1 := reflect.ValueOf(tlsConn).Elem().FieldByName("conn")
		conn1 = reflect.NewAt(conn1.Type(), unsafe.Pointer(conn1.UnsafeAddr())).Elem()
		conn = conn1.Interface().(net.Conn)
	}
	//tls := reflect.TypeOf(conn.UnderlyingConn()) == reflect.TypeOf(&tls.Conn{})
	// Extract the file descriptor associated with the connection
	//connVal := reflect.Indirect(reflect.ValueOf(conn)).FieldByName("conn").Elem()
	tcpConn := reflect.Indirect(reflect.ValueOf(conn)).FieldByName("conn")
	//if tls {
	//	tcpConn = reflect.Indirect(tcpConn.Elem())
	//}
	fdVal := tcpConn.FieldByName("fd")
	pfdVal := reflect.Indirect(fdVal).FieldByName("pfd")

	return int(pfdVal.FieldByName("Sysfd").Int()), conn
}

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
