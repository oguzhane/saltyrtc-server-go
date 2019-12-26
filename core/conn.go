package core

import (
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
