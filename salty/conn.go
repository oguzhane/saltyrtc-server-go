package salty

import (
	"errors"
	"net"
	"reflect"
	"syscall"
)

// Conn ..
type Conn struct {
	fd         int              // file descriptor
	sa         syscall.Sockaddr // remote socket address
	opened     bool             // connection opened event fired
	addrIndex  int              // index of listening address
	remoteAddr net.Addr         // remote addr
	loop       *loop            // connected loop
	netConn    net.Conn
	rawConn    syscall.RawConn
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
	return readRawConn(c.rawConn, p)
}

func readRawConn(c syscall.RawConn, b []byte) (int, error) {
	var operr error
	var n int
	err := c.Read(func(s uintptr) bool {
		n, operr = syscall.Read(int(s), b)
		return true
	})
	if err != nil {
		return n, err
	}
	if operr != nil {
		return n, operr
	}
	return n, nil
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
