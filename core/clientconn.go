package core

import (
	"net"
	"time"
)

type ClientConn struct {
	Conn net.Conn
	t    time.Duration
}

func (c ClientConn) Write(p []byte) (int, error) {
	if err := c.Conn.SetWriteDeadline(time.Now().Add(c.t)); err != nil {
		return 0, err
	}
	return c.Conn.Write(p)
}

func (c ClientConn) Read(p []byte) (int, error) {
	if err := c.Conn.SetReadDeadline(time.Now().Add(c.t)); err != nil {
		return 0, err
	}
	return c.Conn.Read(p)
}

func NewClientConn(conn *net.Conn, t time.Duration) ClientConn {
	return ClientConn{
		Conn: *conn,
		t:    t,
	}
}
