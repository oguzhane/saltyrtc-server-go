package core

import (
	"net"
	"time"

	"github.com/OguzhanE/saltyrtc-server-go/pkg/base"
)

type ClientConn struct {
	Conn      net.Conn
	t         time.Duration
	AliveStat base.AliveStatType
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

func (c ClientConn) Close(closeFrame []byte) error {
	if (c.AliveStat & base.AliveStatDeath) == base.AliveStatDeath {
		return nil
	}
	Sugar.Info("Connection closing..")
	c.AliveStat = base.MarkAsOrphan(c.AliveStat)
	c.Conn.Write(closeFrame)
	err := c.Conn.Close()

	if err != nil {
		Sugar.Errorf("couldnt close the connection. err:%s\n", err)
	} else {
		c.AliveStat = base.MarkAsDeath(c.AliveStat)
	}
	return err
}
