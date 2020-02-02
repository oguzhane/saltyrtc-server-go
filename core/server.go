package core

import (
	"io"
	"io/ioutil"
	"net"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/OguzhanE/saltyrtc-server-go/pkg/base"
	"github.com/OguzhanE/saltyrtc-server-go/pkg/boxkeypair"
	"github.com/OguzhanE/saltyrtc-server-go/pkg/hexutil"

	"github.com/OguzhanE/saltyrtc-server-go/pkg/evpoll"
	"github.com/OguzhanE/saltyrtc-server-go/pkg/gopool"
	"github.com/gammazero/workerpool"
	ws "github.com/gobwas/ws"
	"github.com/gobwas/ws/wsutil"
)

const (
	// MaxJobs ..
	MaxJobs = 32
	// MaxWorkers ..
	MaxWorkers = 8
)

// Server handles clients
type Server struct {
	paths          *Paths
	jobQueue       chan gopool.Job
	wp             *workerpool.WorkerPool
	subprotocols   []string
	subprotocol    string
	permanentBoxes []*boxkeypair.BoxKeyPair
}

// NewServer creates new server instance
func NewServer(permanentBox boxkeypair.BoxKeyPair) *Server {
	permanentBoxes := []*boxkeypair.BoxKeyPair{
		&permanentBox,
	}
	return &Server{
		paths:          NewPaths(),
		subprotocols:   []string{base.SubprotocolSaltyRTCv1},
		subprotocol:    base.SubprotocolSaltyRTCv1,
		permanentBoxes: permanentBoxes,
	}
}

// Start runs the server
func (s *Server) Start(addr string) error {

	s.wp = workerpool.New(MaxWorkers)
	var err error

	ln := &listener{
		network: "tcp",
		addr:    addr,
	}

	ln.ln, err = net.Listen(ln.network, ln.addr)
	if err != nil {
		Sugar.Fatal(err)
	}
	ln.lnaddr = ln.ln.Addr()
	Sugar.Infof("websocket is listening on %s\n", ln.lnaddr.String())

	ln.system()

	poll := evpoll.OpenPoll()
	loop := &loop{
		poll:    poll,
		fdconns: make(map[int]*Conn),
	}
	poll.AddRead(ln.fd)
	return poll.Wait(func(fd int, note interface{}) error {
		Sugar.Infof("Trigger:fd: %v", fd)
		if fd == 0 {
			return loopNote(loop, note)
		}
		c := loop.fdconns[fd]
		switch {
		case c == nil:
			return loopAccept(fd, loop, ln)
		case !c.opened:
			return loopOpened(loop, ln, c)
		default:
			return s.loopRead(loop, ln, c)
		}
	})
}

var tickStarted bool

func (s *Server) handleTick(c *Conn) {
	if tickStarted {
		return
	}
	tickStarted = true
	go func() {
		for _ = range time.Tick(time.Second * 5) {
			// s.Write(c, []byte("ping"), "myCtx", func(ctx interface{}, err error) {
			// 	Sugar.Info(ctx, err)
			// })
			s.WriteCtrl(c, []byte("ping"))
		}
	}()
}

func (s *Server) loopRead(l *loop, ln *listener, c *Conn) error {
	if !c.upgraded {
		err := s.handleNewConn(l, ln, c)
		if c.upgraded {
			submitServerHello(l, c.client) // should we fire off by poll.Trigger?
		}
		return err
	}

	s.handleReceive(l, ln, c)
	return nil
}

func (s *Server) handleReceive(l *loop, ln *listener, c *Conn) {
	c.client.mux.Lock()

	Sugar.Info("Inside handleReceive")

	h, r, err := wsutil.NextReader(c.netConn, ws.StateServerSide)

	if err != nil {
		defer c.client.mux.Unlock()

		Sugar.Error(err)
		if _, ok := err.(ws.ProtocolError); ok || err == syscall.EAGAIN {
			io.Copy(ioutil.Discard, c.netConn) // discard incoming data to be ready for the next
			return
		}

		// l.poll.ModDetach(c.fd)
		// loopCloseConn(l, c, nil)
		Sugar.Info("connection closing..")
		c.Close(nil)
		s.paths.Prune(c.client.Path)
		return
	}

	if h.OpCode.IsControl() {
		defer c.client.mux.Unlock()

		if h.OpCode == ws.OpPing {
			l.poll.ModReadWrite(c.fd) // enable read-write mode to be able to write into header if OpCode is Ping or Close
			defer l.poll.ModRead(c.fd)
		}

		err := wsutil.ControlFrameHandler(c.netConn, ws.StateServerSide)(h, r)

		if err != nil || h.OpCode == ws.OpClose {
			Sugar.Error(err)

			if err == syscall.EAGAIN {
				return
			}
			Sugar.Info("connection closing..")
			// loopCloseConn(l, c, nil)
			c.Close(nil)
			c.client.DelFromPath()
			s.paths.Prune(c.client.Path)
		}
		return
	}

	s.wp.Submit(func() {
		defer c.client.mux.Unlock()
		b, err := ioutil.ReadAll(r)
		if h.OpCode.IsData() && err == nil {
			Sugar.Info("Submit")
			Sugar.Info("Call client.Received")
			c.client.Received(b)
			return
		}
		Sugar.Error(err)
	})
}

func (s *Server) handleNewConn(l *loop, ln *listener, c *Conn) (resultErr error) {
	l.poll.ModReadWrite(c.fd)
	defer l.poll.ModRead(c.fd)

	initiatorKey := ""
	upgrader := ws.Upgrader{
		OnRequest: func(uri []byte) error {
			initiatorKey = string(uri)[1:]
			return hexutil.IsValidHexPathString(initiatorKey)
		},
	}

	// Zero-copy upgrade to WebSocket connection.
	_, err := upgrader.Upgrade(c.netConn)

	if err != nil {
		if err == syscall.EAGAIN {
			return nil
		}
		Sugar.Error(err)
		return loopCloseConn(l, c, nil)
	}

	initiatorKeyBytes, err := hexutil.HexStringToBytes32(initiatorKey)
	if err != nil {
		Sugar.Error("Closing due to invalid key:", initiatorKey)
		loopCloseConn(l, c, CloseFrameInvalidKey)
		// clientConn.Close(CloseFrameInvalidKey) // **cls
		return err
	}

	var client *Client
	box, err := boxkeypair.GenerateBoxKeyPair()
	if err == nil {
		// TODO: we should keep oldPath unless handshake for newPath is completed
		path, _ := s.paths.GetOrCreate(initiatorKey)
		defaultPermanentBox := s.permanentBoxes[0]
		client, err = NewClient(c, *initiatorKeyBytes, defaultPermanentBox, box)
		client.Path = path
		client.Server = s
	}
	if err != nil || client == nil {
		Sugar.Error("Closing due to internal err:", err)
		client.conn.Close(CloseFrameInternalError)
		s.paths.Prune(client.Path)
		// loopCloseConn(l, c, CloseFrameInternalError)
		return err
	}

	// initialize the client
	c.client = client
	c.upgraded = true
	Sugar.Infof("Connection established. key:%s", initiatorKey)
	return nil
}

// Write ..
func (s *Server) Write(c *Conn, data []byte, ctx interface{}, cb func(ctx interface{}, err error)) {
	c.loop.poll.Trigger(&loopWriteNote{c: c, data: data, ctx: ctx, cb: cb})
}

// WriteCtrl ..
func (s *Server) WriteCtrl(c *Conn, data []byte) error {
	c.loop.poll.ModReadWrite(c.fd)
	defer c.loop.poll.ModRead(c.fd)
	return wsutil.WriteServerBinary(c.netConn, data)
}

func loopNote(l *loop, note interface{}) error {
	var err error
	switch v := note.(type) {
	case error: // shutdown
		err = v
	case *loopWriteNote:
		// Wake called for connection
		if l.fdconns[v.c.fd] != v.c {
			return nil // ignore stale wakes
		}
		return handleLoopWrite(l, v)
	}
	return err
}

func loopAccept(fd int, l *loop, ln *listener) error {
	if fd == ln.fd {
		conn, err := ln.ln.Accept()
		nfd := socketFD(conn)
		if err != nil {
			if err == syscall.EAGAIN {
				return nil
			}
			conn.Close()
			return err
		}

		if err := syscall.SetNonblock(nfd, true); err != nil {
			conn.Close()
			return err
		}

		c := &Conn{netConn: conn, fd: nfd, loop: l}
		l.fdconns[c.fd] = c
		l.poll.AddReadWrite(c.fd)
		atomic.AddInt32(&l.count, 1)
	}
	return nil
}

func loopOpened(l *loop, ln *listener, c *Conn) error {
	c.opened = true
	c.remoteAddr = c.netConn.RemoteAddr()
	l.poll.ModRead(c.fd)
	return nil
}

func loopCloseConn(l *loop, c *Conn, preWrite []byte) error {
	if preWrite != nil {
		c.netConn.Write(preWrite)
	}
	atomic.AddInt32(&l.count, -1)
	delete(l.fdconns, c.fd)
	syscall.Close(c.fd)
	return nil
}

func submitServerHello(l *loop, client *Client) {
	server := client.Server
	server.wp.Submit(func() {
		Sugar.Infof("about to submit server hello msg.")
		client.mux.Lock()
		defer client.mux.Unlock()
		client.sendServerHello()
	})

	// go func() {
	// 	time.Sleep(time.Second * 8)
	// 	Sugar.Info("ready to fire-off")
	// 	client.mux.Lock()
	// 	defer client.mux.Unlock()
	// 	if trigger == SendServerHelloMsg {
	// 		cb := &CallbackBag{}
	// 		ok, errx := client.machine.Fire(SendServerHelloMsg, cb)
	// 		Sugar.Infof("cb:%#v ok:%#v err:%#v", cb, ok, errx)
	// 		if !ok && cb.err != nil {
	// 			// todo: handle errors gracefully
	// 			// client.conn.Close(CloseFrameInternalError)
	// 			loopCloseConn(l, client.connx, CloseFrameInternalError)
	// 		}
	// 	}
	// }()

}

func handleLoopWrite(l *loop, note *loopWriteNote) error {
	l.poll.ModReadWrite(note.c.fd)
	defer l.poll.ModRead(note.c.fd)
	err := wsutil.WriteServerBinary(note.c.netConn, note.data)
	if err != nil {
		Sugar.Error(err)
		if err == syscall.EAGAIN {
			note.cb(note.ctx, err)
			return nil
		}
		loopCloseConn(l, note.c, nil)
	}
	note.cb(note.ctx, err) // should we invoke callback by poll.Trigger??
	return nil
}

type loopWriteNote struct {
	c    *Conn
	data []byte
	ctx  interface{}
	cb   func(ctx interface{}, err error)
}
