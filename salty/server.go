package salty

import (
	"crypto/tls"
	"errors"
	"io"
	"net"
	"sync/atomic"
	"syscall"

	"github.com/OguzhanE/saltyrtc-server-go/pkg/crypto/nacl"
	"github.com/OguzhanE/saltyrtc-server-go/pkg/encoding/hexutil"

	"github.com/OguzhanE/saltyrtc-server-go/pkg/evpoll"
	prot "github.com/OguzhanE/saltyrtc-server-go/salty/protocol"
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
	wp             *workerpool.WorkerPool
	subprotocols   []string
	subprotocol    string
	permanentBoxes []*nacl.BoxKeyPair
}

// NewServer creates new server instance
func NewServer(permanentBox nacl.BoxKeyPair) *Server {
	permanentBoxes := []*nacl.BoxKeyPair{
		&permanentBox,
	}
	return &Server{
		paths:          NewPaths(),
		subprotocols:   []string{prot.SubprotocolSaltyRTCv1},
		subprotocol:    prot.SubprotocolSaltyRTCv1,
		permanentBoxes: permanentBoxes,
	}
}

var config *tls.Config

// Start runs the server
func (s *Server) Start(addr string) error {
	var err error
	cer, err := tls.LoadX509KeyPair("/home/ogz/localhost.pem", "/home/ogz/localhost-key.pem")
	if err != nil {
		panic(err)
	}
	config = &tls.Config{Certificates: []tls.Certificate{cer}}

	s.wp = workerpool.New(MaxWorkers)

	// httpServ := new(http.Server)
	ln := &listener{
		network: "tcp",
		addr:    addr,
	}

	tcpLn, err := net.Listen(ln.network, ln.addr)
	if err != nil {
		Sugar.Fatal(err)
	}

	ln.ln = tls.NewListener(tcpLn, config)

	// if err != nil {
	// 	Sugar.Fatal(err)
	// }

	ln.lnaddr = ln.ln.Addr()
	Sugar.Info("Connection listening on ", ln.lnaddr.String())

	ln.system(tcpLn)

	poll := evpoll.OpenPoll()
	loop := &loop{
		poll:    poll,
		fdconns: make(map[int]*Conn),
	}
	poll.AddReadOnce(ln.fd)

	Sugar.Debug("Waiting for an I/O event on an connection file descriptor")
	return poll.Wait(func(fd int, note interface{}) error {
		Sugar.Debug("Triggered for an event on fd: ", fd)
		if fd == ln.fd {
			defer poll.ModReadOnce(fd)
		}
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
	Sugar.Debug("Enqueuing a task to worker pool to handle receiving data")
	s.wp.Submit(func() {
		Sugar.Debug("The task invoked by a worker to handle receiving data")

		c.client.mux.Lock()
		defer c.client.mux.Unlock()

		Sugar.Debug("Reading ws client data..")
		data, op, err := wsutil.ReadClientData(c)

		Sugar.Debug("Client data is read. OpCode: ", op)

		if err != nil {

			if _, ok := err.(ws.ProtocolError); ok || err == syscall.EAGAIN {
				Sugar.Debug(err)
				// io.Copy(ioutil.Discard, c.netConn) // discard incoming data to be ready for the next
				return
			}

			Sugar.Error("Error occurred while reading client data :", err)
			Sugar.Info("connection closing..")

			c.Close(nil)
			c.client.DelFromPath()
			s.paths.Prune(c.client.Path)
			return
		}

		if op.IsData() {
			c.client.Received(data)
		}
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
		Sugar.Error("Could not upgrade connection to websocket :", err)
		return loopCloseConn(l, c, nil)
	}

	initiatorKeyBytes, err := hexutil.HexStringToBytes32(initiatorKey)
	if err != nil {
		Sugar.Warn("Closing due to invalid path key :", initiatorKey)
		loopCloseConn(l, c, CloseFrameInvalidKey)
		return err
	}

	var client *Client
	box, err := nacl.GenerateBoxKeyPair()
	path, _ := s.paths.GetOrCreate(initiatorKey)
	defaultPermanentBox := s.permanentBoxes[0]

	if client, _ = NewClient(c, *initiatorKeyBytes, defaultPermanentBox, box); client != nil {
		client.Path = path
		client.Server = s
	}

	if err != nil || client == nil {
		Sugar.Error("Closing due to internal err :", err)
		c.Close(CloseFrameInternalError)
		s.paths.Prune(path)
		return err
	}

	// initialize the client
	c.client = client
	c.upgraded = true
	Sugar.Info("Connection established with the key :", initiatorKey)
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

// tlsRecordHeaderLooksLikeHTTP reports whether a TLS record header
// looks like it might've been a misdirected plaintext HTTP request.
func tlsRecordHeaderLooksLikeHTTP(hdr [5]byte) bool {
	switch string(hdr[:]) {
	case "GET /", "HEAD ", "POST ", "PUT /", "OPTIO":
		return true
	}
	return false
}

func loopAccept(fd int, l *loop, ln *listener) error {
	if fd == ln.fd {
		conn, err := ln.ln.Accept()

		tlsConn, _ := conn.(*tls.Conn)
		if err := tlsConn.Handshake(); err != nil {
			Sugar.Error(err)
			// If the handshake failed due to the client not speaking
			// TLS, assume they're speaking plaintext HTTP and write a
			// 400 response on the TLS conn's underlying net.Conn.
			if re, ok := err.(tls.RecordHeaderError); ok && re.Conn != nil && tlsRecordHeaderLooksLikeHTTP(re.RecordHeader) {
				io.WriteString(re.Conn, "HTTP/1.0 400 Bad Request\r\n\r\nClient sent an HTTP request to an HTTPS server.\n")
				re.Conn.Close()
				return errors.New("tls handshake failed")
			}
			// c.server.logf("http: TLS handshake error from %s: %v", c.rwc.RemoteAddr(), err)
			return errors.New("tls handshake failed")
		}

		nfd, _ := socketFD(conn)
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
		Sugar.Debug("About to submit server hello message")
		client.mux.Lock()
		defer client.mux.Unlock()
		client.sendServerHello()
	})
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
