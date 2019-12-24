package core

import (
	"io/ioutil"
	"log"
	"net"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/OguzhanE/saltyrtc-server-go/pkg/base"
	"github.com/OguzhanE/saltyrtc-server-go/pkg/boxkeypair"

	"github.com/OguzhanE/saltyrtc-server-go/pkg/evpoll"
	"github.com/OguzhanE/saltyrtc-server-go/pkg/gopool"
	"github.com/OguzhanE/saltyrtc-server-go/pkg/hexutil"
	"github.com/gammazero/workerpool"
	ws "github.com/gobwas/ws"
	"github.com/gobwas/ws/wsutil"
	"github.com/mailru/easygo/netpoll"
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
func NewServer() *Server {
	defaultBox, _ := boxkeypair.GenerateBoxKeyPair()
	permanentBoxes := []*boxkeypair.BoxKeyPair{
		defaultBox,
	}
	Sugar.Infof("defaultServerBoxPk: %x", defaultBox.Pk)
	return &Server{
		paths:          NewPaths(),
		subprotocols:   []string{base.SubprotocolSaltyRTCv1},
		subprotocol:    base.SubprotocolSaltyRTCv1,
		permanentBoxes: permanentBoxes,
	}
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

func loopCloseConn(l *loop, c *Conn) error {
	atomic.AddInt32(&l.count, -1)
	delete(l.fdconns, c.fd)
	syscall.Close(c.fd)
	return nil
}

func loopRead(l *loop, ln *listener, c *Conn) error {
	if !c.upgraded {
		l.poll.ModReadWrite(c.fd)
		defer l.poll.ModRead(c.fd)
		upgrader := ws.Upgrader{}
		_, err := upgrader.Upgrade(c.netConn)
		if err != nil {
			if err == syscall.EAGAIN {
				return nil
			}
			Sugar.Error(err)
			return loopCloseConn(l, c)
		}
		c.upgraded = true
		return nil
	}
	h, r, err := wsutil.NextReader(c.netConn, ws.StateServerSide)
	if err != nil {
		Sugar.Error(err)
		return nil
	}
	if h.OpCode.IsControl() {
		err := wsutil.ControlFrameHandler(c.netConn, ws.StateServerSide)(h, r)
		Sugar.Error(err)

		if err != nil {
			Sugar.Error(err)
			if _, ok := err.(wsutil.ClosedError); ok {
				Sugar.Info("connection closing..")
				loopCloseConn(l, c)
			}
		}
		return nil
	}

	// read all raw data
	b, err := ioutil.ReadAll(r)
	if err != nil {
		Sugar.Error(err)
		return nil
	}
	log.Printf("WSDATA: %s", strings.TrimSpace(string(b)))
	l.poll.ModReadWrite(c.fd)
	defer l.poll.ModRead(c.fd)
	return wsutil.WriteServerBinary(c.netConn, b)
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
		if fd == 0 {
			return nil
		}
		c := loop.fdconns[fd]
		switch {
		case c == nil:
			return loopAccept(fd, loop, ln)
		case !c.opened:
			return loopOpened(loop, ln, c)
		default:
			return loopRead(loop, ln, c)
		}
	})
}

func (s *Server) handleNewConnection(poller netpoll.Poller, conn net.Conn) {
	// NOTE: we wrap conn here to show that ws could work with any kind of
	// io.ReadWriter.
	clientConn := NewClientConn(&conn, time.Millisecond*100)
	initiatorKey := ""
	upgrader := ws.Upgrader{
		OnRequest: func(uri []byte) error {
			initiatorKey = string(uri)[1:]
			return hexutil.IsValidHexPathString(initiatorKey)
		},
	}
	// Zero-copy upgrade to WebSocket connection.
	_, err := upgrader.Upgrade(clientConn)

	if err != nil {
		Sugar.Debugf("%s: upgrade error: %+v", conn.RemoteAddr().String(), err)
		clientConn.Close(CloseFrameProtocolError)
		return
	}

	initiatorKeyBytes, err := hexutil.HexStringToBytes32(initiatorKey)
	if err != nil {
		Sugar.Error("Closing due to invalid key:", initiatorKey)
		clientConn.Close(CloseFrameInvalidKey)
		return
	}
	var client *Client
	box, err := boxkeypair.GenerateBoxKeyPair()
	if err == nil {
		// TODO: we should keep oldPath unless handshake for newPath is completed
		path, oldPath := s.paths.Add(initiatorKey)
		if oldPath != nil && path != oldPath {
			oldPath.MarkAsDeath()
			path.Prune(func(c *Client) bool {
				c.CloseConn(CloseFrameNormalClosure)
				c.MarkAsDeathIfConnDeath()
				return true
			})
		}
		defaultPermanentBox := s.permanentBoxes[0]
		client, err = NewClient(&clientConn, *initiatorKeyBytes, defaultPermanentBox, box)
		client.Path = path
		client.Server = s
	}
	if err != nil || client == nil {
		Sugar.Error("Closing due to internal err:", err)
		clientConn.Close(CloseFrameInternalError)
		return
	}
	// initialize the client
	client.Init()
	Sugar.Infof("Connection established. key:%s", initiatorKey)
	// Create netpoll event descriptor for conn.
	// We want to handle only read events of it.
	desc := netpoll.Must(netpoll.HandleRead(conn))

	// Subscribe to events about conn.
	poller.Start(desc, func(ev netpoll.Event) {
		if ev&(netpoll.EventReadHup|netpoll.EventHup) != 0 || client.AliveStat != base.AliveStatActive {
			// When ReadHup or Hup received, this mean that client has
			// closed at least write end of the connection or connections
			// itself. So we want to stop receive events about such conn
			// and remove it
			poller.Stop(desc)
			{
				path := client.Path
				client.CloseConn(CloseFrameNormalClosure)
				client.MarkAsDeathIfConnDeath()

				pathInitiator, ok := path.GetInitiator()
				isPathInitClient := (ok && pathInitiator == client)
				if isPathInitClient {
					path.RemoveClient(client)
				}
				if (path.AliveStat&base.AliveStatDeath) != base.AliveStatDeath || isPathInitClient {
					path.MarkAsDeath()
					s.paths.RemovePath(path)
					path.Prune(func(c *Client) bool {
						c.CloseConn(CloseFrameNormalClosure)
						c.MarkAsDeathIfConnDeath()
						return true
					})
				}
				return
			}
		}

		s.wp.Submit(func() {
			err := client.Receive()
			if err != nil {
				// When receive failed, we can only disconnect broken
				// connection and stop to receive events about it.
				poller.Stop(desc)
				{
					path := client.Path
					client.CloseConn(CloseFrameNormalClosure)
					client.MarkAsDeathIfConnDeath()

					pathInitiator, ok := path.GetInitiator()
					isPathInitClient := (ok && pathInitiator == client)
					if isPathInitClient {
						path.RemoveClient(client)
					}
					if (path.AliveStat&base.AliveStatDeath) != base.AliveStatDeath || isPathInitClient {
						path.MarkAsDeath()
						s.paths.RemovePath(path)
						path.Prune(func(c *Client) bool {
							c.CloseConn(CloseFrameNormalClosure)
							c.MarkAsDeathIfConnDeath()
							return true
						})
					}
				}
			}
		})
	})
	// fire off the first message
	handleOutgoingMsg(client, SendServerHelloMsg)
}

func handleOutgoingMsg(client *Client, trigger string) {
	server := client.Server
	server.wp.Submit(func() {
		client.mux.Lock()
		defer client.mux.Unlock()
		if trigger == SendServerHelloMsg {
			cb := &CallbackBag{}
			ok, errx := client.machine.Fire(SendServerHelloMsg, cb)
			Sugar.Infof("cb:%#v\nok:%#v\nerrx:%#v\n", cb, ok, errx)
			if !ok && cb.err != nil {
				// todo: handle errors gracefully
				client.conn.Close(CloseFrameInternalError)
			}
		}
	})
}
