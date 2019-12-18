package core

import (
	"log"
	"net"
	"time"

	"github.com/OguzhanE/saltyrtc-server-go/pkg/base"
	"github.com/OguzhanE/saltyrtc-server-go/pkg/boxkeypair"

	"github.com/OguzhanE/saltyrtc-server-go/pkg/gopool"
	"github.com/OguzhanE/saltyrtc-server-go/pkg/hexutil"
	"github.com/gammazero/workerpool"
	ws "github.com/gobwas/ws"
	"github.com/mailru/easygo/netpoll"
)

const (
	MaxJobs    = 32
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

// Start runs the server
func (s *Server) Start(addr *string) error {
	s.wp = workerpool.New(MaxWorkers)

	// Initialize netpoll instance. We will use it to be noticed about incoming
	// events from listener of user connections.
	poller, err := netpoll.New(nil)
	if err != nil {
		return err
	}

	// Create incoming connections listener.
	ln, err := net.Listen("tcp", *addr)
	if err != nil {
		log.Fatal(err)
	}

	Sugar.Infof("websocket is listening on %s", ln.Addr().String())

	// Create netpoll descriptor for the listener.
	// We use OneShot here to manually resume events stream when we want to.
	acceptDesc := netpoll.Must(netpoll.HandleListener(
		ln, netpoll.EventRead|netpoll.EventOneShot,
	))

	// accept is a channel to signal about next incoming connection Accept()
	// results.
	poller.Start(acceptDesc, func(e netpoll.Event) {
		s.wp.Submit(func() {

			conn, err := ln.Accept()
			if err != nil {
				Sugar.Error(err)
				return
			}
			s.handleNewConnection(poller, conn)
		})

		poller.Resume(acceptDesc)
	})

	return nil
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
