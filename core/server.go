package core

import (
	"fmt"
	"log"
	"net"
	"time"

	"github.com/OguzhanE/saltyrtc-server-go/pkg/base"
	"github.com/OguzhanE/saltyrtc-server-go/pkg/boxkeypair"

	"github.com/OguzhanE/saltyrtc-server-go/pkg/gopool"
	"github.com/OguzhanE/saltyrtc-server-go/pkg/hexutil"
	ws "github.com/gobwas/ws"
	"github.com/mailru/easygo/netpoll"
)

var ErrScheduleTimeout = fmt.Errorf("schedule error: timed out")

const (
	MaxJobs    = 32
	MaxWorkers = 8
)

// Server handles clients
type Server struct {
	paths          *Paths
	jobQueue       chan gopool.Job
	subprotocols   []string
	subprotocol    string
	permanentBoxes []*boxkeypair.BoxKeyPair
}

// NewServer creates new server instance
func NewServer() *Server {
	return &Server{
		paths:        NewPaths(),
		subprotocols: []string{base.SubprotocolSaltyRTCv1},
		subprotocol:  base.SubprotocolSaltyRTCv1,
	}
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
	hs, err := upgrader.Upgrade(clientConn)

	if err != nil {
		log.Printf("%s: upgrade error: %v", conn.RemoteAddr().String(), err)
		closeClientConn(clientConn, base.CloseCodeProtocolError)
		return
	}

	log.Printf("%s: established websocket connection: %+v", conn.RemoteAddr().String(), hs)

	// creates new path if it does not exist
	path, pathExists := s.paths.Get(initiatorKey)
	if !pathExists {
		path = s.paths.AddNewPath(initiatorKey)
		if path == nil {
			log.Printf("cannot create new path, key:%s.", initiatorKey)
			closeClientConn(clientConn, base.CloseCodeInternalError)
			return
		}
	}

	initiatorKeyBytes, err := hexutil.HexStringToBytes32(initiatorKey)
	if err != nil {
		log.Println("Closing due to invalid key:", initiatorKey)
		closeClientConn(clientConn, base.CloseCodeInternalError)
		// todo: free up the path if it is necessary
		return
	}
	var client *Client
	box, err := boxkeypair.GenerateBoxKeyPair()
	if err == nil {
		// TODO: pass appropriate params (permanent box)
		client, err = NewClient(&clientConn, *initiatorKeyBytes, nil, box)
		client.Path = path
		client.Server = s
	}
	if err != nil || client == nil {
		log.Println("Closing due to internal err:", err)
		closeClientConn(clientConn, base.CloseCodeInternalError)
		return
	}
	log.Println("Connection established. key:", initiatorKey)
	fmt.Println(client)
	// Create netpoll event descriptor for conn.
	// We want to handle only read events of it.
	desc := netpoll.Must(netpoll.HandleRead(conn))

	// Subscribe to events about conn.
	poller.Start(desc, func(ev netpoll.Event) {
		if ev&(netpoll.EventReadHup|netpoll.EventHup) != 0 {
			// When ReadHup or Hup received, this mean that client has
			// closed at least write end of the connection or connections
			// itself. So we want to stop receive events about such conn
			// and remove it
			poller.Stop(desc)
			// TODO: remove client
			return
		}

		// Here we can read some new message from connection.
		// We can not read it right here in callback, because then we will
		// block the poller's inner loop.
		// We do not want to spawn a new goroutine to read single message.
		// But we want to reuse previously spawned goroutine.
		s.ScheduleJobToQueue(gopool.NewTask(func() {
			if err != nil {
				// When receive failed, we can only disconnect broken
				// connection and stop to receive events about it.
				poller.Stop(desc)
				// TODO: remove client
			}
		}), 2, 2)
	})
}

// Start runs the server
func (s *Server) Start(addr *string) error {
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

	log.Printf("websocket is listening on %s", ln.Addr().String())

	// Create netpoll descriptor for the listener.
	// We use OneShot here to manually resume events stream when we want to.
	acceptDesc := netpoll.Must(netpoll.HandleListener(
		ln, netpoll.EventRead|netpoll.EventOneShot,
	))

	// initilize job workerpool
	s.jobQueue = make(chan gopool.Job, MaxJobs)
	dispatcher := gopool.NewDispatcher(s.jobQueue, MaxWorkers)
	dispatcher.Run()

	// accept is a channel to signal about next incoming connection Accept()
	// results.

	poller.Start(acceptDesc, func(e netpoll.Event) {
		// We do not want to accept incoming connection when goroutine pool is
		// busy. So if there are no free goroutines during 2ms we want to
		// cooldown the server and do not receive connection for some short
		// time.
		s.ScheduleJobToQueue(gopool.NewTask(func() {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			s.handleNewConnection(poller, conn)
		}), 2, 2)

		poller.Resume(acceptDesc)
	})

	return nil
}

// ScheduleJobToQueue tries to add job to queue
func (s *Server) ScheduleJobToQueue(job gopool.Job, retryCount int, durationMs time.Duration) error {
	tryCount := 0
	for {
		select {
		case s.jobQueue <- job:
			return nil
		default:
			if tryCount < retryCount {
				tryCount++
				time.Sleep(durationMs * time.Millisecond)
			} else {
				return ErrScheduleTimeout
			}
		}
	}
}

func closeClientConn(c ClientConn, messageType int) error {
	log.Println("Connection closing..")
	//TODO: close conn with messageType
	// wsConn.WriteMessage(messageType, []byte(nil))
	err := c.Conn.Close()

	if err != nil {
		log.Printf("connection cannot be closed. err:%s\n", err)
	}
	return err
}
