package core

import (
	"bytes"
	"errors"
	"io/ioutil"
	"sync"

	"github.com/OguzhanE/saltyrtc-server-go/pkg/arrayutil"
	"github.com/OguzhanE/saltyrtc-server-go/pkg/base"

	"github.com/OguzhanE/saltyrtc-server-go/pkg/boxkeypair"
	"github.com/OguzhanE/saltyrtc-server-go/pkg/naclutil"
	"github.com/OguzhanE/saltyrtc-server-go/pkg/randutil"
	ws "github.com/gobwas/ws"
	"github.com/gobwas/ws/wsutil"

	"github.com/OguzhanE/statmach"
)

// STATES
const (
	None            = "None"
	ClientConnected = "client-connected" // waiting for server-hello message
	ServerHello     = "server-hello"
	ClientHello     = "client-hello"
	ClientAuth      = "client-auth"
	ServerAuth      = "server-auth"

	NewResponder  = "new-responder"
	DropResponder = "drop-responder"

	NewInitiator = "new-itiator"

	SendError    = "send-error"
	Disconnected = "disconnected"

	InitiatorSuperState = "initiator-super-state"
	ResponderSuperState = "responder-super-state"
)

// Triggers
const (
	SendServerHelloMsg  = "sendServerHelloMessage"
	GetClientHelloMsg   = "getClientHelloMessage"
	GetClientAuthMsg    = "getClientAuthMessage"
	SendServerAuthMsg   = "sendServerAuthMessage"
	SendNewInitiatorMsg = "sendNewInitiatorMessage"
	SendNewResponderMsg = "sendNewResponderMessage"
	GetDropResponderMsg = "getDropResponderMessage"
	SendSendErrorMsg    = "sendSendErrorMessage"
	SendDisconnectedMsg = "sendDisconnectedMessage"
)

type CallbackBag struct {
	err error
}

type Client struct {
	mux     sync.Mutex
	conn    *ClientConn
	machine *statmach.StateMachine

	ClientKey          [base.KeyBytesSize]byte
	ServerSessionBox   *boxkeypair.BoxKeyPair
	ServerPermanentBox *boxkeypair.BoxKeyPair
	CookieOut          []byte
	cookieIn           []byte

	CombinedSequenceNumberOut *CombinedSequenceNumber
	CombinedSequenceNumberIn  *CombinedSequenceNumber

	Authenticated bool
	Id            base.AddressType
	typeValue     base.AddressType
	typeHasValue  bool
	Path          *Path
	Server        *Server
}

func (c *Client) Init() {
	sm := statmach.New(ClientConnected)
	c.machine = sm
	sc := sm.Configure(ClientConnected)
	// ClientConnected->ServerHello
	sc.PermitIf(SendServerHelloMsg, ServerHello, func(params ...interface{}) bool {
		bag, _ := params[0].(*CallbackBag)

		msg := NewServerHelloMessage(base.Server, c.Id, c.ServerSessionBox.Pk[:])
		err := c.Send(msg)
		if err != nil {
			bag.err = err
			return false
		}
		return true
	})

	// configure ServerHello
	sc = sm.Configure(ServerHello)
	// ServerHello->ClientHello
	sc.PermitIf(GetClientHelloMsg, ClientHello, func(params ...interface{}) bool {
		bag, _ := params[0].(*CallbackBag)
		msg, _ := params[1].(*ClientHelloMessage)

		_, hasType := c.GetType()
		if hasType {
			bag.err = errors.New("client already has type")
			return false
		}
		if naclutil.IsValidBoxPkBytes(msg.clientPublicKey) {
			bag.err = errors.New("invalid client public key length")
			return false
		}
		c.SetType(base.Responder)
		copy(c.ClientKey[:], msg.clientPublicKey[0:base.KeyBytesSize])
		return true
	})

	// ServerHello->ClientAuth transition states the method below for initiator handshake
	sc.PermitIf(GetClientAuthMsg, ClientAuth, func(params ...interface{}) bool {
		bag, _ := params[0].(*CallbackBag)
		msg, _ := params[1].(*ClientAuthMessage)
		// validate your_cookie with cookieOut
		if !bytes.Equal(msg.serverCookie, c.CookieOut) {
			bag.err = errors.New("Cookies do not match")
			return false
		}
		presentSubprotocols := arrayutil.IntersectionStr(msg.subprotocols, c.Server.subprotocols)
		if len(presentSubprotocols) == 0 || presentSubprotocols[0] != c.Server.subprotocol {
			bag.err = errors.New("Invalid subprotocol")
			return false
		}
		// todo impl. ping(ing) logic
		if len(c.Server.permanentBoxes) == 0 {
			bag.err = errors.New("the server does not have a permanent key pair")
			return false
		}
		for _, box := range c.Server.permanentBoxes {
			if box.PkEqualTo(msg.serverKey) {
				// box is selected for further usage
				c.ServerPermanentBox = box.Clone()
				break
			}
		}
		if c.ServerPermanentBox == nil {
			bag.err = errors.New("yourKey matches none of the server permanent key pairs")
			return false
		}

		return true
	})

	// configure ClientHello
	sc = sm.Configure(ClientHello)
	// ClientHello->ClientAuth transition states the method below for responder handshake
	sc.PermitIf(GetClientAuthMsg, ClientAuth, func(params ...interface{}) bool {
		bag, _ := params[0].(*CallbackBag)
		msg, _ := params[1].(*ClientAuthMessage)
		// validate your_cookie with cookieOut
		if !bytes.Equal(msg.serverCookie, c.CookieOut) {
			bag.err = errors.New("Cookies do not match")
			return false
		}
		presentSubprotocols := arrayutil.IntersectionStr(msg.subprotocols, c.Server.subprotocols)
		if len(presentSubprotocols) == 0 || presentSubprotocols[0] != c.Server.subprotocol {
			bag.err = errors.New("Invalid subprotocol")
			return false
		}
		// todo impl. ping(ing) logic
		if len(c.Server.permanentBoxes) == 0 {
			bag.err = errors.New("the server does not have a permanent key pair")
			return false
		}
		for _, box := range c.Server.permanentBoxes {
			if box.PkEqualTo(msg.serverKey) {
				// box is selected for further usage
				c.ServerPermanentBox = box.Clone()
				break
			}
		}
		if c.ServerPermanentBox == nil {
			bag.err = errors.New("yourKey matches none of the server permanent key pairs")
			return false
		}

		return true
	})

	// configure ClientAuth
	sc = sm.Configure(ClientAuth)
	// ClientAuth->ServerAuth
	sc.PermitIf(SendServerAuthMsg, ServerAuth, func(params ...interface{}) bool {
		bag, _ := params[0].(*CallbackBag)
		var msg *ServerAuthMessage

		c.Path.mux.Lock()
		if clientType, _ := c.GetType(); clientType == base.Initiator {
			if prevClient, ok := c.Path.GetInitiator(); ok && prevClient != c {
				// todo: kill prevClient
			}
			c.Path.SetInitiator(c)
			msg = NewServerAuthMessageForInitiator(base.Server, c.Id, c.GetCookieIn(), len(c.Server.permanentBoxes) > 0, c.Path.GetResponderIds())
		} else {
			if _, err := c.Path.AddResponder(c); err != nil { // responder
				defer c.Path.mux.Unlock()
				bag.err = errors.New("Path Full")
				return false
			}
			_, initiatorConnected := c.Path.GetInitiator()
			msg = NewServerAuthMessageForResponder(base.Server, c.Id, c.GetCookieIn(), len(c.Server.permanentBoxes) > 0, initiatorConnected)
		}
		c.Path.mux.Unlock()

		err := c.Send(msg)
		if err != nil {
			bag.err = err
			return false
		}
		return true
	})

	// configure ServerAuth
	sc = sm.Configure(ServerAuth)
	// ServerAuth->NewInitiator
	sc.PermitIf(SendNewInitiatorMsg, NewInitiator, func(params ...interface{}) bool {

		return true
	})
	sc.PermitIf(SendSendErrorMsg, SendError, func(params ...interface{}) bool {

		return true
	})
	sc.PermitIf(SendDisconnectedMsg, Disconnected, func(params ...interface{}) bool {

		return true
	})
	sc.PermitIf(GetDropResponderMsg, DropResponder, func(params ...interface{}) bool {

		return true
	})
	sc.PermitIf(SendNewResponderMsg, NewResponder, func(params ...interface{}) bool {

		return true
	})

	// configure NewResponder
	sc = sm.Configure(NewResponder)
	sc.SubstateOf(InitiatorSuperState)
	// configure DropResponder
	sc = sm.Configure(DropResponder)
	sc.SubstateOf(InitiatorSuperState)

	// configure InitiatorSuperState
	sc = sm.Configure(InitiatorSuperState)
	sc.PermitIf(SendNewResponderMsg, NewResponder, func(params ...interface{}) bool {
		return true
	})
	sc.PermitIf(GetDropResponderMsg, DropResponder, func(params ...interface{}) bool {

		return true
	})
	sc.PermitIf(SendSendErrorMsg, SendError, func(params ...interface{}) bool {
		return true
	})
	sc.PermitIf(SendDisconnectedMsg, Disconnected, func(params ...interface{}) bool {
		return true
	})

	// configure NewInitiator
	sc = sm.Configure(NewInitiator)
	sc.PermitReentryIf(SendNewInitiatorMsg, func(params ...interface{}) bool {

		return true
	})
	sc.PermitIf(SendSendErrorMsg, SendError, func(params ...interface{}) bool {

		return true
	})
	sc.PermitIf(SendDisconnectedMsg, Disconnected, func(params ...interface{}) bool {

		return true
	})

	// configure SendError
	sc = sm.Configure(SendError)
	sc.PermitReentryIf(SendSendErrorMsg, func(params ...interface{}) bool {
		return true
	})
	sc.PermitIf(SendDisconnectedMsg, Disconnected, func(params ...interface{}) bool {
		return true
	})
	sc.PermitIf(SendNewInitiatorMsg, NewInitiator, func(params ...interface{}) bool {
		return true
	})
	sc.PermitIf(SendNewResponderMsg, NewResponder, func(params ...interface{}) bool {
		return true
	})
	sc.PermitIf(GetDropResponderMsg, DropResponder, func(params ...interface{}) bool {
		return true
	})
	// configure Disconnected
	sc = sm.Configure(Disconnected)
	sc.PermitReentryIf(SendDisconnectedMsg, func(params ...interface{}) bool {
		return true
	})
	sc.PermitIf(SendSendErrorMsg, SendError, func(params ...interface{}) bool {
		return true
	})
	sc.PermitIf(SendNewInitiatorMsg, NewInitiator, func(params ...interface{}) bool {
		return true
	})
	sc.PermitIf(SendNewResponderMsg, NewResponder, func(params ...interface{}) bool {
		return true
	})
	sc.PermitIf(GetDropResponderMsg, DropResponder, func(params ...interface{}) bool {
		return true
	})
}

// todo: implement it properly
func NewClient(conn *ClientConn, clientKey [base.KeyBytesSize]byte, permanentBox, sessionBox *boxkeypair.BoxKeyPair) (*Client, error) {
	cookieOut, err := randutil.RandBytes(16)
	if err != nil {
		return nil, err
	}
	initialSeqNum, err := randutil.RandUint32()
	if err != nil {
		return nil, err
	}
	return &Client{
		conn:                      conn,
		ClientKey:                 clientKey,
		CookieOut:                 cookieOut,
		CombinedSequenceNumberOut: NewCombinedSequenceNumber(initialSeqNum),
		ServerPermanentBox:        permanentBox,
		ServerSessionBox:          sessionBox,
	}, nil
}

func (c *Client) GetCookieIn() []byte {
	return c.cookieIn
}

func (c *Client) CheckAndSetCookieIn(cookieIn []byte) *base.CheckUp {
	chkUp := base.NewCheckUp()
	if c.cookieIn == nil {
		if bytes.Equal(cookieIn, c.CookieOut) {
			chkUp.SetErr(errors.New("Server and client cookies cannot be the same"))
			return chkUp
		}
		chkUp.Push(func() error { c.cookieIn = cookieIn; return nil })
		return chkUp
	} else {
		if !bytes.Equal(c.cookieIn, cookieIn) {
			chkUp.SetErr(errors.New("Client cookie is not changeable"))
			return chkUp
		}
	}
	return chkUp
}

func (c *Client) GetType() (base.AddressType, bool) {
	return c.typeValue, c.typeHasValue
}
func (c *Client) SetType(t base.AddressType) {
	c.typeHasValue = true
	c.typeValue = t
}

// Receive reads next message from Client's underlying connection.
// It blocks until full message received.
func (c *Client) Receive() error {
	c.mux.Lock()
	defer c.mux.Unlock()

	msgIncoming, err := c.readIncomingMessage()
	if err != nil {
		// c.conn.Close()
		// todo: close connection
		return err
	}
	if msgIncoming == nil {
		// Handled some control message.
		return nil
	}
	if msg, ok := msgIncoming.(*ClientHelloMessage); ok {
		c.machine.Fire(ClientHello, msg)
	}
	// todo: handle all messages
	return nil
}

// readIncomingMessage reads and unpacks received data from connection.
// It takes io mutex.
func (c *Client) readIncomingMessage() (BaseMessage, error) {
	h, r, err := wsutil.NextReader(c.conn, ws.StateServerSide)
	if err != nil {
		return nil, err
	}
	if h.OpCode.IsControl() {
		return nil, wsutil.ControlFrameHandler(c.conn, ws.StateServerSide)(h, r)
	}
	// read all raw data
	b, err := ioutil.ReadAll(r)
	if err != nil {
		return nil, err
	}

	// try to unpack data in order to obtain message
	msg, err := Unpack(c, b)
	if err != nil {
		return nil, err
	}

	return msg, nil
}

func (c *Client) Send(msg BaseMessagePacker) error {
	b, err := msg.Pack(c)
	if err != nil {
		return err
	}
	_, err = c.conn.Write(b)
	return err
}
