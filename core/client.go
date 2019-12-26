package core

import (
	"bytes"
	"errors"
	"io/ioutil"
	"strings"
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

// CallbackBag ..
type CallbackBag struct {
	err error
}

// Client ..
type Client struct {
	mux     sync.Mutex
	conn    *ClientConn
	connx   *Conn
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
	AliveStat     base.AliveStatType
}

func (c *Client) configureServerHello() {
	// configure ServerHello
	sc := c.machine.Configure(ServerHello)
	sc.OnExit(handleOnExit)

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
		c.SetType(base.Initiator)
		return true
	})
}

func (c *Client) configureClientHello() {
	// configure ClientHello
	sc := c.machine.Configure(ClientHello)
	sc.OnExit(handleOnExit)

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
}

func (c *Client) configureClientAuth() {
	// configure ClientAuth
	sc := c.machine.Configure(ClientAuth)
	sc.OnExit(handleOnExit)

	// ClientAuth->ServerAuth
	sc.PermitIf(SendServerAuthMsg, ServerAuth, func(params ...interface{}) bool {
		bag, _ := params[0].(*CallbackBag)
		var msg *ServerAuthMessage
		var slotWrapper *SlotWrapper

		defer func() {
			if slotWrapper != nil && !slotWrapper.committed {
				slotWrapper.Abort()
			}
		}()

		if clientType, _ := c.GetType(); clientType == base.Initiator {
			if prevClient, ok := c.Path.GetInitiator(); ok && prevClient != c {
				// todo: kill prevClient
			}
			slotWrapper = c.Path.SetInitiator(c)
			msg = NewServerAuthMessageForInitiator(base.Server, base.Initiator, c.GetCookieIn(), len(c.Server.permanentBoxes) > 0, c.Path.GetResponderIds())
		} else {
			var err error
			slotWrapper, err = c.Path.AddResponder(c)
			if err != nil { // responder
				bag.err = errors.New("Path Full")
				return false
			}
			_, initiatorConnected := c.Path.GetInitiator()
			msg = NewServerAuthMessageForResponder(base.Server, slotWrapper.allocatedIndex, c.GetCookieIn(), len(c.Server.permanentBoxes) > 0, initiatorConnected)
		}
		data, _ := Pack(c, msg.src, msg.dest, msg)
		err := c.Server.WriteCtrl(c.connx, data)
		if err != nil {
			bag.err = err
			return false
		}
		c.Authenticated = true
		slotWrapper.Commit()
		return true
	})
}

func (c *Client) configureServerAuth() {
	// configure ServerAuth
	sc := c.machine.Configure(ServerAuth)
	sc.OnExit(handleOnExit)

	// ServerAuth->NewInitiator(Responder)
	sc.PermitIf(SendNewInitiatorMsg, NewInitiator, func(params ...interface{}) bool {
		bag, _ := params[0].(*CallbackBag)
		slot, ok := c.Path.GetInitiator()
		if initiator := slot.(*Client); !ok || initiator == nil || initiator.Id == c.Id {
			bag.err = errors.New("no initiator")
			return false
		}
		msg := NewNewInitiatorMessage(base.Server, c.Id)
		data, _ := Pack(c, msg.src, msg.dest, msg)
		err := c.Server.WriteCtrl(c.connx, data)
		if err != nil {
			bag.err = err
			return false
		}
		return true
	})

	// ServerAuth->NewResponder(Initiator)
	sc.PermitIf(SendNewResponderMsg, NewResponder, func(params ...interface{}) bool {
		bag, _ := params[0].(*CallbackBag)
		responderID, _ := params[1].(base.AddressType)
		if responderID <= base.Initiator {
			bag.err = errors.New("invalid responder")
			return false
		}
		slot, err := c.Path.FindClientByID(responderID)
		if responder := slot.(*Client); err != nil || responder == nil || !responder.Authenticated {
			bag.err = errors.New("responder doesnt exist on the path")
			return false
		}
		msg := NewNewResponderMessage(base.Server, c.Id, responderID)
		data, _ := Pack(c, msg.src, msg.dest, msg)
		err = c.Server.WriteCtrl(c.connx, data)
		if err != nil {
			bag.err = err
			return false
		}
		return true
	})

	// ServerAuth->DropResponder(Initiator)
	sc.PermitIf(GetDropResponderMsg, DropResponder, func(params ...interface{}) bool {
		// bag, _ := params[0].(*CallbackBag)
		// dropResponderMsg, _ := params[1].(*DropResponderMessage)
		// todo close conn
		return true
	})

	sc.PermitIf(SendSendErrorMsg, SendError, func(params ...interface{}) bool {

		return true
	})
	sc.PermitIf(SendDisconnectedMsg, Disconnected, func(params ...interface{}) bool {

		return true
	})

}

func (c *Client) configureNewResponder() {
	// configure NewResponder
	sc := c.machine.Configure(NewResponder)
	sc.OnExit(handleOnExit)

	sc.SubstateOf(InitiatorSuperState)
}

func (c *Client) configureDropResponder() {
	// configure DropResponder
	sc := c.machine.Configure(DropResponder)
	sc.OnExit(handleOnExit)

	sc.SubstateOf(InitiatorSuperState)
}

func (c *Client) configureNewInitiator() {
	// configure NewInitiator
	sc := c.machine.Configure(NewInitiator)
	sc.OnExit(handleOnExit)

	sc.PermitReentryIf(SendNewInitiatorMsg, func(params ...interface{}) bool {
		return true
	})
	sc.PermitIf(SendSendErrorMsg, SendError, func(params ...interface{}) bool {

		return true
	})
	sc.PermitIf(SendDisconnectedMsg, Disconnected, func(params ...interface{}) bool {

		return true
	})
}

func (c *Client) configureSendError() {
	// configure SendError
	sc := c.machine.Configure(SendError)
	sc.OnExit(handleOnExit)

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
}

func (c *Client) configureDisconnected() {
	// configure Disconnected
	sc := c.machine.Configure(Disconnected)
	sc.OnExit(handleOnExit)

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

func (c *Client) configureInitiatorSuperState() {
	// configure InitiatorSuperState
	sc := c.machine.Configure(InitiatorSuperState)
	sc.OnExit(handleOnExit)

	sc.PermitIf(GetDropResponderMsg, DropResponder, func(params ...interface{}) bool {

		return true
	})
	sc.PermitIf(SendSendErrorMsg, SendError, func(params ...interface{}) bool {
		return true
	})
	sc.PermitIf(SendDisconnectedMsg, Disconnected, func(params ...interface{}) bool {
		return true
	})
}

func (c *Client) configureClientConnected() {
	// configure ClientConnected
	sc := c.machine.Configure(ClientConnected)
	sc.OnExit(handleOnExit)
	// ClientConnected->ServerHello
	sc.PermitIf(SendServerHelloMsg, ServerHello, func(params ...interface{}) bool {
		bag, _ := params[0].(*CallbackBag)

		msg := NewServerHelloMessage(base.Server, c.Id, c.ServerSessionBox.Pk[:])
		data, _ := Pack(c, msg.src, msg.dest, msg)
		err := c.Server.WriteCtrl(c.connx, data)
		if err != nil {
			bag.err = err
			return false
		}
		return true
	})
}

func handleOnExit(trigger string, destState string) {
	Sugar.Infof("OnExit: trigger: %s, destState: %s", trigger, destState)
}

// Init ..
func (c *Client) Init() {
	// initial state
	sm := statmach.New(ClientConnected)
	c.machine = sm

	c.configureClientConnected()

	c.configureServerHello()

	c.configureClientHello()

	c.configureClientAuth()

	c.configureServerAuth()

	c.configureNewResponder()

	c.configureDropResponder()

	c.configureInitiatorSuperState()

	c.configureNewInitiator()

	c.configureSendError()

	c.configureDisconnected()
}

// NewClient .. todo: implement it properly
func NewClient(conn *ClientConn, clientKey [base.KeyBytesSize]byte, permanentBox, sessionBox *boxkeypair.BoxKeyPair) (*Client, error) {
	cookieOut, err := randutil.RandBytes(base.CookieLength)
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

// GetCookieIn ..
func (c *Client) GetCookieIn() []byte {
	return c.cookieIn
}

// CheckAndSetCookieIn ..
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

// GetType ..
func (c *Client) GetType() (base.AddressType, bool) {
	return c.typeValue, c.typeHasValue
}

// SetType ..
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
		c.machine.Fire(GetClientHelloMsg, msg)
	} else if msg, ok := msgIncoming.(*ClientAuthMessage); ok {
		c.machine.Fire(GetClientAuthMsg, msg)
	} else if msg, ok := msgIncoming.(*DropResponderMessage); ok {
		c.machine.Fire(GetDropResponderMsg, msg)
	}
	// todo: handle all messages
	return nil
}

// readIncomingMessage reads and unpacks received data from connection.
// It takes io mutex.
func (c *Client) readIncomingMessage() (interface{}, error) {
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
	msg, err := Unpack(c, b, UnpackRaw)
	if err != nil {
		return nil, err
	}

	return msg, nil
}

// Received ..
func (c *Client) Received(b []byte) {

	Sugar.Infof("WSDATA: %s\n", strings.TrimSpace(string(b)))

	msgIncoming, err := Unpack(c, b, UnpackRaw)

	if err != nil {
		Sugar.Error(err)
		return
	}

	if msgIncoming == nil {
		// Handled some control message.
		return
	}
	if msg, ok := msgIncoming.(*ClientHelloMessage); ok {
		c.machine.Fire(GetClientHelloMsg, msg)
	} else if msg, ok := msgIncoming.(*ClientAuthMessage); ok {
		c.machine.Fire(GetClientAuthMsg, msg)
	} else if msg, ok := msgIncoming.(*DropResponderMessage); ok {
		c.machine.Fire(GetDropResponderMsg, msg)
	}
	// todo: handle all messages
	return
}

// MarkAsOrphan ..
func (c *Client) MarkAsOrphan() {
	c.AliveStat = base.MarkAsOrphan(c.AliveStat)
}

// MarkAsDeath ..
func (c *Client) MarkAsDeath() {
	c.AliveStat = base.MarkAsDeath(c.AliveStat)
}

// MarkAsDeathIfConnDeath ..
func (c *Client) MarkAsDeathIfConnDeath() bool {
	if (c.conn.AliveStat & base.AliveStatDeath) != base.AliveStatDeath {
		c.AliveStat = base.MarkAsDeath(c.AliveStat)
		return true
	}
	return false
}

// CloseConn ..
func (c *Client) CloseConn(closeFrame []byte) error {
	c.MarkAsOrphan()
	return c.conn.Close(closeFrame)
}
