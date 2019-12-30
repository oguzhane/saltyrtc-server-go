package core

import (
	"bytes"
	"errors"
	"strings"
	"sync"

	"github.com/OguzhanE/saltyrtc-server-go/pkg/arrayutil"
	"github.com/OguzhanE/saltyrtc-server-go/pkg/base"

	"github.com/OguzhanE/saltyrtc-server-go/pkg/boxkeypair"
	"github.com/OguzhanE/saltyrtc-server-go/pkg/naclutil"
	"github.com/OguzhanE/saltyrtc-server-go/pkg/randutil"

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
	conn    *Conn
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

		if clientType, _ := c.GetType(); clientType == base.Initiator {
			// slotWrapper = c.Path.SetInitiator(c)
			msg = NewServerAuthMessageForInitiator(base.Server, base.Initiator, c.GetCookieIn(), len(c.Server.permanentBoxes) > 0, getAuthenticatedResponderIds(c.Path))
			data, _ := Pack(c, msg.src, msg.dest, msg)
			err := c.Server.WriteCtrl(c.conn, data)
			if err != nil {
				bag.err = err
				return false
			}

			if prevClient, ok := c.Path.GetInitiator(); ok && prevClient != c {
				// todo: kill prevClient
			}
			c.Path.SetInitiator(c)
			c.Authenticated = true
			return true
		}

		slotID, err := c.Path.AddResponder(c)
		if err != nil { // responder
			c.Path.Del(slotID)
			bag.err = errors.New("Path Full")
			return false
		}
		clientInit, initiatorConnected := c.Path.GetInitiator()
		msg = NewServerAuthMessageForResponder(base.Server, slotID, c.GetCookieIn(), len(c.Server.permanentBoxes) > 0, initiatorConnected && clientInit.Authenticated)

		data, _ := Pack(c, msg.src, msg.dest, msg)
		err = c.Server.WriteCtrl(c.conn, data)
		if err != nil {
			bag.err = err
			return false
		}
		c.Id = slotID
		c.Authenticated = true
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
		initiator, ok := c.Path.GetInitiator()
		if !ok || initiator.Id == c.Id || !initiator.Authenticated {
			bag.err = errors.New("no authenticated initiator")
			return false
		}
		msg := NewNewInitiatorMessage(base.Server, c.Id)
		data, _ := Pack(c, msg.src, msg.dest, msg)
		err := c.Server.WriteCtrl(c.conn, data)
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
		responder, ok := c.Path.Get(responderID)
		if !ok || !responder.Authenticated {
			bag.err = errors.New("responder doesnt exist on the path")
			return false
		}
		msg := NewNewResponderMessage(base.Server, c.Id, responderID)
		data, _ := Pack(c, msg.src, msg.dest, msg)
		err := c.Server.WriteCtrl(c.conn, data)
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
		err := c.Server.WriteCtrl(c.conn, data)
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
func NewClient(conn *Conn, clientKey [base.KeyBytesSize]byte, permanentBox, sessionBox *boxkeypair.BoxKeyPair) (*Client, error) {
	cookieOut, err := randutil.RandBytes(base.CookieLength)
	if err != nil {
		return nil, err
	}
	initialSeqNum, err := randutil.RandUint32()
	if err != nil {
		return nil, err
	}
	return &Client{
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

func getAuthenticatedResponderIds(p *Path) []base.AddressType {
	ids := []base.AddressType{}
	for kv := range p.Iter() {
		k, _ := kv.Key.(base.AddressType)
		v, _ := kv.Value.(*Client)
		if v.Authenticated {
			ids = append(ids, k)
		}
	}
	return ids
}
