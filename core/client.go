package core

import (
	"bytes"
	"errors"
	"sync"

	"github.com/OguzhanE/saltyrtc-server-go/pkg/arrayutil"
	"github.com/OguzhanE/saltyrtc-server-go/pkg/base"

	"github.com/OguzhanE/saltyrtc-server-go/pkg/boxkeypair"
	"github.com/OguzhanE/saltyrtc-server-go/pkg/naclutil"
	"github.com/OguzhanE/saltyrtc-server-go/pkg/randutil"
)

// STATES
const (
	None = iota + 1
	ServerHello
	ClientHello
	ClientAuth
	ServerAuth
)

// Client ..
type Client struct {
	mux  sync.Mutex
	conn *Conn

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
	State         int
}

// NewClient ..
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
		conn:                      conn,
		ClientKey:                 clientKey,
		CookieOut:                 cookieOut,
		CombinedSequenceNumberOut: NewCombinedSequenceNumber(initialSeqNum),
		ServerPermanentBox:        permanentBox,
		ServerSessionBox:          sessionBox,
		State:                     None,
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
	}
	if !bytes.Equal(c.cookieIn, cookieIn) {
		chkUp.SetErr(errors.New("Client cookie is not changeable"))
		return chkUp
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
		c.handleClientHello(msg)
	} else if msg, ok := msgIncoming.(*ClientAuthMessage); ok {
		err := c.handleClientAuth(msg)
		if err == nil {
			c.Server.wp.Submit(func() {
				c.sendServerAuth()
			})
		}
	} else if msg, ok := msgIncoming.(*DropResponderMessage); ok {
		c.handleDropResponder(msg)
	}
	// todo: handle all messages
	return
}

func (c *Client) sendServerHello() (err error) {
	msg := NewServerHelloMessage(base.Server, c.Id, c.ServerSessionBox.Pk[:])
	data, _ := Pack(c, msg.src, msg.dest, msg)
	err = c.Server.WriteCtrl(c.conn, data)
	if err == nil {
		c.State = ServerHello
		return
	}
	c.conn.Close(nil)
	c.DelFromPath()
	if c.Path.slots.Len() == 0 {
		c.Server.paths.hmap.Del(c.Path.key)
	}
	return
}

func (c *Client) sendNewInitiator() (err error) {
	msg := NewNewInitiatorMessage(base.Server, c.Id)
	data, err := Pack(c, msg.src, msg.dest, msg)
	if err == nil {
		err = c.Server.WriteCtrl(c.conn, data)
	}
	return
}

func (c *Client) sendNewResponder(responderID uint8) (err error) {
	msg := NewNewResponderMessage(base.Server, c.Id, responderID)
	data, err := Pack(c, msg.src, msg.dest, msg)
	if err == nil {
		err = c.Server.WriteCtrl(c.conn, data)
	}
	return
}

func (c *Client) sendServerAuth() (err error) {
	var msg *ServerAuthMessage

	if clientType, _ := c.GetType(); clientType == base.Initiator {

		msg = NewServerAuthMessageForInitiator(base.Server, base.Initiator, c.GetCookieIn(), len(c.Server.permanentBoxes) > 0, getAuthenticatedResponderIds(c.Path))
		data, _ := Pack(c, msg.src, msg.dest, msg)
		err = c.Server.WriteCtrl(c.conn, data)
		if err != nil {
			return
		}

		if prevClient, ok := c.Path.GetInitiator(); ok && prevClient != c {
			// todo: kill prevClient
		}
		c.Path.SetInitiator(c)
		c.Id = base.Initiator
		c.Authenticated = true
		c.State = ServerAuth
		Sugar.Info("Authenticated Initiator: ", base.Initiator)
		// Todo: send "new-initiator" message to responders
		iterOnAuthenticatedResponders(c.Path, func(r *Client) {
			r.sendNewInitiator()
		})
		return
	}
	// server-auth for responder
	slotID, err := c.Path.AddResponder(c)
	if err != nil {
		c.Path.Del(slotID)
		err = errors.New("Path Full")
		c.conn.Close(CloseFramePathFullError)
		return
	}
	clientInit, initiatorConnected := c.Path.GetInitiator()
	msg = NewServerAuthMessageForResponder(base.Server, slotID, c.GetCookieIn(), len(c.Server.permanentBoxes) > 0, initiatorConnected && clientInit.Authenticated)

	data, _ := Pack(c, msg.src, msg.dest, msg)
	err = c.Server.WriteCtrl(c.conn, data)
	if err != nil {
		return
	}
	c.Id = slotID
	c.Authenticated = true
	c.State = ServerAuth
	Sugar.Info("Authenticated Responder: ", slotID)

	// Todo: send "new-responder" message to initiator
	if initiator, ok := c.Path.GetInitiator(); ok && initiator.Authenticated {
		initiator.sendNewResponder(c.Id)
	}
	return
}

func (c *Client) handleClientHello(msg *ClientHelloMessage) (err error) {
	_, hasType := c.GetType()
	if hasType {
		err = errors.New("client already has type")
		return
	}
	if !naclutil.IsValidBoxPkBytes(msg.clientPublicKey) {
		err = errors.New("invalid client public key length")
		return
	}
	copy(c.ClientKey[:], msg.clientPublicKey[0:base.KeyBytesSize])
	c.SetType(base.Responder)
	c.State = ClientHello
	return
}

func (c *Client) handleClientAuth(msg *ClientAuthMessage) (err error) {
	// validate your_cookie with cookieOut
	if !bytes.Equal(msg.serverCookie, c.CookieOut) {
		err = errors.New("Cookies do not match")
		return
	}

	presentSubprotocols := arrayutil.IntersectionStr(msg.subprotocols, c.Server.subprotocols)
	if len(presentSubprotocols) == 0 || presentSubprotocols[0] != c.Server.subprotocol {
		err = errors.New("Invalid subprotocol")
		return
	}

	if len(c.Server.permanentBoxes) == 0 {
		err = errors.New("the server does not have a permanent key pair")
		return
	}

	for _, box := range c.Server.permanentBoxes {
		if box.PkEqualTo(msg.serverKey) {
			// select server permanent box for further use
			c.ServerPermanentBox = box.Clone()
			break
		}
	}
	if c.ServerPermanentBox == nil {
		err = errors.New("yourKey matches none of the server permanent key pairs")
		return
	}

	// todo impl. ping(ing) logic

	// ServerHello->ClientAuth transition states the method below for initiator handshake
	if c.State == ServerHello {
		c.SetType(base.Initiator)
	}
	c.State = ClientAuth
	return
}

func (c *Client) handleDropResponder(msg *DropResponderMessage) (err error) {
	if !c.Authenticated || c.typeValue != base.Initiator {
		err = errors.New("client is not Authenticated or not initiator")
		return
	}
	responder, ok := c.Path.Get(msg.responderId)
	if !ok {
		err = errors.New("Responder does not exist on the path")
		return
	}
	c.Path.Del(msg.responderId)
	closeFrame := getCloseFrameByCode(msg.reason, CloseFrameDropByInitiator)
	responder.conn.Close(closeFrame)
	return
}

// DelFromPath ..
func (c *Client) DelFromPath() {
	if c.Authenticated {
		c.Path.Del(c.Id)
	}
}
func getAuthenticatedResponderIds(p *Path) []base.AddressType {
	ids := []base.AddressType{}
	for kv := range p.Iter() {
		k, _ := kv.Key.(base.AddressType)
		v, _ := kv.Value.(*Client)
		if typeVal, ok := v.GetType(); v.Authenticated && ok && typeVal == base.Responder {
			ids = append(ids, k)
		}
	}
	return ids
}

func iterOnAuthenticatedResponders(p *Path, handler func(c *Client)) {
	for kv := range p.Iter() {
		v, _ := kv.Value.(*Client)
		if typeVal, ok := v.GetType(); v.Authenticated && ok && typeVal == base.Responder {
			handler(v)
		}
	}
}
