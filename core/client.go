package core

import (
	"bytes"
	"errors"
	"fmt"
	"sync"

	"github.com/OguzhanE/saltyrtc-server-go/pkg/arrayutil"
	"github.com/OguzhanE/saltyrtc-server-go/pkg/base"

	prot "github.com/OguzhanE/saltyrtc-server-go/core/protocol"
	"github.com/OguzhanE/saltyrtc-server-go/pkg/crypto/nacl"
	"github.com/OguzhanE/saltyrtc-server-go/pkg/crypto/randutil"
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

	ClientKey          [nacl.NaclKeyBytesSize]byte
	ServerSessionBox   *nacl.BoxKeyPair
	ServerPermanentBox *nacl.BoxKeyPair
	CookieOut          []byte
	cookieIn           []byte

	CombinedSequenceNumberOut *CombinedSequenceNumber
	CombinedSequenceNumberIn  *CombinedSequenceNumber

	Authenticated bool
	Id            prot.AddressType
	typeValue     prot.AddressType
	typeHasValue  bool
	Path          *Path
	Server        *Server
	State         int
}

// NewClient ..
func NewClient(conn *Conn, clientKey [base.KeyBytesSize]byte, permanentBox, sessionBox *nacl.BoxKeyPair) (*Client, error) {
	cookieOut, err := randutil.RandBytes(base.CookieLength)
	if err != nil {
		return nil, err
	}
	initialSeqNum, err := randutil.RandUint32()
	if err != nil {
		return nil, err
	}
	c := &Client{
		conn:                      conn,
		ClientKey:                 clientKey,
		CookieOut:                 cookieOut,
		CombinedSequenceNumberOut: NewCombinedSequenceNumber(initialSeqNum),
		ServerPermanentBox:        permanentBox,
		ServerSessionBox:          sessionBox,
		State:                     None,
	}
	return c, nil
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
func (c *Client) GetType() (prot.AddressType, bool) {
	return c.typeValue, c.typeHasValue
}

// SetType ..
func (c *Client) SetType(t prot.AddressType) {
	c.typeHasValue = true
	c.typeValue = t
}

// Received ..
func (c *Client) Received(b []byte) {
	Sugar.Debug("Unpacking received data..")

	msgIncoming, err := c.Unpack(b)
	if err != nil {
		Sugar.Warn("Could not unpack received data :", err)
		return
	}

	if msg, ok := msgIncoming.(*prot.ClientHelloMessage); ok {
		Sugar.Debug("Received client-hello")
		c.handleClientHello(msg)

	} else if msg, ok := msgIncoming.(*prot.ClientAuthMessage); ok {
		Sugar.Debug("Received client-auth")

		if err := c.handleClientAuth(msg); err == nil {
			c.Server.wp.Submit(func() {
				Sugar.Debug("Sending server-auth")

				c.sendServerAuth()
			})
		}
	} else if msg, ok := msgIncoming.(*prot.DropResponderMessage); ok {
		Sugar.Debug("Sending drop-responder")
		c.handleDropResponder(msg)

	} else if msg, ok := msgIncoming.(*prot.RawMessage); ok {
		Sugar.Debug("Received RawMessage")
		c.handleRawMessage(msg)

	} else {
		Sugar.Warn("Received unhandled message :", msgIncoming)
	}
	// todo: handle all messages
	return
}

func (c *Client) getHeader(dest uint8) (h prot.Header, err error) {
	csnOut, err := c.CombinedSequenceNumberOut.AsBytes()
	if err != nil {
		return
	}

	h = prot.Header{
		Cookie: c.CookieOut,
		Csn:    csnOut,
		Dest:   dest,
		Src:    prot.Server,
	}
	return
}

func (c *Client) sendServerHello() (err error) {
	msg := prot.NewServerHelloMessage(prot.Server, c.Id, c.ServerSessionBox.Pk[:])
	h, err := c.getHeader(msg.Dest)
	if err != nil {
		return
	}
	data, err := c.Pack(h, msg)
	if err != nil {
		return
	}
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
	msg := prot.NewNewInitiatorMessage(prot.Server, c.Id)
	h, err := c.getHeader(msg.Dest)
	if err != nil {
		return
	}

	msg.EncodingOpts = struct {
		ClientKey       [32]byte
		ServerSessionSk [32]byte
		Nonce           []byte
	}{
		ClientKey:       c.ClientKey,
		ServerSessionSk: c.ServerSessionBox.Sk,
		Nonce:           prot.MakeNonce(h),
	}
	data, err := c.Pack(h, msg)
	if err != nil {
		return
	}
	err = c.Server.WriteCtrl(c.conn, data)
	return
}

func (c *Client) sendNewResponder(responderID uint8) (err error) {
	msg := prot.NewNewResponderMessage(prot.Server, c.Id, responderID)
	h, err := c.getHeader(msg.Dest)
	if err != nil {
		return
	}
	msg.EncodingOpts = struct {
		ClientKey       [32]byte
		ServerSessionSk [32]byte
		Nonce           []byte
	}{
		ClientKey:       c.ClientKey,
		ServerSessionSk: c.ServerSessionBox.Sk,
		Nonce:           prot.MakeNonce(h),
	}

	data, err := c.Pack(h, msg)
	if err != nil {
		return
	}

	err = c.Server.WriteCtrl(c.conn, data)
	return
}

func (c *Client) sendServerAuth() (err error) {
	var msg *prot.ServerAuthMessage
	if clientType, _ := c.GetType(); clientType == prot.Initiator {

		msg = prot.NewServerAuthMessageForInitiator(prot.Server, prot.Initiator, c.GetCookieIn(), len(c.Server.permanentBoxes) > 0, getAuthenticatedResponderIds(c.Path))
		h, err1 := c.getHeader(msg.Dest)
		if err1 != nil {
			err = err1
			return
		}
		msg.EncodingOpts = struct {
			ServerPermanentSk [32]byte
			ClientKey         [32]byte
			ServerSessionSk   [32]byte
			ServerSessionPk   [32]byte
			Nonce             []byte
		}{
			ServerPermanentSk: c.ServerPermanentBox.Sk,
			ClientKey:         c.ClientKey,
			ServerSessionSk:   c.ServerSessionBox.Sk,
			ServerSessionPk:   c.ServerSessionBox.Pk,
			Nonce:             prot.MakeNonce(h),
		}

		data, err1 := c.Pack(h, msg)
		if err1 != nil {
			return
		}
		if err = c.Server.WriteCtrl(c.conn, data); err != nil {
			return
		}

		if prevClient, ok := c.Path.GetInitiator(); ok && prevClient != c {
			// todo: kill prevClient
		}

		c.Path.SetInitiator(c)
		c.Id = prot.Initiator
		c.Authenticated = true
		c.State = ServerAuth

		Sugar.Debug("New authenticated Initiator: ", prot.Initiator)

		iterOnAuthenticatedResponders(c.Path, func(r *Client) {
			// TODO(oergin): consider to send 'new-initiator' message by a new worker
			r.sendNewInitiator()
		})
		return
	}
	// server-auth for responder
	slotID, err := c.Path.AddResponder(c)
	if err != nil {
		err = fmt.Errorf("Could not allocate Id for responder : %w", err)
		c.conn.Close(CloseFramePathFullError)
		return
	}
	clientInit, initiatorConnected := c.Path.GetInitiator()
	msg = prot.NewServerAuthMessageForResponder(prot.Server, slotID, c.GetCookieIn(), len(c.Server.permanentBoxes) > 0, initiatorConnected && clientInit.Authenticated)
	h, err1 := c.getHeader(msg.Dest)
	if err1 != nil {
		err = err1
		return
	}
	msg.EncodingOpts = struct {
		ServerPermanentSk [32]byte
		ClientKey         [32]byte
		ServerSessionSk   [32]byte
		ServerSessionPk   [32]byte
		Nonce             []byte
	}{
		ServerPermanentSk: c.ServerPermanentBox.Sk,
		ClientKey:         c.ClientKey,
		ServerSessionSk:   c.ServerSessionBox.Sk,
		ServerSessionPk:   c.ServerSessionBox.Pk,
		Nonce:             prot.MakeNonce(h),
	}

	data, err1 := c.Pack(h, msg)
	if err1 != nil {
		err = err1
		return
	}
	if err = c.Server.WriteCtrl(c.conn, data); err != nil {
		return
	}
	c.Id = slotID
	c.Authenticated = true
	c.State = ServerAuth
	Sugar.Debug("New authenticated Responder: ", slotID)

	if initiator, ok := c.Path.GetInitiator(); ok && initiator.Authenticated {
		initiator.sendNewResponder(c.Id)
	}
	return
}

func (c *Client) handleClientHello(msg *prot.ClientHelloMessage) (err error) {
	_, hasType := c.GetType()
	if hasType {
		err = errors.New("client already has type")
		return
	}
	if !nacl.IsValidBoxPkBytes(msg.ClientPublicKey) {
		err = errors.New("invalid client public key length")
		return
	}
	copy(c.ClientKey[:], msg.ClientPublicKey[0:base.KeyBytesSize])
	c.SetType(prot.Responder)
	c.State = ClientHello
	return
}

func (c *Client) handleClientAuth(msg *prot.ClientAuthMessage) (err error) {
	// validate your_cookie with cookieOut
	if !bytes.Equal(msg.ServerCookie, c.CookieOut) {
		err = errors.New("Cookies do not match")
		return
	}

	presentSubprotocols := arrayutil.IntersectionStr(msg.Subprotocols, c.Server.subprotocols)
	if len(presentSubprotocols) == 0 || presentSubprotocols[0] != c.Server.subprotocol {
		err = errors.New("Invalid subprotocol")
		return
	}

	if len(c.Server.permanentBoxes) == 0 {
		err = errors.New("server does not have a permanent key pair")
		return
	}

	for _, box := range c.Server.permanentBoxes {
		if box.PkEqualTo(msg.ServerKey) {
			// select server permanent box for further use
			c.ServerPermanentBox = box.Clone()
			break
		}
	}
	if c.ServerPermanentBox == nil {
		err = errors.New("yourKey matches none of permanent key pairs of server")
		return
	}

	// todo impl. ping(ing) logic

	// ServerHello->ClientAuth transition states the method below for initiator handshake
	if c.State == ServerHello {
		c.SetType(prot.Initiator)
	}
	c.State = ClientAuth
	return
}

func (c *Client) handleDropResponder(msg *prot.DropResponderMessage) (err error) {
	if !c.Authenticated || c.typeValue != prot.Initiator {
		err = errors.New("Client is not authenticated, nor initiator")
		return
	}
	responder, ok := c.Path.Get(msg.ResponderId)
	if !ok {
		err = errors.New("Responder does not exist on the path")
		return
	}
	c.Path.Del(msg.ResponderId)
	closeFrame := getCloseFrameByCode(msg.Reason, CloseFrameDropByInitiator)
	responder.conn.Close(closeFrame)
	return
}

func (c *Client) handleRawMessage(msg *prot.RawMessage) (err error) {
	if !c.Authenticated || c.Id != msg.Src || msg.Src == msg.Dest {
		err = errors.New("Client is not authenticated nor valid raw message")
		return
	}
	destClient, ok := c.Path.Get(msg.Dest)
	if !ok {
		err = errors.New("Dest client does not exist")
		return
	}
	err = destClient.sendRawData(msg.Data)
	return
}

func (c *Client) sendRawData(data []byte) (err error) {
	Sugar.Debug("Sending raw data..")
	err = c.Server.WriteCtrl(c.conn, data)
	return
}

// DelFromPath ..
func (c *Client) DelFromPath() {
	if c.Authenticated {
		c.Path.Del(c.Id)
	}
}
func getAuthenticatedResponderIds(p *Path) []prot.AddressType {
	ids := []prot.AddressType{}
	for kv := range p.Iter() {
		k, _ := kv.Key.(prot.AddressType)
		v, _ := kv.Value.(*Client)
		if typeVal, ok := v.GetType(); v.Authenticated && ok && typeVal == prot.Responder {
			ids = append(ids, k)
		}
	}
	return ids
}

func iterOnAuthenticatedResponders(p *Path, handler func(c *Client)) {
	for kv := range p.Iter() {
		v, _ := kv.Value.(*Client)
		if typeVal, ok := v.GetType(); v.Authenticated && ok && typeVal == prot.Responder {
			handler(v)
		}
	}
}

// Pack ..
func (c *Client) Pack(h prot.Header, pm prot.PayloadMarshaler) ([]byte, error) {

	payloadBts, _ := pm.MarshalPayload()
	f := prot.Frame{
		Header:  h,
		Payload: payloadBts,
	}

	buf := bytes.NewBuffer(make([]byte, 0, prot.HeaderSize+len(f.Payload)))
	prot.WriteFrame(buf, f)

	c.CombinedSequenceNumberOut.Increment()
	return buf.Bytes(), nil
}

func (c *Client) checkCookieIn(cookie []byte) (err error) {
	if c.cookieIn == nil {
		if bytes.Equal(cookie, c.CookieOut) {
			return errors.New("Server and client cookies could not be the same")
		}
		return nil
	}
	if !bytes.Equal(c.cookieIn, cookie) {
		return errors.New("Client cookieIn is not changeable")
	}
	return nil
}

// Unpack ..
func (c *Client) Unpack(data []byte) (msg interface{}, err error) {
	f, err := prot.ParseFrame(data)
	if err != nil {
		return
	}

	destType := prot.GetAddressTypeFromAddr(f.Header.Dest)

	// Validate destination
	isToServer := destType == prot.Server
	if typeVal, typeHasVal := c.GetType(); !isToServer && !(c.Authenticated && typeHasVal && typeVal != destType) {
		return nil, prot.NewMessageFlowError(fmt.Sprintf("Not allowed to relay messages to 0x%x", f.Header.Dest), prot.ErrNotAllowedMessage)
	}

	// Validate source
	if c.Id != f.Header.Src {
		return nil, prot.NewMessageFlowError(fmt.Sprintf("Identities do not match, expected 0x%x, got 0x%x", c.Id, f.Header.Src), prot.ErrNotMatchedIdentities)
	}

	if destType != prot.Server {
		return prot.NewRawMessage(f.Header.Src, f.Header.Dest, data), nil
	}

	// Validate cookie
	if err = c.checkCookieIn(f.Header.Cookie); err != nil {
		return
	}

	// validate and increase csn
	csn, err := ParseCombinedSequenceNumber(f.Header.Csn)
	if err != nil {
		return nil, err
	}
	csnIn := c.CombinedSequenceNumberIn
	if csnIn != nil {
		if csnIn.HasErrOverflowSentinel() {
			return nil, prot.NewMessageFlowError("Cannot receive any more messages, due to a sequence number counter overflow", ErrOverflowSentinel)
		}
		if !csnIn.EqualsTo(csn) {
			return nil, prot.NewMessageFlowError("invalid received sequence number", ErrNotExpectedCsn)
		}
	} else if csn.GetOverflowNumber() != 0 {
		return nil, prot.NewMessageFlowError("overflow number must be initialized with zero", ErrInvalidOverflowNumber)
	}

	nonce, _ := prot.ExtractNonce(data)
	decryptedPayload, err1 := prot.DecryptPayload(c.ClientKey, c.ServerSessionBox.Sk, nonce, f.Payload)
	if err1 == nil {
		f.Payload = decryptedPayload
	}

	if msg, err = prot.UnmarshalMessage(f); err != nil {
		return
	}

	if csnIn == nil {
		c.CombinedSequenceNumberIn = csn
	}
	c.CombinedSequenceNumberIn.Increment()
	c.cookieIn = f.Header.Cookie
	return
}
