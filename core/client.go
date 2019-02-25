package core

import (
	"sync"
	"github.com/oguzhane/saltyrtc-server-go/common/randutil"
	"github.com/oguzhane/saltyrtc-server-go/common"
	"bytes"
	"errors"
	"github.com/gobwas/ws"
	"github.com/gobwas/ws/wsutil"
)

type ReadDataBag struct {
	client      *Client
	messageType *int
	data        *[]byte
	err         *error
}

type WriteDataBag struct {
}

type Client struct {
	mux   sync.Mutex
	conn *ClientConn

	ClientKey [32]byte
	ServerSessionBox *common.BoxKeyPair
	ServerPermanentBox *common.BoxKeyPair
	CookieOut []byte
	cookieIn []byte

	CombinedSequenceNumberOut *CombinedSequenceNumber
	CombinedSequenceNumberIn *CombinedSequenceNumber
	
	Authenticated bool
	Id common.AddressType
	Type common.AddressType
}

// todo: implement it properly
func NewClient(conn *ClientConn, clientKey [32]byte) (*Client, error) {
	cookieOut, err := randutil.RandBytes(16)
	if err != nil{
		return nil, err
	}
	initialSeqNum, err := randutil.RandUint32()
	if err != nil{
		return nil, err
	}
	return &Client{
		conn: conn,
		ClientKey: clientKey,
		CookieOut: cookieOut,
		CombinedSequenceNumberOut: NewCombinedSequenceNumber(initialSeqNum),
	}, nil
}

func (c *Client) GetCookieIn() []byte {
	return c.cookieIn
}
func (c *Client) SetCookieIn(cookieIn []byte) error {
	if c.cookieIn == nil{
		if bytes.Equal(cookieIn, c.CookieOut) {
			return errors.New("Server and client cookies cannot be the same")
		}	
		c.cookieIn = cookieIn		
	} else {
		if !bytes.Equal(c.cookieIn, cookieIn) {
			return errors.New("Client cookie is not changeable")
		}
	}
	return nil
}

// Receive reads next message from EditorClient's underlying connection.
// It blocks until full message received.
func (ec *Client) Receive() error {
	req, err := ec.readRequest()
	if err != nil {
		ec.conn.Close()
		return err
	}
	if req == nil {
		// Handled some control message.
		return nil
	}
	switch req.Method {
	case "rename":
		name, ok := req.Params["name"].(string)
		if !ok {
			return ec.writeErrorTo(req, Object{
				"error": "bad params",
			})
		}
		prev, ok := ec.chat.Rename(ec, name)
		if !ok {
			return ec.writeErrorTo(req, Object{
				"error": "already exists",
			})
		}
		ec.chat.Broadcast("rename", Object{
			"prev": prev,
			"name": name,
			"time": timestamp(),
		})
		return ec.writeResultTo(req, nil)
	case "publish":
		req.Params["author"] = ec.id
		req.Params["time"] = timestamp()
		ec.chat.Broadcast("publish", req.Params)
	default:
		return ec.writeErrorTo(req, Object{
			"error": "not implemented",
		})
	}
	return nil
}

// readRequests reads json-rpc request from connection.
// It takes io mutex.
func (ec *Client) readRequest() (*Request, error) {
	ec.io.Lock()
	defer ec.io.Unlock()

	h, r, err := wsutil.NextReader(ec.conn, ws.StateServerSide)
	if err != nil {
		return nil, err
	}
	if h.OpCode.IsControl() {
		return nil, wsutil.ControlFrameHandler(ec.conn, ws.StateServerSide)(h, r)
	}

	req := &Request{}
	decoder := json.NewDecoder(r)
	if err := decoder.Decode(req); err != nil {
		return nil, err
	}

	return req, nil
}

func (ec *Client) writeErrorTo(req *Request, err Object) error {
	return ec.write(Error{
		ID:    req.ID,
		Error: err,
	})
}

func (ec *Client) writeResultTo(req *Request, result Object) error {
	return ec.write(Response{
		ID:     req.ID,
		Result: result,
	})
}

func (ec *Client) writeNotice(method string, params Object) error {
	return ec.write(Request{
		Method: method,
		Params: params,
	})
}

func (ec *Client) write(x interface{}) error {
	w := wsutil.NewWriter(ec.conn, ws.StateServerSide, ws.OpText)
	encoder := json.NewEncoder(w)

	ec.io.Lock()
	defer ec.io.Unlock()

	if err := encoder.Encode(x); err != nil {
		return err
	}

	return w.Flush()
}

func (ec *Client) writeRaw(p []byte) error {
	ec.io.Lock()
	defer ec.io.Unlock()

	_, err := ec.conn.Write(p)

	return err
}