package core

import (
	"sync"
	"github.com/oguzhane/saltyrtc-server-go/common/randutil"
	"github.com/oguzhane/saltyrtc-server-go/common"
	"bytes"
	"errors"
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