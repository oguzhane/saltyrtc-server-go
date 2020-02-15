package core

import (
	"bytes"
	"errors"

	"github.com/OguzhanE/saltyrtc-server-go/pkg/base"
	"github.com/OguzhanE/saltyrtc-server-go/pkg/crypto/nacl"
)

type ClientNoncePacker struct {
	NoncePacker
	client *Client
	src    base.AddressType
	dest   base.AddressType
}

func (cnp ClientNoncePacker) Src() base.AddressType {
	return cnp.src
}

func (cnp ClientNoncePacker) Dest() base.AddressType {
	return cnp.dest
}

func (cnp ClientNoncePacker) Csn() *CombinedSequenceNumber {
	return cnp.client.CombinedSequenceNumberOut
}

func (cnp ClientNoncePacker) Cookie() ([]byte, error) {
	return cnp.client.CookieOut, nil
}

func NewClientNoncePacker(c *Client, src base.AddressType, dest base.AddressType) ClientNoncePacker {
	return ClientNoncePacker{
		client: c,
		src:    src,
		dest:   dest,
	}
}

type ClientNonceUnpacker struct {
	NonceUnpacker
	client *Client
}

func (cnu ClientNonceUnpacker) Type() (base.AddressType, bool) {
	return cnu.client.GetType()
}

func (cnu ClientNonceUnpacker) Authenticated() bool {
	return cnu.client.Authenticated
}

func (cnu ClientNonceUnpacker) Id() base.AddressType {
	return cnu.client.Id
}

func (cnu ClientNonceUnpacker) ClientKey() [nacl.NaclKeyBytesSize]byte {
	return cnu.client.ClientKey
}

func (cnu ClientNonceUnpacker) ServerSessionSk() [nacl.NaclKeyBytesSize]byte {
	return cnu.client.ServerSessionBox.Sk
}

func (cnu ClientNonceUnpacker) Csn() *CombinedSequenceNumber {
	return cnu.client.CombinedSequenceNumberIn
}

func (cnu ClientNonceUnpacker) ReceiveCsn(csn *CombinedSequenceNumber) {
	cnu.client.CombinedSequenceNumberIn = csn
}

func (cnu ClientNonceUnpacker) MakeCookieWriter(cookieIn []byte) (Do func(), err error) {
	c := cnu.client
	if c.cookieIn == nil {
		if bytes.Equal(cookieIn, c.CookieOut) {
			return nil, errors.New("Server and client cookies could not be the same")
		}
		return func() { c.cookieIn = cookieIn }, nil
	}
	if !bytes.Equal(c.cookieIn, cookieIn) {
		return nil, errors.New("Client cookieIn is not changeable")
	}
	return func() { c.cookieIn = cookieIn }, nil
}
