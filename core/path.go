package core

import (
	prot "github.com/OguzhanE/saltyrtc-server-go/core/protocol"
	hm "github.com/cornelk/hashmap"
)

// Path ..
type Path struct {
	key      string
	number   uint32
	slots    *hm.HashMap
	lastSlot prot.AddressType
	orphan   bool
}

// NewPath ..
func NewPath(key string, number uint32) *Path {
	return &Path{
		key:      key,
		number:   number,
		slots:    &hm.HashMap{},
		lastSlot: prot.Initiator,
	}
}

// SetInitiator ..
func (p *Path) SetInitiator(c *Client) {
	p.slots.Set(prot.Initiator, c)
}

// GetInitiator ..
func (p *Path) GetInitiator() (*Client, bool) {
	return p.Get(prot.Initiator)
}

// AddResponder ..
func (p *Path) AddResponder(c *Client) (prot.AddressType, error) {
	lastSlot := p.lastSlot
	var responderID prot.AddressType = lastSlot + 0x01 //0x02
	for ; responderID <= prot.Responder; responderID = responderID + 0x01 {
		_, loaded := p.slots.GetOrInsert(responderID, c)
		if !loaded {
			p.lastSlot = responderID
			return responderID, nil
		}
	}
	responderID = 0x02
	for ; responderID <= lastSlot; lastSlot = responderID + 0x01 {
		_, loaded := p.slots.GetOrInsert(responderID, c)
		if !loaded {
			p.lastSlot = responderID
			return responderID, nil
		}
	}
	return prot.Server, prot.NewSlotsFullError("No free slot on path")
}

// Del ..
func (p *Path) Del(id prot.AddressType) {
	p.slots.Del(id)
}

// Get ..
func (p *Path) Get(id prot.AddressType) (*Client, bool) {
	v, ok := p.slots.Get(id)
	c, _ := v.(*Client)
	return c, ok
}

// Iter ..
func (p *Path) Iter() <-chan hm.KeyValue {
	return p.slots.Iter()
}

// Walk ..
func (p *Path) Walk(cb func(c *Client)) {
	var id prot.AddressType = prot.Initiator
	for ; id <= prot.Responder; id = id + 0x01 {
		if v, ok := p.slots.Get(id); ok {
			c := v.(*Client)
			cb(c)
		}
	}
}
