package core

import (
	"github.com/OguzhanE/saltyrtc-server-go/pkg/base"
	hm "github.com/cornelk/hashmap"
)

// Path ..
type Path struct {
	key      string
	number   uint32
	slots    *hm.HashMap
	lastSlot base.AddressType
	orphan   bool
}

func NewPath(key string, number uint32) *Path {
	return &Path{
		key:      key,
		number:   number,
		slots:    &hm.HashMap{},
		lastSlot: base.Initiator,
	}
}

// SetInitiator ..
func (p *Path) SetInitiator(c *Client) {
	p.slots.Set(base.Initiator, c)
}

// GetInitiator ..
func (p *Path) GetInitiator() (*Client, bool) {
	return p.Get(base.Initiator)
}

// AddResponder ..
func (p *Path) AddResponder(c *Client) (base.AddressType, error) {
	lastSlot := p.lastSlot
	var responderID base.AddressType = lastSlot + 0x01 //0x02
	for ; responderID <= base.Responder; responderID = responderID + 0x01 {
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
	return base.Server, base.NewSlotsFullError("No free slot on path")
}

// Del ..
func (p *Path) Del(id base.AddressType) {
	p.slots.Del(id)
}

// Get ..
func (p *Path) Get(id base.AddressType) (*Client, bool) {
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
	var id base.AddressType = base.Initiator
	for ; id <= base.Responder; id = id + 0x01 {
		if v, ok := p.slots.Get(id); ok {
			c := v.(*Client)
			cb(c)
		}
	}
}
