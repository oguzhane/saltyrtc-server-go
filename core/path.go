package core

import (
	"fmt"
	"sync"

	"github.com/OguzhanE/saltyrtc-server-go/pkg/base"
)

// Path is responsible for web socket connection path for responder and initiators
type Path struct {
	mux          sync.Mutex
	initiatorKey string
	number       uint32
	slots        map[base.AddressType]*Client
}

// NewPath function creates Path instance
func NewPath(initiatorKey string, number uint32) *Path {
	return &Path{
		initiatorKey: initiatorKey,
		number:       number,
		slots:        make(map[base.AddressType]*Client),
	}
}

// InitiatorKey gets initiator key string
func (p *Path) InitiatorKey() string {
	return p.initiatorKey
}

// CheckAndSetInitiator sets initiator *Client instance
func (p *Path) CheckAndSetInitiator(initiator *Client) *base.CheckUp {
	chkUp := base.NewCheckUp()
	chkUp.Push(func() error { p.slots[base.Initiator] = initiator; initiator.Id = base.Initiator; return nil })
	return chkUp
}

// GetInitiator returns *Client initiator instance and its existence
func (p *Path) GetInitiator() (*Client, bool) {
	val, ok := p.slots[base.Initiator]
	return val, ok
}

// CheckAndAddResponder checks and add responder to slots on path
// returns ResponderID and error
func (p *Path) CheckAndAddResponder(responder *Client) (*base.CheckUp, base.AddressType) {
	chkUp := base.NewCheckUp()
	if responder == nil {
		chkUp.SetErr(base.NewValueError("Responder cannot be nil"))
		return chkUp, base.Server
	}
	var responderID base.AddressType = 0x02
	for ; responderID <= base.Responder; responderID = responderID + 0x01 {
		_, prs := p.slots[responderID]
		if !prs {
			chkUp.Push(func() error { p.slots[responderID] = responder; responder.Id = responderID; return nil })
			return chkUp, responderID
		}
	}
	chkUp.SetErr(base.NewSlotsFullError("No free slot on path"))
	return chkUp, base.Server
}

// RemoveClientByID removes client from slots by id
func (p *Path) RemoveClientByID(id base.AddressType) (*Client, error) {
	client, prs := p.slots[id]

	if !prs {
		return nil, base.NewValueError(fmt.Sprintf("Invalid slot id:0x%x", id))
	}
	delete(p.slots, id)
	return client, nil
}

func (p *Path) GetResponderIds() []uint8 {
	ids := make([]uint8, 0)
	var responderID base.AddressType = 0x02
	for ; responderID <= base.Responder; responderID = responderID + 0x01 {
		_, ok := p.slots[responderID]
		if ok {
			ids = append(ids, responderID)
		}
	}
	return ids
}

// FindClientByID finds client by id
func (p *Path) FindClientByID(id base.AddressType) (*Client, error) {
	client, prs := p.slots[id]
	if !prs {
		return nil, base.NewValueError(fmt.Sprintf("Invalid slot id:0x%x", id))
	}
	return client, nil
}
