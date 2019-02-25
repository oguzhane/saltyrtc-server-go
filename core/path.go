package core

import (
	"fmt"

	"github.com/oguzhane/saltyrtc-server-go/common"
)

// Path is responsible for web socket connection path for responder and initiators
type Path struct {
	initiatorKey string
	number       uint32
	slots        map[common.AddressType]*Client
}

// NewPath function creates Path instance
func NewPath(initiatorKey string, number uint32) *Path {
	return &Path{
		initiatorKey: initiatorKey,
		number:       number,
		slots:        make(map[common.AddressType]*Client),
	}
}

// InitiatorKey gets initiator key string
func (p *Path) InitiatorKey() string {
	return p.initiatorKey
}

// SetInitiator sets initiator *Client instance
func (p *Path) SetInitiator(initiator *Client) error {

	p.slots[common.Initiator] = initiator
	return nil
}

// GetInitiator returns *Client initiator instance and its existence
func (p *Path) GetInitiator() (*Client, bool) {
	val, ok := p.slots[common.Initiator]
	return val, ok
}

// AddResponder add responder to slots on path
// returns ResponderID and error
func (p *Path) AddResponder(responder *Client) (common.AddressType, error) {
	if responder == nil {
		return common.Server, common.NewValueError("Responder cannot be nil")
	}
	var responderID common.AddressType = 0x02
	for ; responderID <= common.Responder; responderID = responderID + 0x01 {
		_, prs := p.slots[responderID]
		if !prs {
			p.slots[responderID] = responder
			break
		}
	}
	if responderID > common.Responder {
		return common.Server, common.NewSlotsFullError("No free slot on path")
	}
	return responderID, nil
}

// RemoveClientByID removes client from slots by id
func (p *Path) RemoveClientByID(id common.AddressType) (*Client, error) {
	client, prs := p.slots[id]

	if !prs {
		return nil, common.NewValueError(fmt.Sprintf("Invalid slot id:0x%x", id))
	}
	delete(p.slots, id)
	return client, nil
}
