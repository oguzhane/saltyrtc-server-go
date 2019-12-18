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
	slots        map[base.AddressType]interface{}
	AliveStat    base.AliveStatType
}

type SlotWrapper struct {
	client         *Client
	allocatedIndex base.AddressType
	path           *Path
	committed      bool
}

func NewSlotWrapper(client *Client, path *Path, allocatedIndex uint8) *SlotWrapper {
	client.Id = allocatedIndex
	return &SlotWrapper{
		client:         client,
		allocatedIndex: allocatedIndex,
		path:           path,
	}
}

func (sw *SlotWrapper) Commit() {
	sw.path.mux.Lock()
	defer sw.path.mux.Unlock()

	sw.path.slots[sw.allocatedIndex] = sw.client
	sw.committed = true
}

func (sw *SlotWrapper) Abort() {
	sw.path.mux.Lock()
	defer sw.path.mux.Unlock()
	sw.client.Id = base.Server
	delete(sw.path.slots, sw.allocatedIndex)
}

// NewPath function creates Path instance
func NewPath(initiatorKey string, number uint32) *Path {
	return &Path{
		initiatorKey: initiatorKey,
		number:       number,
		slots:        make(map[base.AddressType]interface{}),
	}
}

// InitiatorKey gets initiator key string
func (p *Path) InitiatorKey() string {
	return p.initiatorKey
}

// SetInitiator sets initiator *Client instance
func (p *Path) SetInitiator(initiator *Client) *SlotWrapper {
	p.mux.Lock()
	defer p.mux.Unlock()

	wrapper := NewSlotWrapper(initiator, p, base.Initiator)
	p.slots[base.Initiator] = wrapper
	return wrapper
}

// GetInitiator returns *Client initiator instance and its existence
func (p *Path) GetInitiator() (interface{}, bool) {
	p.mux.Lock()
	defer p.mux.Unlock()
	val, ok := p.slots[base.Initiator]
	return val, ok
}

// AddResponder adds responder to slots on path
// returns ResponderID and error
func (p *Path) AddResponder(responder *Client) (*SlotWrapper, error) {
	p.mux.Lock()
	defer p.mux.Unlock()
	if responder == nil {
		return nil, base.NewValueError("Responder cannot be nil")
	}
	var responderID base.AddressType = 0x02
	for ; responderID <= base.Responder; responderID = responderID + 0x01 {
		_, prs := p.slots[responderID]
		if !prs {
			wrapper := NewSlotWrapper(responder, p, responderID)
			p.slots[responderID] = wrapper
			return wrapper, nil
		}
	}
	return nil, base.NewSlotsFullError("No free slot on path")
}

// RemoveClientByID removes client from slots by id
func (p *Path) RemoveClientByID(id base.AddressType) (interface{}, error) {
	p.mux.Lock()
	defer p.mux.Unlock()

	client, prs := p.slots[id]

	if !prs {
		return nil, base.NewValueError(fmt.Sprintf("Invalid slot id:0x%x", id))
	}
	delete(p.slots, id)
	return client, nil
}

// RemoveClient removes client from slots by id, if it is the same one
// returns if it had existed
func (p *Path) RemoveClient(client *Client) bool {
	p.mux.Lock()
	defer p.mux.Unlock()

	if client == nil || client.Id == base.Server {
		return false
	}
	slot, ok := p.slots[client.Id]
	if c, _ := unwrapClient(slot); ok && c == client {
		delete(p.slots, client.Id)
		client.Id = base.Server // reset id to default
	}
	return ok
}

// GetResponderIds gets settled responders
func (p *Path) GetResponderIds() []uint8 {
	p.mux.Lock()
	defer p.mux.Unlock()

	ids := make([]uint8, 0)
	var responderID base.AddressType = 0x02
	for ; responderID <= base.Responder; responderID = responderID + 0x01 {
		if _, ok := p.slots[responderID].(*Client); ok {
			ids = append(ids, responderID)
		}
	}
	return ids
}

// FindClientByID finds client by id
func (p *Path) FindClientByID(id base.AddressType) (interface{}, error) {
	p.mux.Lock()
	defer p.mux.Unlock()

	client, prs := p.slots[id]
	if !prs {
		return nil, base.NewValueError(fmt.Sprintf("Invalid slot id:0x%x", id))
	}
	return client, nil
}

func (p *Path) Prune(aliveClientHandler func(c *Client) bool) uint8 {
	freeSlotNum := base.Responder
	var clientID base.AddressType = 0x01
	for ; clientID <= base.Responder; clientID = clientID + 0x01 {
		if slot, ok := p.slots[clientID]; ok {
			client, _ := unwrapClient(slot)
			if client == nil || ((client.conn.AliveStat & base.AliveStatDeath) == base.AliveStatDeath) || aliveClientHandler(client) {
				client.MarkAsOrphan() // should we keep it???
				delete(p.slots, clientID)
				continue
			}
			freeSlotNum = freeSlotNum - 0x01
		}
	}
	return freeSlotNum
}

func (p *Path) MarkAsOrphan() {
	p.AliveStat = base.MarkAsOrphan(p.AliveStat)
}

func (p *Path) MarkAsDeath() {
	p.AliveStat = base.MarkAsDeath(p.AliveStat)
}

func unwrapClient(v interface{}) (*Client, *SlotWrapper) {
	if slotWrapper, ok := v.(*SlotWrapper); ok {
		return slotWrapper.client, slotWrapper
	}
	if client, ok := v.(*Client); ok {
		return client, nil
	}
	return nil, nil
}
