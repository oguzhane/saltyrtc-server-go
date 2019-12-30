package core

import (
	"sync/atomic"

	hm "github.com/cornelk/hashmap"
)

// Paths stores path instances
type Paths struct {
	hmap   *hm.HashMap
	number uint32
}

// NewPaths creates new Paths instance
func NewPaths() *Paths {
	return &Paths{
		hmap:   &hm.HashMap{},
		number: 0,
	}
}

// GetOrCreate ..
func (paths *Paths) GetOrCreate(key string) (*Path, bool) {
	v, ok := paths.hmap.Get(key)
	if p := v.(*Path); ok && !p.orphan {
		return p, true
	}
	num := atomic.AddUint32(&paths.number, 1)
	p := NewPath(key, num)
	paths.hmap.Set(key, p)
	return p, false
}
