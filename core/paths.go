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

// Add adds path to paths by initiatorKey
// -if path for initiatorKey doesnt exist or existing one is not marked as active, it creates new path and returns the new and old one,
// -otherwise it returns existing one as the new and old one
// func (paths *Paths) Add(initiatorKey string) (*Path, *Path) {
// 	_p := paths.paths[initiatorKey]
// 	oldPath := _p
// 	if _p == nil || _p.AliveStat != base.AliveStatActive {
// 		paths.number++
// 		_p = NewPath(initiatorKey, paths.number)
// 		paths.paths[initiatorKey] = _p
// 	}
// 	return _p, oldPath
// }

// // Get method, returns path instance by initiator key
// func (paths *Paths) Get(initiatorKey string) (*Path, bool) {
// 	path, exists := paths.paths[initiatorKey]
// 	return path, exists
// }

// // Remove method, removes path instance by initiator key
// func (paths *Paths) Remove(initiatorKey string) {
// 	delete(paths.paths, initiatorKey)
// }

// func (paths *Paths) RemovePath(path *Path) {
// 	key := path.InitiatorKey()
// 	_, ok := paths.Get(key)
// 	if ok {
// 		paths.Remove(key)
// 	}
// }
