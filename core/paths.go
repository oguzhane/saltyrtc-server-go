package core

// Paths stores path instances
type Paths struct {
	paths  map[string]*Path
	number uint32
}

// NewPaths creates new Paths instance
func NewPaths() *Paths {
	return &Paths{
		paths:  make(map[string]*Path),
		number: 0,
	}
}

// AddNewPath adds path to paths by initiatorKey
// -if the same initiatorKey exists, it doesnt add new path and returns nil,
// -otherwise creates Path and add it to paths returns the instance
func (paths *Paths) AddNewPath(initiatorKey string) *Path {
	_p := paths.paths[initiatorKey]
	if _p == nil {
		paths.paths[initiatorKey] = NewPath(initiatorKey, paths.number+1)
		paths.number++
		return paths.paths[initiatorKey]
	}
	return nil
}

// Get method, returns path instance by initiator key
func (paths *Paths) Get(initiatorKey string) (*Path, bool) {
	path, exists := paths.paths[initiatorKey]
	return path, exists
}

// Remove method, removes path instance by initiator key
func (paths *Paths) Remove(initiatorKey string) {
	delete(paths.paths, initiatorKey)
}
