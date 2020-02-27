package base

type Guard struct {
	defaultGuard func() bool
	firstFn      *GuardFuncNode
	lastFn       *GuardFuncNode
}

func NewGuard(defaultGuard func() bool) *Guard {
	return &Guard{
		defaultGuard: defaultGuard,
	}
}

func (c *Guard) Push(fn func(prevGuard *func() bool) func() bool) {
	if c.lastFn != nil {
		c.lastFn.next = &GuardFuncNode{
			fn: fn,
		}
		c.lastFn = c.lastFn.next
	} else {
		c.firstFn = &GuardFuncNode{
			fn: fn,
		}
		c.lastFn = c.firstFn
	}
}

func (c *Guard) Eval() {
	if !c.defaultGuard() || c.firstFn == nil {
		return
	}
	curr := c.firstFn
	currGuard := c.defaultGuard
	for curr != nil {
		currGuard := curr.fn(&currGuard)
		if !currGuard() {
			return
		}
		curr = curr.next
	}
}

type GuardFuncNode struct {
	fn   func(prevGuard *func() bool) func() bool
	next *GuardFuncNode
}
