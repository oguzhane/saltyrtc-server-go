package base

type EvalWithGuard struct {
	defaultGuard func() bool
	firstFn      *EvalWithGuardFuncNode
	lastFn       *EvalWithGuardFuncNode
}

func NewEvalWithGuard(defaultGuard func() bool) *EvalWithGuard {
	return &EvalWithGuard{
		defaultGuard: defaultGuard,
	}
}

func (c *EvalWithGuard) Push(fn func(prevGuard *func() bool) func() bool) {
	if c.lastFn != nil {
		c.lastFn.next = &EvalWithGuardFuncNode{
			fn: fn,
		}
		c.lastFn = c.lastFn.next
	} else {
		c.firstFn = &EvalWithGuardFuncNode{
			fn: fn,
		}
		c.lastFn = c.firstFn
	}
}

func (c *EvalWithGuard) Eval() {
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

type EvalWithGuardFuncNode struct {
	fn   func(prevGuard *func() bool) func() bool
	next *EvalWithGuardFuncNode
}
