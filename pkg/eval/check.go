package base

import "errors"

var ErrNoEvalFunc = errors.New("NoEvalFunc")

type Check struct {
	Err     error
	firstFn *checkFuncNode
	lastFn  *checkFuncNode
}

func NewCheckWithErr(err error) *Check {
	return &Check{
		Err: err,
	}
}

func NewCheck() *Check {
	return &Check{}
}

func (c *Check) SetErr(err error) {
	c.Err = err
}

func (c *Check) Push(fn func() error) {
	if c.lastFn != nil {
		c.lastFn.next = &checkFuncNode{
			fn: fn,
		}
		c.lastFn = c.lastFn.next
	} else {
		c.firstFn = &checkFuncNode{
			fn: fn,
		}
		c.lastFn = c.firstFn
	}
}

func (c *Check) Eval() error {
	if c.Err != nil {
		return c.Err
	}
	if c.firstFn == nil {
		return ErrNoEvalFunc
	}
	curr := c.firstFn
	for curr != nil {
		err := curr.fn()
		if err != nil {
			return err
		}
		curr = curr.next
	}
	return nil
}

type checkFuncNode struct {
	fn   func() error
	next *checkFuncNode
}
