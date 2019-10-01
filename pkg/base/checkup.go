package base

import "errors"

var ErrNoEvalFunc = errors.New("NoEvalFunc")

type CheckUp struct {
	Err     error
	firstFn *checkUpFuncNode
	lastFn  *checkUpFuncNode
}

func NewCheckUpWithErr(err error) *CheckUp {
	return &CheckUp{
		Err: err,
	}
}

func NewCheckUp() *CheckUp {
	return &CheckUp{}
}

func (c *CheckUp) SetErr(err error) {
	c.Err = err
}

func (c *CheckUp) Push(fn func() error) {
	if c.lastFn != nil {
		c.lastFn.next = &checkUpFuncNode{
			fn: fn,
		}
		c.lastFn = c.lastFn.next
	} else {
		c.firstFn = &checkUpFuncNode{
			fn: fn,
		}
		c.lastFn = c.firstFn
	}
}

func (c *CheckUp) Eval() error {
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

type checkUpFuncNode struct {
	fn   func() error
	next *checkUpFuncNode
}
