package common

import (
	"errors"
)

var (
	ErrOverflowSentinel = errors.New("OverflowSentinel")
)


type SlotsFullError struct {
	msg string
}

func NewSlotsFullError(message string) *SlotsFullError {
	return &SlotsFullError{
		msg: message,
	}
}

func (e *SlotsFullError) Error() string {
	return e.msg
}


type ValueError struct {
	msg string
}

func NewValueError(message string) *ValueError {
	return &ValueError{
		msg: message,
	}
}

func (e *ValueError) Error() string {
	return e.msg
}


type PathError struct {
	msg string
}

func NewPathError(message string) *PathError {
	return &PathError{
		msg: message,
	}
}

func (e *PathError) Error() string {
	return e.msg
}


type MessageFlowError struct {
	msg string
}

func NewMessageFlowError(message string) *MessageFlowError {
	return &MessageFlowError{
		msg: message,
	}
}

func (e *MessageFlowError) Error() string {
	return e.msg
}