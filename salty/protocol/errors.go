package protocol

import (
	"errors"
)

var (
	// ErrSlotsFull occurs when no free slot on path
	ErrSlotsFull = errors.New("no free slot on path")
)

// MessageFlowError occurs when a received message violates flow
type MessageFlowError struct {
	Msg string
	Err error
}

// NewMessageFlowError ..
func NewMessageFlowError(message string, err error) *MessageFlowError {
	return &MessageFlowError{
		Msg: message,
		Err: err,
	}
}

func (e *MessageFlowError) Error() string {
	return e.Msg + ": " + e.Err.Error()
}
