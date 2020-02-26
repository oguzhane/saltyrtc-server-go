package protocol

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

type MessageFlowError struct {
	Msg string
	Err error
}

func NewMessageFlowError(message string, err error) *MessageFlowError {
	return &MessageFlowError{
		Msg: message,
		Err: err,
	}
}

func (e *MessageFlowError) Error() string {
	return e.Msg + ": " + e.Err.Error()
}
