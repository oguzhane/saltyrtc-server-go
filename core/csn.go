package core

import (
	"encoding/binary"
	"errors"
	"io"
	"math"
)

var (
	// ErrOverflowSentinel ..
	ErrOverflowSentinel = errors.New("OverflowSentinel")
	// ErrInvalidOverflowNumber ..
	ErrInvalidOverflowNumber = errors.New("Invalid overflow number")
	// ErrNotExpectedCsn ..
	ErrNotExpectedCsn = errors.New("unexpected sequence number")
)

// CombinedSequenceNumber ..
type CombinedSequenceNumber struct {
	overflowNum            uint16
	sequenceNum            uint32
	hasErrOverflowSentinel bool
}

// AsBytes gets csn as bytes
func (csn *CombinedSequenceNumber) AsBytes() ([]byte, error) {
	if csn.hasErrOverflowSentinel {
		return nil, ErrOverflowSentinel
	}
	b := make([]byte, 6)
	binary.BigEndian.PutUint16(b[0:], csn.overflowNum)
	binary.BigEndian.PutUint32(b[2:], csn.sequenceNum)
	return b, nil
}

func (csn *CombinedSequenceNumber) Write(w io.Writer) error {
	if csn.hasErrOverflowSentinel {
		return ErrOverflowSentinel
	}
	err := binary.Write(w, binary.BigEndian, csn.overflowNum)
	if err != nil {
		return err
	}
	err = binary.Write(w, binary.BigEndian, csn.sequenceNum)
	return err
}

// WillHaveErrOverflowSentinel states if the next csn will have ErrOverflowSentinel
func (csn *CombinedSequenceNumber) WillHaveErrOverflowSentinel() bool {
	return csn.hasErrOverflowSentinel || (csn.overflowNum == math.MaxUint16 && csn.sequenceNum == math.MaxUint32)
}

// HasErrOverflowSentinel ..
func (csn *CombinedSequenceNumber) HasErrOverflowSentinel() bool {
	return csn.hasErrOverflowSentinel
}

// GetOverflowNumber ..
func (csn *CombinedSequenceNumber) GetOverflowNumber() uint16 {
	return csn.overflowNum
}

// GetSequenceNumber ..
func (csn *CombinedSequenceNumber) GetSequenceNumber() uint32 {
	return csn.sequenceNum
}

// Increment increase csn one
func (csn *CombinedSequenceNumber) Increment() error {
	if csn.hasErrOverflowSentinel ||
		(csn.overflowNum == math.MaxUint16 && csn.sequenceNum == math.MaxUint32) {
		csn.hasErrOverflowSentinel = true
		return ErrOverflowSentinel
	}
	if csn.sequenceNum == math.MaxUint32 {
		csn.overflowNum = csn.overflowNum + 0x01
		csn.sequenceNum = 0x00
		return nil
	}
	csn.sequenceNum = csn.sequenceNum + 0x01
	return nil
}

// EqualsTo ..
func (csn *CombinedSequenceNumber) EqualsTo(targetCsn *CombinedSequenceNumber) bool {
	return csn.overflowNum == targetCsn.overflowNum && csn.sequenceNum == targetCsn.sequenceNum
}

// NewCombinedSequenceNumber ..
func NewCombinedSequenceNumber(initialSequenceNum uint32) *CombinedSequenceNumber {
	return &CombinedSequenceNumber{
		overflowNum: 0x0000,
		sequenceNum: initialSequenceNum,
	}
}

// ParseCombinedSequenceNumber ..
func ParseCombinedSequenceNumber(csnBytes []byte) (*CombinedSequenceNumber, error) {
	if len(csnBytes) != 6 {
		return nil, errors.New("the length of csnBytes must be 6 bytes")
	}

	csn := &CombinedSequenceNumber{
		overflowNum: binary.BigEndian.Uint16(csnBytes[0:2]),
		sequenceNum: binary.BigEndian.Uint32(csnBytes[2:6]),
	}

	return csn, nil
}
