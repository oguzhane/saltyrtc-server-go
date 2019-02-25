package core

import (
	"encoding/binary"
	"io"
	"math"

	"github.com/oguzhane/saltyrtc-server-go/common"
)

type CombinedSequenceNumber struct {
	overflowNum            uint16
	sequenceNum            uint32
	hasErrOverflowSentinel bool
}

func (csn *CombinedSequenceNumber) AsBytes() ([]byte, error) {
	if csn.hasErrOverflowSentinel {
		return nil, common.ErrOverflowSentinel
	}
	b := make([]byte, 6)
	binary.BigEndian.PutUint16(b[0:], csn.overflowNum)
	binary.BigEndian.PutUint32(b[2:], csn.sequenceNum)
	return b, nil
}

func (csn *CombinedSequenceNumber) Write(w io.Writer) error {
	if csn.hasErrOverflowSentinel {
		return common.ErrOverflowSentinel
	}
	err := binary.Write(w, binary.BigEndian, csn.overflowNum)
	if err != nil {
		return err
	}
	err = binary.Write(w, binary.BigEndian, csn.sequenceNum)
	return err
}

func (csn *CombinedSequenceNumber) WillHaveErrOverflowSentinel() bool {
	return csn.hasErrOverflowSentinel || (csn.overflowNum == math.MaxUint16 && csn.sequenceNum == math.MaxUint32)
}

func (csn *CombinedSequenceNumber) HasErrOverflowSentinel() bool {
	return csn.hasErrOverflowSentinel
}

func (csn *CombinedSequenceNumber) GetOverflowNumber() uint16 {
	return csn.overflowNum
}

func (csn *CombinedSequenceNumber) GetSequenceNumber() uint32 {
	return csn.sequenceNum
}

func (csn *CombinedSequenceNumber) Increment() error {
	if csn.hasErrOverflowSentinel ||
		(csn.overflowNum == math.MaxUint16 && csn.sequenceNum == math.MaxUint32) {
		csn.hasErrOverflowSentinel = true
		return common.ErrOverflowSentinel
	}
	if csn.sequenceNum == math.MaxUint32 {
		csn.overflowNum = csn.overflowNum + 0x01
	}
	csn.sequenceNum = csn.sequenceNum + 0x01
	return nil
}

func NewCombinedSequenceNumber(initialSequenceNum uint32) *CombinedSequenceNumber {
	return &CombinedSequenceNumber{
		overflowNum: 0x0000,
		sequenceNum: initialSequenceNum,
	}
}
