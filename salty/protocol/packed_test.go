package protocol

import (
	"bytes"
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestWriteHeader(t *testing.T) {
	require := require.New(t)
	var buf bytes.Buffer

	want := make([]byte, HeaderSize)
	rand.Read(want)

	header := Header{
		Cookie: want[:CookieLength],
		Src:    want[16],
		Dest:   want[17],
		Csn:    want[18:],
	}

	WriteHeader(&buf, header)
	got := buf.Bytes()

	require.Equal(want, got)
}

func TestWriteFrame(t *testing.T) {
	require := require.New(t)
	var buf bytes.Buffer

	headerBts, header := newTestHeader()

	payload := make([]byte, 32)
	rand.Read(payload)

	want := append(headerBts, payload...)
	f := Frame{
		Header:  header,
		Payload: payload,
	}

	WriteFrame(&buf, f)

	got := buf.Bytes()

	require.Equal(want, got)
}

func TestReadHeader(t *testing.T) {
	require := require.New(t)
	var buf bytes.Buffer

	bts, want := newTestHeader()
	buf.Write(bts)

	got, err := ReadHeader(&buf)

	require.Nil(err)

	require.Equal(want.Cookie, got.Cookie)
	require.Equal(want.Src, got.Src)
	require.Equal(want.Dest, got.Dest)
	require.Equal(want.Csn, got.Csn)
}

func TestReadFrame(t *testing.T) {
	require := require.New(t)
	var buf bytes.Buffer

	headerBts, wantHeader := newTestHeader()

	wantPayload := make([]byte, 32)
	rand.Read(wantPayload)

	buf.Write(append(headerBts, wantPayload...))

	f, err := ReadFrame(&buf)

	require.Nil(err)

	require.Equal(wantHeader.Cookie, f.Header.Cookie)
	require.Equal(wantHeader.Src, f.Header.Src)
	require.Equal(wantHeader.Dest, f.Header.Dest)
	require.Equal(wantHeader.Csn, f.Header.Csn)

	require.Equal(wantPayload, f.Payload)
}

func TestReadFrameWithSize(t *testing.T) {
	require := require.New(t)
	var buf bytes.Buffer

	headerBts, wantHeader := newTestHeader()

	wantPayload := make([]byte, 32)
	rand.Read(wantPayload)

	buf.Write(append(headerBts, wantPayload...))

	f, err := ReadFrameWithSize(&buf, 56)

	require.Nil(err)

	require.Equal(wantHeader.Cookie, f.Header.Cookie)
	require.Equal(wantHeader.Src, f.Header.Src)
	require.Equal(wantHeader.Dest, f.Header.Dest)
	require.Equal(wantHeader.Csn, f.Header.Csn)

	require.Equal(wantPayload, f.Payload)
}

func TestParseHeader(t *testing.T) {
	require := require.New(t)

	bts, want := newTestHeader()
	got, err := ParseHeader(bts)

	require.Nil(err)

	require.Equal(want.Cookie, got.Cookie)
	require.Equal(want.Src, got.Src)
	require.Equal(want.Dest, got.Dest)
	require.Equal(want.Csn, got.Csn)
}

func TestParseHeader_InvalidLength(t *testing.T) {
	require := require.New(t)

	_, err := ParseHeader([]byte{0x01, 0x02})

	require.Equal(ErrHeaderLengthUnexpected, err)
}

func TestExtractNonce(t *testing.T) {
	require := require.New(t)

	want, _ := newTestHeader()

	got, err := ExtractNonce(append(want, []byte{0x01}...))

	require.Nil(err)
	require.Equal(want, got)
}

func TestExtractNonce_InvalidLength(t *testing.T) {
	require := require.New(t)

	got, err := ExtractNonce([]byte{0x01, 0x02})

	require.Equal(ErrHeaderLengthUnexpected, err)
	require.Nil(got)
}

func TestMakeNonce(t *testing.T) {
	require := require.New(t)

	want, h := newTestHeader()

	got := MakeNonce(h)

	require.Equal(want, got)
}

func TestParseFrame(t *testing.T) {
	require := require.New(t)

	headerBts, wantHeader := newTestHeader()

	wantPayload := make([]byte, 32)
	rand.Read(wantPayload)

	f, err := ParseFrame(append(headerBts, wantPayload...))

	require.Nil(err)

	require.Equal(wantHeader.Cookie, f.Header.Cookie)
	require.Equal(wantHeader.Src, f.Header.Src)
	require.Equal(wantHeader.Dest, f.Header.Dest)
	require.Equal(wantHeader.Csn, f.Header.Csn)

	require.Equal(wantPayload, f.Payload)
}

func newTestHeader() (bts []byte, h Header) {
	bts = make([]byte, HeaderSize)
	rand.Read(bts)
	h = Header{
		Cookie: bts[:CookieLength],
		Src:    bts[16],
		Dest:   bts[17],
		Csn:    bts[18:],
	}
	return
}
