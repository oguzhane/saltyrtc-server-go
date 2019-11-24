package core

import (
	"bytes"
	"reflect"
	"testing"

	"github.com/OguzhanE/saltyrtc-server-go/pkg/base"
	"github.com/OguzhanE/saltyrtc-server-go/pkg/boxkeypair"
	"github.com/OguzhanE/saltyrtc-server-go/pkg/hexutil"
)

func TestServerHelloMessage(t *testing.T) {
	clientKey, _ := hexutil.HexStringToBytes32("eed23022797406049feb27c3812f8411ab521faafe7fb1b02717745cb0dcfa15")
	permanentBox, _ := boxkeypair.GenerateBoxKeyPair()
	sessionBox, _ := boxkeypair.GenerateBoxKeyPair()
	serverBox, _ := boxkeypair.GenerateBoxKeyPair()

	client, _ := NewClient(nil, *clientKey, permanentBox, sessionBox)
	msg := NewServerHelloMessage(base.Server, base.Initiator, serverBox.Pk[:])
	packedBytes, _ := Pack(client, base.Server, base.Initiator, msg)

	rawUnpack, err := UnpackRaw(packedBytes)

	if err != nil || rawUnpack.Source != msg.src || rawUnpack.Dest != msg.dest || !reflect.DeepEqual(rawUnpack.Cookie, client.CookieOut) {
		t.Errorf("unmatched nonce. err: %#v\n", err)
	}
	decodedPayload, err := decodePayload(rawUnpack.Payload)
	if err != nil || decodedPayload.Type != base.ServerHello || !reflect.DeepEqual(serverBox.Pk[:], decodedPayload.Key) {
		t.Errorf("unmatched payload. err: %#v\n", err)
	}
}

func TestClientHelloMessage(t *testing.T) {
	clientKey, _ := hexutil.HexStringToBytes32("eed23022797406049feb27c3812f8411ab521faafe7fb1b02717745cb0dcfa15")
	permanentBox, _ := boxkeypair.GenerateBoxKeyPair()
	sessionBox, _ := boxkeypair.GenerateBoxKeyPair()

	remoteClient, _ := NewClient(nil, *clientKey, permanentBox, sessionBox)
	remoteClient.Id = base.Initiator

	msg := NewClientHelloMessage(base.Initiator, base.Server, clientKey[:])
	packedBytes, _ := Pack(remoteClient, base.Initiator, base.Server, msg)
	rawUnpack, err := UnpackRaw(packedBytes)
	if err != nil || rawUnpack.Source != msg.src || rawUnpack.Dest != msg.dest || !reflect.DeepEqual(rawUnpack.Cookie, remoteClient.CookieOut) {
		t.Errorf("unmatched nonce. err: %#v\n", err)
	}
	decodedPayload, err := decodePayload(rawUnpack.Payload)
	if err != nil || decodedPayload.Type != base.ClientHello || !reflect.DeepEqual((*clientKey)[:], decodedPayload.Key) {
		t.Errorf("unmatched payload. err: %#v\n", err)
	}
	t.Logf("%#v\n", remoteClient.CombinedSequenceNumberOut)

	// Reset csn
	t.Logf("%#v\n", remoteClient.CombinedSequenceNumberOut)

	initiator, _ := NewClient(nil, *clientKey, permanentBox, sessionBox)
	initiator.Id = base.Initiator

	msgUnpack, err := Unpack(initiator, packedBytes, UnpackRaw)
	if err != nil {
		t.Errorf("cant unpack message. err: %#v\n", err)
	}

	helloMsg, ok := msgUnpack.(*ClientHelloMessage)
	if !ok {
		t.Error("invalid unpacked message")
	}

	if !reflect.DeepEqual(helloMsg, msg) {
		t.Error("unmatched unpacked message")
	}
}

func TestClientAuthMessage(t *testing.T) {
	clientKey, _ := hexutil.HexStringToBytes32("eed23022797406049feb27c3812f8411ab521faafe7fb1b02717745cb0dcfa15")
	permanentBox, _ := boxkeypair.GenerateBoxKeyPair()
	sessionBox, _ := boxkeypair.GenerateBoxKeyPair()

	remoteClient, _ := NewClient(nil, *clientKey, permanentBox, sessionBox)
	remoteClient.Authenticated = true
	remoteClient.Id = base.Initiator

	msg := NewClientAuthMessage(base.Initiator, base.Server, remoteClient.CookieOut, []string{base.SubprotocolSaltyRTCv1}, 10, permanentBox.Pk)
	oldCsnOut := &CombinedSequenceNumber{
		overflowNum: remoteClient.CombinedSequenceNumberOut.overflowNum,
		sequenceNum: remoteClient.CombinedSequenceNumberOut.sequenceNum,
	}
	packedBytes, err := Pack(remoteClient, base.Initiator, base.Server, msg)
	rawData, err := UnpackRaw(packedBytes)
	// t.Logf("-> %#v\n", rawUnpack)
	oldCsnBytes, err := oldCsnOut.AsBytes()
	if err != nil ||
		rawData.Source != msg.src ||
		rawData.Dest != msg.dest ||
		!reflect.DeepEqual(rawData.Cookie, remoteClient.CookieOut) || !reflect.DeepEqual(oldCsnBytes, rawData.Csn) {
		t.Errorf("unmatched nonce. err: %#v\n", err)
	}
	decryptedPayload, err := decryptPayload(remoteClient, rawData.Nonce, rawData.Payload)
	if err != nil {
		t.Errorf("cant decrypt: %#v\n", err)
	}

	decodedPayload, err := decodePayload(decryptedPayload)

	if err != nil || decodedPayload.Type != base.ClientAuth ||
		!reflect.DeepEqual(decodedPayload.YourCookie, msg.serverCookie) ||
		!reflect.DeepEqual(decodedPayload.Subprotocols, msg.subprotocols) ||
		!reflect.DeepEqual(decodedPayload.PingInterval, msg.pingInterval) ||
		!bytes.Equal(decodedPayload.YourKey, msg.serverKey[:]) {
		t.Errorf("unmatched payload. err: %#v\n", err)
	}

	initiator, _ := NewClient(nil, *clientKey, permanentBox, sessionBox)
	initiator.Id = base.Initiator
	msgUnpack, err := Unpack(initiator, packedBytes, UnpackRaw)
	if err != nil {
		t.Errorf("cant unpack message. err: %#v\n", err)
	}
	// fmt.Printf("->%#v\n", msgUnpack)

	clientAuthMsg, ok := msgUnpack.(*ClientAuthMessage)
	if !ok {
		t.Error("invalid unpacked message")
	}

	if !reflect.DeepEqual(clientAuthMsg, msg) {
		t.Error("unmatched unpacked message")
	}
}

func TestServerAuthMessage(t *testing.T) {
	clientKey, _ := hexutil.HexStringToBytes32("eed23022797406049feb27c3812f8411ab521faafe7fb1b02717745cb0dcfa15")
	permanentBox, _ := boxkeypair.GenerateBoxKeyPair()
	sessionBox, _ := boxkeypair.GenerateBoxKeyPair()

	remoteClient, _ := NewClient(nil, *clientKey, permanentBox, sessionBox)
	remoteClient.Authenticated = true
	remoteClient.Id = base.Initiator

	msg := NewServerAuthMessageForInitiator(base.Server, base.Initiator, remoteClient.CookieOut, true, []uint8{0x02, 0x03})
	oldCsnOut := &CombinedSequenceNumber{
		overflowNum: remoteClient.CombinedSequenceNumberOut.overflowNum,
		sequenceNum: remoteClient.CombinedSequenceNumberOut.sequenceNum,
	}
	packedBytes, err := Pack(remoteClient, base.Server, base.Initiator, msg)
	rawData, err := UnpackRaw(packedBytes)
	// t.Logf("-> %#v\n", rawUnpack)
	oldCsnBytes, err := oldCsnOut.AsBytes()
	if err != nil ||
		rawData.Source != msg.src ||
		rawData.Dest != msg.dest ||
		!reflect.DeepEqual(rawData.Cookie, remoteClient.CookieOut) ||
		!reflect.DeepEqual(oldCsnBytes, rawData.Csn) {
		t.Errorf("unmatched nonce. err: %#v\n", err)
	}

	decryptedPayload, err := decryptPayload(remoteClient, rawData.Nonce, rawData.Payload)
	if err != nil {
		t.Errorf("cant decrypt: %#v\n", err)
	}

	decodedPayload, err := decodePayload(decryptedPayload)

	if err != nil || decodedPayload.Type != base.ServerAuth ||
		!reflect.DeepEqual(decodedPayload.YourCookie, msg.clientCookie) ||
		!reflect.DeepEqual(decodedPayload.InitiatorConnected, msg.initiatorConnected) {
		t.Errorf("unmatched payload. err: %#v\n", err)
	}
}
