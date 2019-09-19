package core

import (
	"bytes"
	"errors"
	"io/ioutil"
	"sync"

	"github.com/OguzhanE/saltyrtc-server-go/pkg/arrayutil"
	"github.com/OguzhanE/saltyrtc-server-go/pkg/base"

	"github.com/OguzhanE/saltyrtc-server-go/pkg/boxkeypair"
	"github.com/OguzhanE/saltyrtc-server-go/pkg/naclutil"
	"github.com/OguzhanE/saltyrtc-server-go/pkg/randutil"
	ws "github.com/gobwas/ws"
	"github.com/gobwas/ws/wsutil"

	"github.com/OguzhanE/statmach"
)

// STATES
const (
	None            = "None"
	ClientConnected = "client-connected" // waiting for server-hello message
	ServerHello     = "server-hello"
	ClientHello     = "client-hello"
	ClientAuth      = "client-auth"
	ServerAuth      = "server-auth"

	NewResponder  = "new-responder"
	DropResponder = "drop-responder"

	NewInitiator = "new-itiator"

	SendError    = "send-error"
	Disconnected = "disconnected"

	InitiatorSuperState = "initiator-super-state"
	ResponderSuperState = "responder-super-state"
)

// Triggers
const (
	SendServerHelloMsg  = "sendServerHelloMessage"
	GetClientHelloMsg   = "getClientHelloMessage"
	GetClientAuthMsg    = "getClientAuthMessage"
	SendServerAuthMsg   = "sendServerAuthMessage"
	SendNewInitiatorMsg = "sendNewInitiatorMessage"
	SendNewResponderMsg = "sendNewResponderMessage"
	GetDropResponderMsg = "getDropResponderMessage"
	SendSendErrorMsg    = "sendSendErrorMessage"
	SendDisconnectedMsg = "sendDisconnectedMessage"
)

type CallbackBag struct {
	err error
}

type Client struct {
	mux     sync.Mutex
	conn    *ClientConn
	machine *statmach.StateMachine

	ClientKey          [base.KeyBytesSize]byte
	ServerSessionBox   *boxkeypair.BoxKeyPair
	ServerPermanentBox *boxkeypair.BoxKeyPair
	CookieOut          []byte
	cookieIn           []byte

	CombinedSequenceNumberOut *CombinedSequenceNumber
	CombinedSequenceNumberIn  *CombinedSequenceNumber

	Authenticated bool
	Id            base.AddressType
	typeValue     base.AddressType
	typeHasValue  bool
	Path          *Path
	Server        *Server
}

func (c *Client) Init() {
	sm := statmach.New(ClientConnected)
	c.machine = sm
	sc := sm.Configure(ClientConnected)
	sc.PermitIf(SendServerHelloMsg, ServerHello, func(params ...interface{}) bool {
		/*
					This message MUST be sent by the server after a client connected to the server using a valid signalling path.
					The server MUST generate a new cryptographically secure random NaCl key pair for each client.
					The public key (32 bytes) of that key pair MUST be set in the key field of this message.
					A receiving client MUST check that the message contains a valid NaCl public key (the size of the key MUST be exactly 32 bytes).
					In case the client has knowledge of the server's public permanent key,
					it SHALL ensure that the server's public session key is different to the server's public permanent key.
					The message SHALL NOT be encrypted.
					{
			  		"type": "server-hello",
			  		"key": b"debc3a6c9a630f27eae6bc3fd962925bdeb63844c09103f609bf7082bc383610"
					}
		*/
		bag, _ := params[0].(*CallbackBag)

		msg := NewServerHelloMessage(base.Server, c.Id, c.ServerSessionBox.Pk[:])
		err := c.Send(msg)
		if err != nil {
			bag.err = err
			return false
		}
		return true
	})

	// configure ServerHello
	sc = sm.Configure(ServerHello)
	sc.PermitIf(GetClientHelloMsg, ClientHello, func(params ...interface{}) bool {
		/*
			As soon as the client has received the 'server-hello' message, it MUST ONLY respond with this message in case the client takes the role of a responder.
			The initiator MUST skip this message. The responder MUST set the public key (32 bytes) of the permanent key pair in the key field of this message.
			A receiving server MUST check that the message contains a valid NaCl public key (the size of the key MUST be exactly 32 bytes).
			Note that the server does not know whether the client will send a 'client-hello' message (the client is a responder) or a 'client-auth' message (the client is the initiator).
			Therefore, the server MUST be prepared to handle both message types at that particular point in the message flow.
			This is also the intended way to differentiate between initiator and responder.
			The message SHALL NOT be encrypted.
			{
			  "type": "client-hello",
			  "key": b"55e7dd57a01974ca31b6e588909b7b501cdc7694f21b930abb1600241b2ddb27"
			}
		*/
		bag, _ := params[0].(*CallbackBag)
		msg, _ := params[1].(*ClientHelloMessage)

		_, hasType := c.GetType()
		if hasType {
			bag.err = errors.New("client already has type")
			return false
		}
		if naclutil.IsValidBoxPkBytes(msg.clientPublicKey) {
			bag.err = errors.New("invalid client public key length")
			return false
		}
		c.SetType(base.Responder)
		copy(c.ClientKey[:], msg.clientPublicKey[0:base.KeyBytesSize])
		return true
	})
	// ServerHello->ClientAuth transformation states this method below for initiator handshake
	sc.PermitIf(GetClientAuthMsg, ClientAuth, func(params ...interface{}) bool {
		/*
			   After the 'client-hello' message has been sent (responder) or after the 'server-hello' message has been received (initiator) the client MUST send this message to the server.

			   The client MUST set the your_cookie field to the cookie the server has used in the nonce of the 'server-hello' message.
			   It SHALL also set the subprotocols field to the exact same Array of subprotocol strings it has provided to the WebSocket client implementation for subprotocol negotiation.
				 If the user application requests to be pinged (see RFC 6455 section 5.5.2) in a specific interval,
				 the client SHALL set the field ping_interval to the requested interval in seconds.
				 Otherwise, ping_interval MUST be set to 0 indicating that no WebSocket ping messages SHOULD be sent.
			   If the client has stored the server's public permanent key (32 bytes), it SHOULD set it in the your_key field.
				 When the server receives a 'client-auth' message, it MUST check that the cookie provided in the your_cookie field contains
				 the cookie the server has used in its previous messages to that client.
				 The server SHALL check that the subprotocols field contains an Array of subprotocol strings, and:

				 If the server has access to the subprotocol selection function used by the underlying WebSocket implementation,
				 SHALL use the same function to select the subprotocol from the server's list and the client's list.
				 The resulting selected subprotocol MUST be equal to the initially negotiated subprotocol.
				 If the server does not have access to the subprotocol selection function of the underlying WebSocket implementation but
				 it does have access to the list of subprotocols provided by the client to the WebSocket implementation,
				 it SHALL validate that the lists contain the same subprotocol strings in the same order.
				 If the server is not able to apply either of the above mechanisms, it SHALL validate
				 that the negotiated subprotocol is present in the subprotocols field.
				 Furthermore, the server SHALL validate that the ping_interval field contains a non-negative integer.
				 If the value is 0, the server SHOULD NOT send WebSocket ping messages to the client. Otherwise,
				 the server SHOULD send a WebSocket ping message in the requested interval in seconds to the client and wait for a corresponding pong message
				 (as described in RFC 6455 section 5.5.3). An unanswered ping MUST result in a protocol error and the connection SHALL be closed with a close code of
				 3008 (Timeout). A timeout of 30 seconds for unanswered ping messages is RECOMMENDED.

			   If the 'client-auth' message contains a your_key field, it MUST be compared to the list of server public permanent keys. Then:

			   If the server does not have a permanent key pair, it SHALL drop the client with a close code of 3007 (Invalid Key).
				 If the server does have at least one permanent key pair and if the key sent by the client does not match any of the public keys,
				 it SHALL drop the client with a close code of 3007 (Invalid Key).
				 If the key sent by the client matches a public permanent key of the server,
				 then that key pair SHALL be selected for further usage of the server's permanent key pair towards that client.
				 In case the 'client-auth' message did not contain a your_key field but the server does have at least one permanent key pair,
				 the server SHALL select the primary permanent key pair for further usage of the server's permanent key pair towards the client.

			   The message SHALL be NaCl public-key encrypted by the server's session key pair (public key sent in 'server-hello') and the client's permanent key pair (public key as part of the WebSocket path or sent in 'client-hello').

			   {
			     "type": "client-auth",
			     "your_cookie": b"af354da383bba00507fa8f289a20308a",
			     "subprotocols": [
			       "v1.saltyrtc.org",
			       "some.other.protocol"
			     ],
			     "ping_interval": 30,
			     "your_key": b"2659296ce03993e876d5f2abcaa6d19f92295ff119ee5cb327498d2620efc979"
			   }
		*/

		bag, _ := params[0].(*CallbackBag)
		msg, _ := params[1].(*ClientAuthMessage)
		// validate your_cookie with cookieOut
		if !bytes.Equal(msg.serverCookie, c.CookieOut) {
			bag.err = errors.New("Cookies do not match")
			return false
		}
		chosenArr := arrayutil.IntersectionStr(msg.subprotocols, c.Server.subprotocols)
		if len(chosenArr) == 0 || chosenArr[0] != c.Server.subprotocol {
			bag.err = errors.New("Invalid subprotocol")
			return false
		}
		// todo: continue to impl.
		return true
	})
	// configure ClientHello
	sc = sm.Configure(ClientHello)
	sc.PermitIf(GetClientAuthMsg, ClientAuth, func(params ...interface{}) bool {
		/*
		   After the 'client-hello' message has been sent (responder) or after the 'server-hello' message has been received (initiator) the client MUST send this message to the server.

		   The client MUST set the your_cookie field to the cookie the server has used in the nonce of the 'server-hello' message.
		   It SHALL also set the subprotocols field to the exact same Array of subprotocol strings it has provided to the WebSocket client implementation for subprotocol negotiation.
		   If the user application requests to be pinged (see RFC 6455 section 5.5.2) in a specific interval, the client SHALL set the field ping_interval to the requested interval in seconds. Otherwise, ping_interval MUST be set to 0 indicating that no WebSocket ping messages SHOULD be sent.
		   If the client has stored the server's public permanent key (32 bytes), it SHOULD set it in the your_key field.
		   When the server receives a 'client-auth' message, it MUST check that the cookie provided in the your_cookie field contains the cookie the server has used in its previous messages to that client. The server SHALL check that the subprotocols field contains an Array of subprotocol strings, and:

		   If the server has access to the subprotocol selection function used by the underlying WebSocket implementation, SHALL use the same function to select the subprotocol from the server's list and the client's list. The resulting selected subprotocol MUST be equal to the initially negotiated subprotocol.
		   If the server does not have access to the subprotocol selection function of the underlying WebSocket implementation but it does have access to the list of subprotocols provided by the client to the WebSocket implementation, it SHALL validate that the lists contain the same subprotocol strings in the same order.
		   If the server is not able to apply either of the above mechanisms, it SHALL validate that the negotiated subprotocol is present in the subprotocols field.
		   Furthermore, the server SHALL validate that the ping_interval field contains a non-negative integer. If the value is 0, the server SHOULD NOT send WebSocket ping messages to the client. Otherwise, the server SHOULD send a WebSocket ping message in the requested interval in seconds to the client and wait for a corresponding pong message (as described in RFC 6455 section 5.5.3). An unanswered ping MUST result in a protocol error and the connection SHALL be closed with a close code of 3008 (Timeout). A timeout of 30 seconds for unanswered ping messages is RECOMMENDED.

		   If the 'client-auth' message contains a your_key field, it MUST be compared to the list of server public permanent keys. Then:

		   If the server does not have a permanent key pair, it SHALL drop the client with a close code of 3007 (Invalid Key).
		   If the server does have at least one permanent key pair and if the key sent by the client does not match any of the public keys, it SHALL drop the client with a close code of 3007 (Invalid Key).
		   If the key sent by the client matches a public permanent key of the server, then that key pair SHALL be selected for further usage of the server's permanent key pair towards that client.
		   In case the 'client-auth' message did not contain a your_key field but the server does have at least one permanent key pair, the server SHALL select the primary permanent key pair for further usage of the server's permanent key pair towards the client.

		   The message SHALL be NaCl public-key encrypted by the server's session key pair (public key sent in 'server-hello') and the client's permanent key pair (public key as part of the WebSocket path or sent in 'client-hello').

		   {
		     "type": "client-auth",
		     "your_cookie": b"af354da383bba00507fa8f289a20308a",
		     "subprotocols": [
		       "v1.saltyrtc.org",
		       "some.other.protocol"
		     ],
		     "ping_interval": 30,
		     "your_key": b"2659296ce03993e876d5f2abcaa6d19f92295ff119ee5cb327498d2620efc979"
		   }
		*/
		return true
	})

	// configure ClientAuth
	sc = sm.Configure(ClientAuth)
	sc.PermitIf(SendServerAuthMsg, ServerAuth, func(params ...interface{}) bool {
		/*
					Once the server has received the 'client-auth' message, it SHALL reply with this message. Depending on the client's role, the server SHALL choose and assign an identity to the client by setting the destination address accordingly:

			In case the client is the initiator, a previous initiator on the same path SHALL be dropped by closing its connection with a close code of 3004 (Dropped by Initiator) immediately. The new initiator SHALL be assigned the initiator address (0x01).
			In case the client is a responder, the server SHALL choose a responder identity from the range 0x02..0xff. If no identity can be assigned because each identity is being held by an authenticated responder, the server SHALL close the connection to the client with a close code of 3000 (Path Full).
			After the procedure above has been followed, the client SHALL be marked as authenticated towards the server. The server MUST set the following fields:

			The your_cookie field SHALL contain the cookie the client has used in its previous messages.
			The signed_keys field SHALL be set in case the server has at least one permanent key pair. Its value MUST contain the concatenation of the server's public session key and the client's public permanent key (in that order). The content of this field SHALL be NaCl public key encrypted using the previously selected private permanent key of the server and the client's public permanent key. For encryption, the message's nonce SHALL be used.
			ONLY in case the client is an initiator, the responders field SHALL be set containing an Array of the active responder addresses on that path. An active responder is a responder that has already completed the authentication process and is still connected to the same path as the initiator.
			ONLY in case the client is a responder, the initiator_connected field SHALL be set to a boolean whether an initiator is active on the same path. An initiator is considered active if it has completed the authentication process and is still connected.
			When the client receives a 'server-auth' message, it MUST have accepted and set its identity as described in the Receiving a Signalling Message section. This identity is valid until the connection has been severed. It MUST check that the cookie provided in the your_cookie field contains the cookie the client has used in its previous and messages to the server. If the client has knowledge of the server's public permanent key, it SHALL decrypt the signed_keys field by using the message's nonce, the client's private permanent key and the server's public permanent key. The decrypted message MUST match the concatenation of the server's public session key and the client's public permanent key (in that order). If the signed_keys is present but the client does not have knowledge of the server's permanent key, it SHALL log a warning. Moreover, the client MUST do the following checks depending on its role:

			In case the client is the initiator, it SHALL check that the responders field is set and contains an Array of responder identities. The responder identities MUST be validated and SHALL neither contain addresses outside the range 0x02..0xff nor SHALL an address be repeated in the Array. An empty Array SHALL be considered valid. However, Nil SHALL NOT be considered a valid value of that field. It SHOULD store the responder's identities in its internal list of responders. Additionally, the initiator MUST keep its path clean by following the procedure described in the Path Cleaning section.
			In case the client is the responder, it SHALL check that the initiator_connected field contains a boolean value. In case the field's value is true, the responder MUST proceed with sending a 'token' or 'key' client-to-client message described in the Client-to-Client Messages section.
			After the procedure above has been followed by the client, it SHALL mark the server as authenticated.

			The message SHALL be NaCl public-key encrypted by the server's session key pair and the client's permanent key pair.

			{
			  "type": "server-auth",
			  "your_cookie": b"18b96fd5a151eae23e8b5a1aed2fe30d",
			  "signed_keys": b"e42bfd8c5bc9870ae1a0d928d52810983ac7ddf69df013a7621d072aa9633616cfd...",
			  "initiator_connected": true,  // ONLY towards responders
			  "responders": [  // ONLY towards initiators
			    0x02,
			    0x03
			  ]
			}

		*/
		return true
	})

	// configure ServerAuth
	sc = sm.Configure(ServerAuth)
	sc.PermitIf(SendNewInitiatorMsg, NewInitiator, func(params ...interface{}) bool {
		/*

			When a new initiator has authenticated itself towards the server on a path, the server MUST send this message to all currently authenticated responders on the same path. No additional field needs to be set. The server MUST ensure that a 'new-initiator' message has been sent before the corresponding initiator is able to send messages to any responder.

			A responder who receives a 'new-initiator' message MUST proceed by deleting all currently cached information about and for the previous initiator (such as cookies and the sequence numbers) and continue by sending a 'token' or 'key' client-to-client message described in the Client-to-Client Messages section.

			The message SHALL be NaCl public-key encrypted by the server's session key pair and the responder's permanent key pair.

			{
			  "type": "new-initiator"
			}
		*/
		return true
	})
	sc.PermitIf(SendSendErrorMsg, SendError, func(params ...interface{}) bool {
		/*

			In case the server could not relay a client-to-client message (meaning that the connection between server and the receiver has been severed), the server MUST send this message to the original sender of the message that should have been relayed. The server SHALL set the id field to the concatenation of the source address, the destination address, the overflow number and the sequence number (or the combined sequence number) of the nonce section from the original message.

			A receiving client MUST treat this incident by raising an error event to the user's application and deleting all cached information about and for the other client (such as cookies and sequence numbers). The client MAY stay on the path and wait for a new initiator/responder to connect. However, the client-to-client handshake MUST start from the beginning.

			The message SHALL be NaCl public-key encrypted by the server's session key pair and the client's permanent key pair.

			{
			  "type": "send-error",
			  "id": b"010200000000000f"
			}
		*/
		return true
	})
	sc.PermitIf(SendDisconnectedMsg, Disconnected, func(params ...interface{}) bool {
		/*
		   If an initiator that has been authenticated towards the server terminates the connection with the server, the server SHALL send this message towards all connected and authenticated responders.

		   If a responder that has been authenticated towards the server terminates the connection with the server, the server SHALL send this message towards the initiator (if present).

		   An initiator who receives a 'disconnected' message SHALL validate that the id field contains a valid responder address (0x02..0xff).

		   A responder who receives a 'disconnected' message SHALL validate that the id field contains a valid initiator address (0x01).

		   A receiving client MUST notify the user application about the incoming 'disconnected' message, along with the id field.

		   The message SHALL be NaCl public-key encrypted by the server's session key pair and the client's permanent key pair.

		   {
		     "type": "disconnected",
		     "id": 0x02
		   }
		*/
		return true
	})
	sc.PermitIf(GetDropResponderMsg, DropResponder, func(params ...interface{}) bool {
		/*
		   At any time, an authenticated initiator MAY request to drop an authenticated responder from the path the initiator is connected to by sending this message. The initiator MUST include the id field and set its value to the responder's identity the initiator wants to drop. In addition, it MAY include the reason field which contains an optional close code the server SHALL close the connection to the responder with. Before the message is being sent, the initiator SHALL delete all currently cached information (such as cookies and sequence numbers) about and for the previous responder that used the same address.

		   Upon receiving a 'drop-responder' message, the server MUST validate that the messages has been received from an authenticated initiator. The server MUST validate that the id field contains a valid responder address (0x02..0xff). If a reason field exists, it must contain a valid close code (see Close Code Enumeration, listing of close codes that are valid for 'drop-responder' messages). It proceeds by looking up the WebSocket connection of the provided responder identity. If no connection can be found, the message SHALL be silently discarded but MAY generate an informational logging entry. If the WebSocket connection has been found, the connection SHALL be closed with the provided close code of the reason field. If no reason field has been provided, the connection SHALL be closed with a close code of 3004 (Dropped by Initiator). Closing the connection MUST NOT trigger a 'disconnected' message.

		   The message SHALL be NaCl public-key encrypted by the server's session key pair and the initiator's permanent key pair.

		   {
		     "type": "drop-responder",
		     "id": 0x02,
		     "reason": 3005
		   }
		*/
		return true
	})
	sc.PermitIf(SendNewResponderMsg, NewResponder, func(params ...interface{}) bool {
		/*
		   As soon as a new responder has authenticated itself towards the server on path, the server MUST send this message to an authenticated initiator on the same path. The field id MUST be set to the assigned identity of the newly connected responder. The server MUST ensure that a 'new-responder' message has been sent before the corresponding responder is able to send messages to the initiator.

		   An initiator who receives a 'new-responder' message SHALL validate that the id field contains a valid responder address (0x02..0xff). It SHOULD store the responder's identity in its internal list of responders. If a responder with the same id already exists, all currently cached information about and for the previous responder (such as cookies and the sequence number) MUST be deleted first. Furthermore, the initiator MUST keep its path clean by following the procedure described in the Path Cleaning section.

		   The message SHALL be NaCl public-key encrypted by the server's session key pair and the initiator's permanent key pair.

		   {
		     "type": "new-responder",
		     "id": 0x04
		   }
		*/
		return true
	})

	// configure NewResponder
	sc = sm.Configure(NewResponder)
	sc.SubstateOf(InitiatorSuperState)
	// configure DropResponder
	sc = sm.Configure(DropResponder)
	sc.SubstateOf(InitiatorSuperState)

	// configure InitiatorSuperState
	sc = sm.Configure(InitiatorSuperState)
	sc.PermitIf(SendNewResponderMsg, NewResponder, func(params ...interface{}) bool {
		return true
	})
	sc.PermitIf(GetDropResponderMsg, DropResponder, func(params ...interface{}) bool {

		return true
	})
	sc.PermitIf(SendSendErrorMsg, SendError, func(params ...interface{}) bool {
		return true
	})
	sc.PermitIf(SendDisconnectedMsg, Disconnected, func(params ...interface{}) bool {
		return true
	})

	// configure NewInitiator
	sc = sm.Configure(NewInitiator)
	sc.PermitReentryIf(SendNewInitiatorMsg, func(params ...interface{}) bool {

		return true
	})
	sc.PermitIf(SendSendErrorMsg, SendError, func(params ...interface{}) bool {

		return true
	})
	sc.PermitIf(SendDisconnectedMsg, Disconnected, func(params ...interface{}) bool {

		return true
	})

	// configure SendError
	sc = sm.Configure(SendError)
	sc.PermitReentryIf(SendSendErrorMsg, func(params ...interface{}) bool {
		return true
	})
	sc.PermitIf(SendDisconnectedMsg, Disconnected, func(params ...interface{}) bool {
		return true
	})
	sc.PermitIf(SendNewInitiatorMsg, NewInitiator, func(params ...interface{}) bool {
		return true
	})
	sc.PermitIf(SendNewResponderMsg, NewResponder, func(params ...interface{}) bool {
		return true
	})
	sc.PermitIf(GetDropResponderMsg, DropResponder, func(params ...interface{}) bool {
		return true
	})
	// configure Disconnected
	sc = sm.Configure(Disconnected)
	sc.PermitReentryIf(SendDisconnectedMsg, func(params ...interface{}) bool {
		return true
	})
	sc.PermitIf(SendSendErrorMsg, SendError, func(params ...interface{}) bool {
		return true
	})
	sc.PermitIf(SendNewInitiatorMsg, NewInitiator, func(params ...interface{}) bool {
		return true
	})
	sc.PermitIf(SendNewResponderMsg, NewResponder, func(params ...interface{}) bool {
		return true
	})
	sc.PermitIf(GetDropResponderMsg, DropResponder, func(params ...interface{}) bool {
		return true
	})
}

// todo: implement it properly
func NewClient(conn *ClientConn, clientKey [base.KeyBytesSize]byte, permanentBox, sessionBox *boxkeypair.BoxKeyPair) (*Client, error) {
	cookieOut, err := randutil.RandBytes(16)
	if err != nil {
		return nil, err
	}
	initialSeqNum, err := randutil.RandUint32()
	if err != nil {
		return nil, err
	}
	return &Client{
		conn:                      conn,
		ClientKey:                 clientKey,
		CookieOut:                 cookieOut,
		CombinedSequenceNumberOut: NewCombinedSequenceNumber(initialSeqNum),
		ServerPermanentBox:        permanentBox,
		ServerSessionBox:          sessionBox,
	}, nil
}

func (c *Client) GetCookieIn() []byte {
	return c.cookieIn
}
func (c *Client) SetCookieIn(cookieIn []byte) error {
	if c.cookieIn == nil {
		if bytes.Equal(cookieIn, c.CookieOut) {
			return errors.New("Server and client cookies cannot be the same")
		}
		c.cookieIn = cookieIn
	} else {
		if !bytes.Equal(c.cookieIn, cookieIn) {
			return errors.New("Client cookie is not changeable")
		}
	}
	return nil
}

func (c *Client) GetType() (base.AddressType, bool) {
	return c.typeValue, c.typeHasValue
}
func (c *Client) SetType(t base.AddressType) {
	c.typeHasValue = true
	c.typeValue = t
}

// Receive reads next message from Client's underlying connection.
// It blocks until full message received.
func (c *Client) Receive() error {

	msgIncoming, err := c.readIncomingMessage()
	if err != nil {
		// c.conn.Close()
		// todo: close connection
		return err
	}
	if msgIncoming == nil {
		// Handled some control message.
		return nil
	}
	if msg, ok := msgIncoming.(*ClientHelloMessage); ok {
		c.machine.Fire(ClientHello, msg)
	}
	// todo: handle all messages
	return nil
}

// readIncomingMessage reads and unpacks received data from connection.
// It takes io mutex.
func (c *Client) readIncomingMessage() (BaseMessage, error) {
	c.mux.Lock()
	defer c.mux.Unlock()

	h, r, err := wsutil.NextReader(c.conn, ws.StateServerSide)
	if err != nil {
		return nil, err
	}
	if h.OpCode.IsControl() {
		return nil, wsutil.ControlFrameHandler(c.conn, ws.StateServerSide)(h, r)
	}
	// read all raw data
	b, err := ioutil.ReadAll(r)
	if err != nil {
		return nil, err
	}

	// try to unpack data in order to obtain message
	msg, err := Unpack(c, b)
	if err != nil {
		return nil, err
	}

	return msg, nil
}

func (c *Client) Send(msg BaseMessagePacker) error {
	c.mux.Lock()
	defer c.mux.Unlock()
	b, err := msg.Pack(c)
	if err != nil {
		return err
	}
	_, err = c.conn.Write(b)
	return err
}
