package tracker

import (
	"errors"
	"net"
	"time"

	adErrors "airdispat.ch/errors"
	"airdispat.ch/identity"
	"airdispat.ch/message"
	"airdispat.ch/tracker/wire"
	"code.google.com/p/goprotobuf/proto"
)

// The error Structure used to store all of the
// errors generated by the tracker framework
type TrackerError struct {
	Location string
	Error    error
}

// The delegate protocol used to interact with a specific tracker
// implementation
type TrackerDelegate interface {
	HandleError(err *TrackerError)
	LogMessage(toLog ...string)
	AllowConnection(fromAddr *identity.Address) bool

	SaveRecord(address *identity.Address, record *message.SignedMessage, alias string)

	GetRecordByAddress(address *identity.Address) *message.SignedMessage
	GetRecordByAlias(alias string) *message.SignedMessage
}

// The tracker structure that holds variables to the delegate
// and keypair.
type Tracker struct {
	Key      *identity.Identity
	Delegate TrackerDelegate
}

// The function that starts the Tracking Server on a Specific Port
func (t *Tracker) StartServer(port string) error {
	// Resolve the Address of the Server
	service := ":" + port
	tcpAddr, _ := net.ResolveTCPAddr("tcp4", service)
	t.Delegate.LogMessage("Starting Tracker on " + service)

	// Start the Server
	listener, err := net.ListenTCP("tcp", tcpAddr)
	if err != nil {
		return err
	}
	t.Delegate.LogMessage("Tracker is Running...")

	t.trackerLoop(listener)
	return nil
}

// Called when the Tracker runs into an error. It reports the error to the delegate.
func (t *Tracker) handleError(location string, error error) {
	t.Delegate.HandleError(&TrackerError{
		Location: location,
		Error:    error,
	})
}

// This is the loop used while the Tracker waits for clients to connect.
func (t *Tracker) trackerLoop(listener *net.TCPListener) {
	// Loop Forever while we wait for Clients
	for {
		// Open a Connection to the Client
		conn, err := listener.Accept()
		if err != nil {
			t.handleError("Tracker Loop (Accepting New Client)", err)
			return
		}

		// Concurrently Handle the Connection
		go t.handleClient(conn)
	}
}

// Called when the tracker connects to a client.
func (t *Tracker) handleClient(conn net.Conn) {
	t.Delegate.LogMessage("Serving", conn.RemoteAddr().String())
	tNow := time.Now()
	defer t.Delegate.LogMessage("Finished with", conn.RemoteAddr().String(), "in", time.Since(tNow).String())

	defer conn.Close()
	// Read in the Message Sent from the Client
	newMessage, err := message.ReadMessageFromConnection(conn)
	if err != nil {
		t.handleError("Handle Client (Reading in Message)", err)
		adErrors.CreateError(adErrors.UnexpectedError, "Unable to read message.", t.Key.Address).Send(t.Key, conn)
		return
	}

	s, err := newMessage.Decrypt(t.Key)
	if err != nil {
		t.handleError("Unable to decrypt message.", err)
		adErrors.CreateError(adErrors.UnexpectedError, "Unable to decrypt message.", t.Key.Address).Send(t.Key, conn)
		return
	}

	if !s.Verify() {
		t.handleError("Unable to verify message.", nil)
		adErrors.CreateError(adErrors.InvalidSignature, "Unable to verify message.", t.Key.Address).Send(t.Key, conn)
		return
	}

	mes, typ, header, err := s.ReconstructMessageWithTimestamp()
	if err != nil {
		t.handleError("Unable to reconstruct message.", err)
		adErrors.CreateError(adErrors.UnexpectedError, "Unable to reconstruct message.", t.Key.Address).Send(t.Key, conn)
		return
	}

	// Determine how to Proceed based on the Message Type
	switch typ {

	// Handle Registration
	case wire.RegistrationCode:
		// Unmarshal the Sent Data
		assigned := &wire.TrackerRegister{}
		err := proto.Unmarshal(mes, assigned)
		if err != nil {
			t.handleError("Handle Client (Unloading Registration Payload)", err)
			adErrors.CreateError(adErrors.UnexpectedError, "Unable to unload message payload.", t.Key.Address).Send(t.Key, conn)
			return
		}

		if assigned.GetAddress() != header.From.String() {
			t.handleError("Unable to verify message integrity.", errors.New("Unable to verify message integrity."))
			adErrors.CreateError(adErrors.InvalidSignature, "Signature doesn't match registration address.", t.Key.Address).Send(t.Key, conn)
			return
		}

		t.Delegate.SaveRecord(header.From, s, assigned.GetUsername())

	// Handle Query
	case wire.QueryCode:
		// Unmarshall the Sent Data
		assigned := &wire.TrackerQuery{}
		err := proto.Unmarshal(mes, assigned)

		if err != nil {
			t.handleError("Handle Client (Unloading Query Payload)", err)
			adErrors.CreateError(adErrors.UnexpectedError, "Unable to unload message payload.", t.Key.Address).Send(t.Key, conn)
			return
		}

		t.handleQuery(header.From, assigned, conn)
	}
}

func (t *Tracker) handleQuery(theAddress *identity.Address, req *wire.TrackerQuery, conn net.Conn) {
	var info *message.SignedMessage
	if req.GetUsername() == "" {
		addr := identity.CreateAddressFromString(req.GetAddress())
		if addr == nil {
			adErrors.CreateError(adErrors.UnexpectedError, "Address is not valid.", t.Key.Address).Send(t.Key, conn)
			return
		} else {
			info = t.Delegate.GetRecordByAddress(addr)
		}
	} else {
		info = t.Delegate.GetRecordByAlias(req.GetUsername())
	}

	// Return an Error Message if we could not find the address
	if info == nil {
		adErrors.CreateError(adErrors.AddressNotFound, "Couldn't find that address.", t.Key.Address).Send(t.Key, conn)
		return
	}

	err := info.AddSignature(t.Key)
	if err != nil {
		t.handleError("Couldn't add signature.", err)
		adErrors.CreateError(adErrors.InternalError, "Couldn't sign query response.", t.Key.Address).Send(t.Key, conn)
		return
	}

	enc, err := info.UnencryptedMessage(theAddress)
	if err != nil {
		t.handleError("Create unencrypted message.", err)
		adErrors.CreateError(adErrors.InternalError, "Couldn't pack query response.", t.Key.Address).Send(t.Key, conn)
		return
	}

	err = enc.SendMessageToConnection(conn)
	if err != nil {
		t.handleError("Send unencrypted message.", err)
		adErrors.CreateError(adErrors.InternalError, "Couldn't send query response.", t.Key.Address).Send(t.Key, conn)
		return
	}
}
