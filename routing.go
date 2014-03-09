package tracker

import (
	"airdispat.ch/crypto"
	"airdispat.ch/identity"
	"airdispat.ch/message"
	"airdispat.ch/tracker/wire"
	"code.google.com/p/goprotobuf/proto"
	"errors"
	"time"
)

type TrackerRouter struct {
	URL    string
	origin *identity.Identity
}

type TrackerQueryMessage struct {
	From    *identity.Identity
	Address string
}

func (b *TrackerQueryMessage) ToBytes() []byte {
	q := &wire.TrackerQuery{
		Address: &b.Address,
	}
	bytes, err := proto.Marshal(q)
	if err != nil {
		return nil
	}
	return bytes
}
func (b *TrackerQueryMessage) Type() string { return wire.QueryCode }
func (b *TrackerQueryMessage) Header() message.Header {
	return message.Header{
		From:      b.From.Address,
		To:        nil,
		Timestamp: time.Now().Unix(),
	}
}

type TrackerRegistrationMessage struct {
	Address  string
	Location string
	Key      []byte
}

func TrackerRegistrationMessageFromBytes(b []byte) *TrackerRegistrationMessage {
	q := &wire.TrackerRegister{}
	err := proto.Unmarshal(b, q)
	if err != nil {
		return nil
	}

	return &TrackerRegistrationMessage{
		Address:  q.GetAddress(),
		Location: q.GetLocation(),
		Key:      q.GetEncryptionKey(),
	}
}

func (b *TrackerRegistrationMessage) ToBytes() []byte {
	expirationTime := uint64(time.Now().Add(time.Hour * 24 * 7).Unix())
	q := &wire.TrackerRegister{
		Address:       &b.Address,
		Location:      &b.Location,
		Expires:       &expirationTime,
		EncryptionKey: b.Key,
	}
	bytes, err := proto.Marshal(q)
	if err != nil {
		return nil
	}
	return bytes
}
func (b *TrackerRegistrationMessage) Type() string { return wire.RegistrationCode }
func (b *TrackerRegistrationMessage) Header() message.Header {
	return message.Header{
		From:      identity.CreateAddressFromString(b.Address),
		To:        nil,
		Timestamp: time.Now().Unix(),
	}
}

func (a *TrackerRouter) Lookup(addrString string) (*identity.Address, error) {
	q := &TrackerQueryMessage{a.origin, addrString}

	signed, err := message.SignMessage(q, a.origin)
	if err != nil {
		return nil, err
	}

	addr := identity.CreateAddressFromString(addrString)
	enc, err := signed.UnencryptedMessage(addr)
	if err != nil {
		return nil, err
	}

	conn, err := message.ConnectToServer(a.URL)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	err = enc.SendMessageToConnection(conn)
	if err != nil {
		return nil, err
	}

	m, err := message.ReadMessageFromConnection(conn)
	if err != nil {
		return nil, err
	}

	sin, err := m.UnencryptedMessage()
	if err != nil {
		return nil, err
	}

	if !sin.Verify() {
		return nil, errors.New("Unable to verify message.")
	}

	d, mType, _, err := sin.ReconstructMessage()
	if err != nil {
		return nil, err
	}

	if mType != wire.RegistrationCode {
		return nil, errors.New("Got the wrong response.")
	}

	reg := TrackerRegistrationMessageFromBytes(d)

	i := identity.CreateAddressFromString(reg.Address)
	i.Location = reg.Location

	rsa, err := crypto.BytesToRSA(reg.Key)
	if err != nil {
		return nil, err
	}

	i.EncryptionKey = rsa

	return i, nil
}

func (a *TrackerRouter) LookupAlias(alias string) (*identity.Address, error) {
	return nil, errors.New("Don't support aliases currently.")
}

func (a *TrackerRouter) Register(key *identity.Identity) (err error) {
	byteKey := crypto.RSAToBytes(key.Address.EncryptionKey)

	q := &TrackerRegistrationMessage{
		Address:  key.Address.String(),
		Location: key.Address.Location,
		Key:      byteKey,
	}

	signed, err := message.SignMessage(q, a.origin)
	if err != nil {
		return
	}

	enc, err := signed.UnencryptedMessage(key.Address)
	if err != nil {
		return
	}

	conn, err := message.ConnectToServer(a.URL)
	if err != nil {
		return
	}
	defer conn.Close()

	err = enc.SendMessageToConnection(conn)
	if err != nil {
		return
	}
	return
}

// SECTION FOR TRACKER LIST

type TrackerListRouter struct {
	trackers []*TrackerRouter
}

func CreateTrackerListRouter(trackers ...*TrackerRouter) *TrackerListRouter {
	output := &TrackerListRouter{}

	if trackers == nil {
		return nil
	}

	output.trackers = trackers
	return output
}

func CreateTrackerListRouterWithStrings(currentIdentity *identity.Identity, trackers ...string) *TrackerListRouter {
	output := &TrackerListRouter{}
	trackerList := make([]*TrackerRouter, len(trackers))

	for i, v := range trackers {
		trackerList[i] = &TrackerRouter{v, currentIdentity}
	}

	output.trackers = trackerList
	return output
}

func (a *TrackerListRouter) Lookup(addr string) (*identity.Address, error) {
	data := make(chan *identity.Address)
	errChan := make(chan error)
	timeout := make(chan bool)

	go func() {
		time.Sleep(30 * time.Second)
		timeout <- true
	}()

	queryFunction := func(c chan *identity.Address, t *TrackerRouter) {
		response, err := t.Lookup(addr)
		if err != nil {
			errChan <- err
			return
		}

		c <- response
	}

	for _, tracker := range a.trackers {
		go queryFunction(data, tracker)
	}

	errorCount := 0

	for errorCount < len(a.trackers) {
		select {
		case d := <-data:
			return d, nil
		case <-errChan:
			errorCount++
		case <-timeout:
			return nil, errors.New("All trackers timed out.")
		}
	}
	return nil, errors.New("Unable to find address in trackers.")
}

// This is non-deterministic... Yes. That isn't the correct word. Sorry.
func (a *TrackerListRouter) Register(key *identity.Identity) error {
	for _, tracker := range a.trackers {
		go tracker.Register(key)
	}
	return nil
}
