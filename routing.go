package tracker

import (
	"errors"
	"fmt"
	"net"

	"airdispat.ch/crypto"
	adErrors "airdispat.ch/errors"
	"airdispat.ch/identity"
	"airdispat.ch/message"
	"airdispat.ch/tracker/wire"
	w "airdispat.ch/wire"
)

// GetTrackingServerLocationFromURL will attempt to get information about a tracking server
// from a DNS SRV Record.
func GetTrackingServerLocationFromURL(url string) string {
	_, recs, err := net.LookupSRV("adtp", "tcp", url)
	if err != nil {
		return url
	}
	for _, s := range recs {
		return fmt.Sprintf("%s:%d", s.Target, s.Port)
	}
	return url
}

// Router implements the AirDispatch routing.Router interface for the
// tracker system.
type Router struct {
	URL    string
	Origin *identity.Identity
}

// Lookup will perform a Router lookup on an address, and return a
// new (*identity).Address.
func (a *Router) Lookup(addrString string) (*identity.Address, error) {
	return a.lookup(addrString, "")
}

// LookupAlias will perform a Router lookup on a certain alias, and return a
// new (*identity).Address.
func (a *Router) LookupAlias(alias string) (*identity.Address, error) {
	return a.lookup("", alias)
}

func (a *Router) lookup(addrString string, alias string) (*identity.Address, error) {
	q := &QueryMessage{
		From:    a.Origin,
		Address: addrString,
		Alias:   alias,
	}

	signed, err := message.SignMessage(q, a.Origin)
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

	d, mType, h, err := sin.ReconstructMessageWithoutTimestamp()
	if err != nil {
		return nil, err
	}

	if mType == w.ErrorCode {
		// Something occured on the other side.
		return nil, adErrors.CreateErrorFromBytes(d, h)
	} else if mType != wire.RegistrationCode {
		return nil, errors.New("Got the wrong response.")
	}

	reg := RegistrationMessageFromBytes(d)

	i := identity.CreateAddressFromString(reg.Address)
	i.Location = reg.Location

	rsa, err := crypto.BytesToRSA(reg.Key)
	if err != nil {
		return nil, err
	}

	i.EncryptionKey = rsa

	return i, nil
}

// Register will register an identity (and alias) with a tracker.
func (a *Router) Register(key *identity.Identity, alias string) (err error) {
	byteKey := crypto.RSAToBytes(key.Address.EncryptionKey)

	q := &RegistrationMessage{
		Address:  key.Address.String(),
		Location: key.Address.Location,
		Alias:    alias,
		Key:      byteKey,
	}

	signed, err := message.SignMessage(q, key)
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

	err = adErrors.CheckConnectionForError(conn)
	return
}
