package tracker

import (
	"time"

	"airdispat.ch/identity"
	"airdispat.ch/message"
	"airdispat.ch/routing"
	"airdispat.ch/tracker/wire"
	"code.google.com/p/goprotobuf/proto"
)

// QueryMessage is a struct that represents the protocol buffers representation
// of querying a tracker.
type QueryMessage struct {
	From    *identity.Identity
	Address string
	Alias   string
}

// ToBytes will serialize a QueryMessage to be sent over the wire.
func (b *QueryMessage) ToBytes() []byte {
	q := &wire.TrackerQuery{
		Address:  &b.Address,
		Username: &b.Alias,
	}
	bytes, err := proto.Marshal(q)
	if err != nil {
		return nil
	}
	return bytes
}

// Type will return the QueryCode type for this message.
func (b *QueryMessage) Type() string { return wire.QueryCode }

// Header will return the message header.
func (b *QueryMessage) Header() message.Header {
	return message.Header{
		From:      b.From.Address,
		To:        nil,
		Timestamp: time.Now().Unix(),
	}
}

// RegistrationMessage is the record that is sent to the Tracker to allow
// setting up a new record.
type RegistrationMessage struct {
	Address  string
	Location string
	Alias    string
	Redirect map[string]routing.Redirect
	Key      []byte
}

// RegistrationMessageFromBytes will deserialize a registration message into
// an easy to use struct.
func RegistrationMessageFromBytes(b []byte) *RegistrationMessage {
	q := &wire.TrackerRegister{}
	err := proto.Unmarshal(b, q)
	if err != nil {
		return nil
	}

	redirect := make(map[string]routing.Redirect)
	for _, v := range q.GetRedirect() {
		redirect[v.GetTypes()] = routing.Redirect{
			Type:        routing.LookupType(v.GetTypes()),
			Fingerprint: v.GetAddress(),
			Alias:       v.GetAlias(),
		}
	}

	return &RegistrationMessage{
		Address:  q.GetAddress(),
		Location: q.GetLocation(),
		Key:      q.GetEncryptionKey(),
		Alias:    q.GetUsername(),
		Redirect: redirect,
	}
}

// ToBytes will serialize a RegistrationMessage to be sent over the wire.
func (b *RegistrationMessage) ToBytes() []byte {
	expirationTime := uint64(time.Now().Add(time.Hour * 24 * 7).Unix())
	q := &wire.TrackerRegister{
		Address:       &b.Address,
		Location:      &b.Location,
		Username:      &b.Alias,
		Expires:       &expirationTime,
		EncryptionKey: b.Key,
	}

	var redirects []*wire.Redirect
	for _, v := range b.Redirect {
		stringType := string(v.Type)
		redirects = append(redirects, &wire.Redirect{
			Types:   &stringType,
			Alias:   &v.Alias,
			Address: &v.Fingerprint,
		})
	}
	bytes, err := proto.Marshal(q)
	if err != nil {
		return nil
	}
	return bytes
}

// Type will return the type of the message - in this case, RegistrationCode.
func (b *RegistrationMessage) Type() string { return wire.RegistrationCode }

// Header will return the RegistrationMessage header.
func (b *RegistrationMessage) Header() message.Header {
	return message.Header{
		From:      identity.CreateAddressFromString(b.Address),
		To:        nil,
		Timestamp: time.Now().Unix(),
	}
}
