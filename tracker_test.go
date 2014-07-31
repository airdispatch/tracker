package tracker

import (
	"testing"
	"time"

	"airdispat.ch/identity"
	"airdispat.ch/message"
	"airdispat.ch/routing"
)

func TestTracker(t *testing.T) {
	trackerKey, err := identity.CreateIdentity()
	if err != nil {
		t.Error(err)
	}

	testTracker := &testingTracker{
		addressedStorage: make(map[string]*message.SignedMessage),
		aliasedStorage:   make(map[string]*message.SignedMessage),
	}

	tracker := &Tracker{
		Key:      trackerKey,
		Delegate: testTracker,
	}

	go func() {
		err = tracker.StartServer("9090")
		if err != nil {
			t.Error(err)
		}
	}()

	// Wait for Server to Startup
	time.Sleep(1 * time.Second)

	toLog, err := identity.CreateIdentity()
	toLog.SetLocation("google.com")
	if err != nil {
		t.Error(err)
	}

	router := &Router{
		URL:    "localhost:9090",
		Origin: toLog,
	}

	err = router.Register(toLog, "hunter", nil)
	if err != nil {
		t.Error(err)
	}

	addr := identity.CreateAddressFromString(toLog.Address.String())
	idAddr, err := router.Lookup(addr.String(), routing.LookupTypeDEFAULT)
	if err != nil {
		t.Error(err)
	}

	if idAddr.String() != addr.String() {
		t.Error("Returned address is not the same as registered address.")
	}

	if idAddr.Location != toLog.Address.Location {
		t.Error("Returned Location is not the same.")
	}

	idAddr, err = router.LookupAlias("hunter", routing.LookupTypeDEFAULT)
	if err != nil {
		t.Error(err)
	}

	if idAddr.String() != addr.String() {
		t.Error("Returned address is not the same as registered address.")
	}

	if idAddr.Location != toLog.Address.Location {
		t.Error("Returned Location is not the same.")
	}
}

// Simple Fake Tracker
type testingTracker struct {
	BasicTracker
	addressedStorage map[string]*message.SignedMessage
	aliasedStorage   map[string]*message.SignedMessage
}

func (t testingTracker) SaveRecord(address *identity.Address, record *message.SignedMessage, alias string) {
	t.addressedStorage[address.String()] = record
	if alias != "" {
		t.aliasedStorage[alias] = record
	}
}

func (t testingTracker) GetRecordByAddress(address *identity.Address) *message.SignedMessage {
	info, _ := t.addressedStorage[address.String()]
	return info
}

func (t testingTracker) GetRecordByAlias(alias string) *message.SignedMessage {
	info, _ := t.aliasedStorage[alias]
	return info
}
