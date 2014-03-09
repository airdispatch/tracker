package tracker

import (
	"airdispat.ch/identity"
	"airdispat.ch/message"
	"testing"
	"time"
)

func TestTracker(t *testing.T) {
	trackerKey, err := identity.CreateIdentity()
	if err != nil {
		t.Error(err)
	}

	testTracker := &testingTracker{
		storage: make(map[string]*message.SignedMessage),
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

	router := &TrackerRouter{
		URL:    "localhost:9090",
		origin: toLog,
	}

	err = router.Register(toLog)
	if err != nil {
		t.Error(err)
	}

	addr := identity.CreateAddressFromString(toLog.Address.String())
	idAddr, err := router.Lookup(addr.String())
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
	storage map[string]*message.SignedMessage
}

func (t testingTracker) SaveRecord(address *identity.Address, record *message.SignedMessage) {
	t.storage[address.String()] = record
}

func (t testingTracker) GetRecordByAddress(address *identity.Address) *message.SignedMessage {
	info, _ := t.storage[address.String()]
	return info
}
