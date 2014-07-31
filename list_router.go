package tracker

import (
	"errors"
	"time"

	"airdispat.ch/identity"
	"airdispat.ch/routing"
)

// ListRouter implements the AirDispatch routing.Router interface for a
// group of Trackers.
type ListRouter struct {
	trackers []routing.Router
}

// CreateListRouter will return a ListRouter for a slice of currently functioning
// routers.
func CreateListRouter(redirect RedirectHandler, trackers ...routing.Router) *ListRouter {
	output := &ListRouter{}

	if trackers == nil {
		return nil
	}

	output.trackers = trackers
	return output
}

// CreateListRouterWithStrings will return a ListRouter with an identity and
// list of tracker URLS.
func CreateListRouterWithStrings(redirect RedirectHandler, currentIdentity *identity.Identity, trackers ...string) *ListRouter {
	output := &ListRouter{}
	trackerList := make([]routing.Router, len(trackers))

	for i, v := range trackers {
		trackerList[i] = &Router{
			URL:        v,
			Origin:     currentIdentity,
			Redirector: redirect,
		}
	}

	output.trackers = trackerList
	return output
}

type queryFunc func(routing.Router) (*identity.Address, error)

func (a *ListRouter) lookup(query queryFunc) (*identity.Address, error) {
	data := make(chan *identity.Address)
	errChan := make(chan error)
	timeout := make(chan bool)

	go func() {
		time.Sleep(30 * time.Second)
		timeout <- true
	}()

	queryFunction := func(c chan *identity.Address, t routing.Router) {
		response, err := query(t)
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

// Lookup will return a new identity.Address for an address fingerprint.
func (a *ListRouter) Lookup(addr string, name routing.LookupType) (*identity.Address, error) {
	return a.lookup(func(r routing.Router) (*identity.Address, error) {
		return r.Lookup(addr, name)
	})
}

// LookupAlias will return a new identity.Address for an alias.
func (a *ListRouter) LookupAlias(alias string, name routing.LookupType) (*identity.Address, error) {
	return a.lookup(func(r routing.Router) (*identity.Address, error) {
		return r.LookupAlias(alias, name)
	})
}

// Register will register an address with a list of trackers.
func (a *ListRouter) Register(key *identity.Identity, alias string, redirects map[string]routing.Redirect) error {
	for _, tracker := range a.trackers {
		go tracker.Register(key, alias, redirects)
	}
	return nil
}
