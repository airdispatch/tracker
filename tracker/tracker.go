package main

import (
	"airdispat.ch/identity"
	"airdispat.ch/message"
	"airdispat.ch/tracker"
	"flag"
	"fmt"
)

var port = flag.String("port", "2048", "select the port on which to run the tracking server")
var key_file = flag.String("key", "", "the file that will save or load your keys")

var storedAddresses map[string]*message.SignedMessage
var aliasedAddresses map[string]*message.SignedMessage

func main() {
	flag.Parse()

	// Initialize the Database of Addresses
	storedAddresses = make(map[string]*message.SignedMessage)
	aliasedAddresses = make(map[string]*message.SignedMessage)

	loadedKey, err := identity.LoadKeyFromFile(*key_file)

	if err != nil {

		loadedKey, err = identity.CreateIdentity()
		if err != nil {
			fmt.Println("Unable to Create Tracker Key")
			return
		}

		if *key_file != "" {

			err = loadedKey.SaveKeyToFile(*key_file)
			if err != nil {
				fmt.Println("Unable to Save Tracker Key")
				return
			}
		}

	}
	fmt.Println("Loaded Address", loadedKey.Address.String())

	theTracker := &tracker.Tracker{
		Key:      loadedKey,
		Delegate: &myTracker{},
	}
	theTracker.StartServer(*port)
}

type myTracker struct {
	tracker.BasicTracker
}

func (myTracker) SaveRecord(address *identity.Address, record *message.SignedMessage, alias string) {
	fmt.Println("Saving Address", address.String(), alias)
	// Store the RegisterdAddress in the Database
	storedAddresses[address.String()] = record

	if alias != "" {
		aliasedAddresses[alias] = record
	}
}

func (myTracker) GetRecordByAddress(address *identity.Address) *message.SignedMessage {
	fmt.Println("Getting Address", address.String())
	// Lookup the Address (by address) in the Database
	info, _ := storedAddresses[address.String()]
	return info
}

func (myTracker) GetRecordByAlias(alias string) *message.SignedMessage {
	fmt.Println("Getting Address", alias)
	// Lookup the Address (by address) in the Database
	info, _ := aliasedAddresses[alias]
	return info
}
