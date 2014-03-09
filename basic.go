package tracker

import (
	"airdispat.ch/identity"
	"fmt"
)

type BasicTracker struct {
	TrackerDelegate
}

func (BasicTracker) HandleError(err *TrackerError) {
	fmt.Println("Error Occurred At: " + err.Location + " - " + err.Error.Error())
	// os.Exit(1)
}

func (BasicTracker) AllowConnection(fromAddr *identity.Address) bool {
	return true
}

func (BasicTracker) LogMessage(toLog string) {
	fmt.Println(toLog)
}
