package cryptopals

import (
	"sync"
	"testing"
)

func TestNegotiatedGroupsAttack(t *testing.T) {
	c := challenge35{}

	inClient := make(chan interface{}, 2)
	outClient := make(chan interface{}, 2)

	inServer := make(chan interface{}, 2)
	outServer := make(chan interface{}, 2)

	var wg sync.WaitGroup
	wg.Add(3)

	message := "Cooking MC's like a pound of bacon"
	var clientMessage []byte

	go func() {
		netClient := &network{in: inClient, out: outClient}
		c.Client([]byte(message), netClient)
		wg.Done()
	}()

	go func() {
		netServer := &network{in: inServer, out: outServer}
		c.Server(netServer)
		wg.Done()
	}()

	go func() {
		netClient := &network{in: outClient, out: inClient}
		netServer := &network{in: outServer, out: inServer}
		clientMessage = c.Attacker(netClient, netServer)
		wg.Done()
	}()

	wg.Wait()

	clientString := string(clientMessage)

	if message != clientString {
		t.Fatalf("Expected %v, was %v", message, clientString)
	}
}
