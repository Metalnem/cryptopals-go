package cryptopals

import (
	"sync"
	"testing"
)

func TestAttackerKeyFixing(t *testing.T) {
	c := challenge34{}

	inClient := make(chan interface{}, 3)
	outClient := make(chan interface{}, 3)

	inServer := make(chan interface{}, 3)
	outServer := make(chan interface{}, 3)

	var wg sync.WaitGroup
	wg.Add(3)

	message := "Cooking MC's like a pound of bacon"
	var clientMessage, serverMessage []byte

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
		clientMessage, serverMessage = c.AttackerKeyFixing(netClient, netServer)
		wg.Done()
	}()

	wg.Wait()

	clientString := string(clientMessage)

	if message != clientString {
		t.Fatalf("Expected %v, was %v", message, clientString)
	}

	serverString := string(serverMessage)

	if message != serverString {
		t.Fatalf("Expected %v, was %v", message, serverString)
	}
}
