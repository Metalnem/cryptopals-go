package cryptopals

import (
	"sync"
	"testing"
)

func TestSrp(t *testing.T) {
	c := challenge36{}

	params := c.defaultSrpParams()
	info := srpClientInfo{I: "alice", P: "password123"}

	in := make(chan interface{}, 2)
	out := make(chan interface{}, 2)

	var wg sync.WaitGroup
	wg.Add(2)

	var ok1, ok2 bool

	go func() {
		net1 := &network{in: in, out: out}
		ok1 = c.Client(params, info, net1)
		wg.Done()
	}()

	go func() {
		net2 := &network{in: out, out: in}
		ok2 = c.Server(params, info, net2)
		wg.Done()
	}()

	wg.Wait()

	if !ok1 || !ok2 {
		t.Fatalf("Protocol violation error")
	}
}
