package cryptopals

import (
	"sync"
	"testing"
)

func TestSimplifiedSrp(t *testing.T) {
	c := challenge38{}

	params := challenge36{}.defaultSrpParams()
	info := srpClientInfo{I: "alice", P: "password123"}

	in := make(chan interface{}, 3)
	out := make(chan interface{}, 3)

	var wg sync.WaitGroup
	wg.Add(2)

	var password string
	var err error

	dict := []string{
		"password",
		"123",
		"password123",
	}

	go func() {
		net1 := &network{in: in, out: out}
		c.Client(params, info, net1)
		wg.Done()
	}()

	go func() {
		net2 := &network{in: out, out: in}
		password, err = c.Attacker(params, dict, net2)
		wg.Done()
	}()

	wg.Wait()

	if err != nil {
		t.Fatal(err)
	}

	if info.P != password {
		t.Fatalf("Expected %v, was %v", info.P, password)
	}
}
