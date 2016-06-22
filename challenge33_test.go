package cryptopals

import (
	"math/big"
	"reflect"
	"sync"
	"testing"
)

func TestDiffieHellman(t *testing.T) {
	c := challenge33{}

	in := make(chan *big.Int, 1)
	out := make(chan *big.Int, 1)

	var wg sync.WaitGroup
	wg.Add(2)

	var key1, key2 []byte

	go func() {
		net1 := &network{in: in, out: out}
		key1 = c.DiffieHellman(net1)
		wg.Done()
	}()

	go func() {
		net2 := &network{in: out, out: in}
		key2 = c.DiffieHellman(net2)
		wg.Done()
	}()

	wg.Wait()

	if !reflect.DeepEqual(key1, key2) {
		t.Errorf("Expected %v, was %v", key1, key2)
	}
}
