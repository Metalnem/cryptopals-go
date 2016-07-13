package cryptopals

import (
	"sync"
	"testing"
)

func TestUnpaddedMessageRecoveryOracle(t *testing.T) {
	c := challenge41{}

	m1 := "I've got the moves like Jagger"
	priv := generateRsaPrivateKey(2048)
	pub := priv.public()

	in := make(chan interface{}, 1)
	out := make(chan interface{}, 1)

	var wg sync.WaitGroup
	wg.Add(2)

	var m2 string

	go func() {
		net1 := &network{in: in, out: out}
		m2 = c.Client(pub, net1)
		wg.Done()
	}()

	go func() {
		net2 := &network{in: out, out: in}
		c.Server(m1, priv, net2)
		wg.Done()
	}()

	wg.Wait()

	if m1 != m2 {
		t.Fatalf("Expected %v, was %v", m1, m2)
	}
}
