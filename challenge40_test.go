package cryptopals

import (
	"math/big"
	"testing"
)

func TestRsaBroadcastAttack(t *testing.T) {
	c := challenge40{}
	m1 := "Chinese Remainder Theorem"
	mx := new(big.Int).SetBytes([]byte(m1))

	priv0 := generateRsaPrivateKey(2048)
	priv1 := generateRsaPrivateKey(2048)
	priv2 := generateRsaPrivateKey(2048)

	pub0 := priv0.publicKey()
	pub1 := priv1.publicKey()
	pub2 := priv2.publicKey()

	c0 := pub0.encrypt(mx)
	c1 := pub1.encrypt(mx)
	c2 := pub2.encrypt(mx)

	dec := c.RsaBroadcastAttack(pub0, pub1, pub2, c0, c1, c2)
	m2 := string(dec.Bytes())

	if m1 != m2 {
		t.Fatalf("Expected %v, was %v", m1, m2)
	}
}
