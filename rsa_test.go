package cryptopals

import (
	"math/big"
	"testing"
)

func TestRsa(t *testing.T) {
	priv := generateRsaPrivateKey(4096)
	pub := priv.publicKey()

	m1 := "Modular multiplicative inverse"
	enc := pub.encrypt(new(big.Int).SetBytes([]byte(m1)))
	dec := priv.decrypt(enc)
	m2 := string(dec.Bytes())

	if m1 != m2 {
		t.Fatalf("Expected %v, was %v", m1, m2)
	}
}
