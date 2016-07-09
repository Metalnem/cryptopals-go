package cryptopals

import (
	"math/big"
	"testing"
)

func TestRsa(t *testing.T) {
	c := challenge39{}
	priv := generateRsaPrivateKey(4096)
	pub := priv.publicKey()

	m1 := "Modular multiplicative inverse"
	enc := c.RsaEncrypt(pub, new(big.Int).SetBytes([]byte(m1)))
	dec := c.RsaDecrypt(priv, enc)
	m2 := string(dec.Bytes())

	if m1 != m2 {
		t.Fatalf("Expected %v, was %v", m1, m2)
	}
}
