package cryptopals

import "testing"

func TestBadDsaParameters(t *testing.T) {
	c := challenge45{}

	params := c.badDsaParameters()
	priv := generateDsaPrivateKey(params)
	pub := priv.public()

	m1 := []byte("Hello, world")
	m2 := []byte("Goodbye, world")

	sig1 := priv.sign(m1)
	sig2 := priv.sign(m2)

	if !pub.verify(m1, sig2) || !pub.verify(m2, sig1) {
		t.Fatal("Failed to verify the signature")
	}
}
