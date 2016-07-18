package cryptopals

import "testing"

func TestForgeRsaSignature(t *testing.T) {
	c := challenge42{}

	priv := generateRsaPrivateKey(3072)
	pub := priv.public()

	data := []byte("hi mom")
	signature := c.sign(priv, data)

	if !c.verify(pub, data, signature) {
		t.Fatal("Failed to verify original signature")
	}

	forged := c.ForgeRsaSignature(data)

	if !c.verify(pub, data, forged) {
		t.Fatal("Failed to verify forged signature")
	}
}
