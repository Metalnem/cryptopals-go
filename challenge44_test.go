package cryptopals

import (
	"encoding/hex"
	"math/big"
	"testing"
)

func TestRecoverDsaKeyFromRepeatedNonce(t *testing.T) {
	c := challenge44{}
	y := new(big.Int)

	y.SetString("2d026f4bf30195ede3a088da85e398ef869611d0f68f07"+
		"13d51c9c1a3a26c95105d915e2d8cdf26d056b86b8a7b8"+
		"5519b1c23cc3ecdc6062650462e3063bd179c2a6581519"+
		"f674a61f1d89a1fff27171ebc1b93d4dc57bceb7ae2430"+
		"f98a6a4d83d8279ee65d71c1203d2c96d65ebbf7cce9d3"+
		"2971c3de5084cce04a2e147821", 16)

	pub := &dsaPublicKey{dsaParameters: defaultDsaParameters(), y: y}
	priv, err := c.RecoverDsaKeyFromRepeatedNonce(pub)

	if err != nil {
		t.Fatal(err)
	}

	actual := hex.EncodeToString(sha1Digest([]byte(priv.x.Text(16))))
	expected := "ca8f6f7c66fa362d40760d135b763eb8527d3d52"

	if actual != expected {
		t.Fatalf("Expected %v, was %v", expected, actual)
	}
}
