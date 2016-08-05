package cryptopals

import (
	"encoding/hex"
	"testing"
)

func TestForgeCbcMacHash(t *testing.T) {
	key := []byte("YELLOW SUBMARINE")

	m1 := []byte("alert('MZA who was that?');\n")
	h1 := hex.EncodeToString(CbcMacHash(m1, key))

	if h1 != "296b8d7cb78a243dda4d0a61d33bbdd1" {
		t.Fatal("Failed to calculcate correct CBC-MAC hash")
	}
}
