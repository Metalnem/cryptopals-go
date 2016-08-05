package cryptopals

import (
	"encoding/hex"
	"testing"
)

func TestForgeCbcMacHash(t *testing.T) {
	key := []byte("YELLOW SUBMARINE")
	message := []byte("alert('MZA who was that?');\n")
	hash := hex.EncodeToString(CbcMacHash(message, key))

	if hash != "296b8d7cb78a243dda4d0a61d33bbdd1" {
		t.Fatal("Failed to calculate correct CBC-MAC hash")
	}

	target := []byte("alert('Ayo, the Wu is back!')//'")
	forged := challenge50{}.ForgeCbcMacHash(message, key, target)

	actual := hash
	expected := hex.EncodeToString(CbcMacHash(forged, key))

	if actual != expected {
		t.Fatalf("Expected %v, was %v", expected, actual)
	}
}
