package cryptopals

import (
	"crypto/rand"
	"crypto/rsa"
	"testing"
)

func TestDecryptRsaPaddingOracleSimple(t *testing.T) {
	t.Skip("Skip this test, because it runs too long")

	priv, _ := rsa.GenerateKey(rand.Reader, 768)
	pub := priv.PublicKey

	expected := "kick it, CC"
	ciphertext, err := rsa.EncryptPKCS1v15(rand.Reader, &pub, []byte(expected))

	if err != nil {
		t.Fatal(err)
	}

	oracle := func(ciphertext []byte) bool {
		_, err := rsa.DecryptPKCS1v15(rand.Reader, priv, ciphertext)
		return err == nil
	}

	actual := string(challenge47{}.DecryptRsaPaddingOracleSimple(&pub, ciphertext, oracle))

	if actual != expected {
		t.Fatalf("Expected %v, was %v", expected, actual)
	}
}
