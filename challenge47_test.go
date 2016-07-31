package cryptopals

import (
	"crypto/rand"
	"crypto/rsa"
	"testing"
)

func TestDecryptRsaPaddingOracleSimple(t *testing.T) {
	c := challenge47{}

	priv, _ := rsa.GenerateKey(rand.Reader, 1024)
	pub := priv.PublicKey

	expected := "Chosen Ciphertext Attacks Against Protocols Based on the RSA Encryption Standard PKCS #1"
	ciphertext, err := rsa.EncryptPKCS1v15(rand.Reader, &pub, []byte(expected))

	if err != nil {
		t.Fatal(err)
	}

	oracle := func(ciphertext []byte) bool {
		_, err := rsa.DecryptPKCS1v15(rand.Reader, priv, ciphertext)
		return err == nil
	}

	actual := string(c.DecryptRsaPaddingOracleSimple(&pub, ciphertext, oracle))

	if actual != expected {
		t.Fatalf("Expected %v, was %v", expected, actual)
	}
}
