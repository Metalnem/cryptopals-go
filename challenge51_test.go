package cryptopals

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"testing"
)

func TestDecryptAesCtrCompressed(t *testing.T) {
	c := challenge51{}
	prefix := "sessionid="

	cipher := func(data []byte) []byte {
		block, _ := aes.NewCipher(randBytes(aes.BlockSize))
		ctr := cipher.NewCTR(block, randBytes(aes.BlockSize))

		var ciphertext []byte
		ciphertext = append(ciphertext, data...)
		ctr.XORKeyStream(ciphertext, ciphertext)

		return ciphertext
	}

	oracle := compressionOracle{
		cookie: "sessionid=TmV2ZXIgcmV2ZWFsIHRoZSBXdS1UYW5nIFNlY3JldCE=",
		cipher: cipher,
	}

	expected := "Never reveal the Wu-Tang Secret!"
	plaintext := c.DecryptAesCtrCompressed(prefix, oracle)
	cookie := string(plaintext[len(prefix):])
	bytes, _ := base64.StdEncoding.DecodeString(cookie)
	actual := string(bytes)

	if actual != expected {
		t.Fatalf("Expected %v, was %v", expected, actual)
	}
}
