package cryptopals

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"testing"
)

func TestDecryptCompressed(t *testing.T) {
	c := challenge51{}

	cookie := "sessionid=TmV2ZXIgcmV2ZWFsIHRoZSBXdS1UYW5nIFNlY3JldCE="
	prefix := "sessionid="
	secret := "Never reveal the Wu-Tang Secret!"

	aesCtr := func(data []byte) []byte {
		block, _ := aes.NewCipher(randBytes(aes.BlockSize))
		ctr := cipher.NewCTR(block, randBytes(aes.BlockSize))

		var ciphertext []byte
		ciphertext = append(ciphertext, data...)
		ctr.XORKeyStream(ciphertext, ciphertext)

		return ciphertext
	}

	aesCbc := func(data []byte) []byte {
		key := randBytes(aes.BlockSize)
		return AesCbcEncrypt(data, key)
	}

	tests := []struct {
		oracle  compressionOracle
		decrypt decryptor
	}{
		{oracle: compressionOracle{cookie: cookie, prefix: prefix, encrypt: aesCtr}, decrypt: c.DecryptAesCtrCompressed},
		{oracle: compressionOracle{cookie: cookie, prefix: prefix, encrypt: aesCbc}, decrypt: c.DecryptAesCbcCompressed},
	}

	for _, test := range tests {
		plaintext := test.decrypt(test.oracle)
		cookie := string(plaintext[len(test.oracle.prefix):])
		bytes, err := base64.StdEncoding.DecodeString(cookie)

		if err != nil {
			t.Fatal(err)
		}

		actual := string(bytes)

		if actual != secret {
			t.Fatalf("Expected %v, was %v", secret, actual)
		}
	}
}
