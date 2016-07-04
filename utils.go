package cryptopals

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
)

func randBytes(size int) []byte {
	b := make([]byte, size)

	if _, err := rand.Read(b); err != nil {
		panic("Random number generator failed")
	}

	return b
}

func sha256Digest(b ...[]byte) []byte {
	h := sha256.New()

	for _, x := range b {
		h.Write(x)
	}

	return h.Sum(nil)
}

func hmacSHA256(key, message []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(message)

	return h.Sum(nil)
}
