package cryptopals

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"hash"
	"math/big"
)

func randBytes(size int) []byte {
	b := make([]byte, size)

	if _, err := rand.Read(b); err != nil {
		panic("Random number generator failed")
	}

	return b
}

func randInt(max *big.Int) *big.Int {
	n, err := rand.Int(rand.Reader, max)

	if err != nil {
		panic("Random number generator failed")
	}

	return n
}

func randPrime(size bitSize) *big.Int {
	p, err := rand.Prime(rand.Reader, int(size))

	if err != nil {
		panic("Random number generator failed")
	}

	return p
}

func sha1Digest(b ...[]byte) []byte {
	return hashDigest(sha1.New, b...)
}

func sha256Digest(b ...[]byte) []byte {
	return hashDigest(sha256.New, b...)
}

func hashDigest(f func() hash.Hash, b ...[]byte) []byte {
	h := f()

	for _, x := range b {
		h.Write(x)
	}

	return h.Sum(nil)
}

func hmacSHA1(key, message []byte) []byte {
	return hmacHash(sha1.New, key, message)
}

func hmacSHA256(key, message []byte) []byte {
	return hmacHash(sha256.New, key, message)
}

func hmacHash(f func() hash.Hash, key, message []byte) []byte {
	h := hmac.New(f, key)
	h.Write(message)

	return h.Sum(nil)
}

func xor(b1, b2 []byte) []byte {
	l1 := len(b1)
	l2 := len(b2)
	l := l1

	if l1 > l2 {
		l = l2
	}

	b := make([]byte, l)

	for i := 0; i < l; i++ {
		b[i] = b1[i] ^ b2[i]
	}

	return b
}
