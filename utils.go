package cryptopals

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"math/big"
)

func randBytes(size int) []byte {
	b := make([]byte, size)

	if _, err := rand.Read(b); err != nil {
		panic("Random number generator failed")
	}

	return b
}

func randPrime(size bitSize) *big.Int {
	p, err := rand.Prime(rand.Reader, int(size))

	if err != nil {
		panic("Random number generator failed")
	}

	return p
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

func cbrt(n *big.Int) *big.Int {
	two := big.NewInt(2)
	three := big.NewInt(3)
	root := n

	for pow := new(big.Int); pow.Exp(root, three, nil).Cmp(n) > 0; {
		x := new(big.Int).Mul(root, two)
		y := new(big.Int).Exp(root, two, nil)
		z := new(big.Int).Div(n, y)
		t := new(big.Int).Add(x, z)
		root = new(big.Int).Div(t, three)
	}

	return root
}
