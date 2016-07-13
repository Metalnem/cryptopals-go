// Challenge 42 - Bleichenbacher's e=3 RSA Attack
// http://cryptopals.com/sets/6/challenges/42

package cryptopals

import (
	"crypto/subtle"
	"math/big"
)

type challenge42 struct {
}

func (challenge42) sign(key *privateKey, data []byte) *big.Int {
	b := make([]byte, key.size())
	h := sha256Digest(data)
	pos := len(b) - len(h) - 1

	b[1] = 1

	for i := 2; i < pos; i++ {
		b[i] = byte(255)
	}

	b[pos] = byte(len(h))
	copy(b[pos+1:], h)

	m := new(big.Int).SetBytes(b)

	return key.decrypt(m)
}

func (challenge42) verify(key *publicKey, data []byte, signature *big.Int) bool {
	m := key.encrypt(signature)
	b := m.Bytes()

	if b[0] != 1 {
		return false
	}

	pos := 1

	for ; b[pos] == 255; pos++ {
	}

	l := int(b[pos])
	h1 := b[pos+1 : pos+l+1]
	h2 := sha256Digest(data)

	return subtle.ConstantTimeCompare(h1, h2) == 1
}
