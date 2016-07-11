// Challenge 41 - Implement unpadded message recovery oracle
// http://cryptopals.com/sets/6/challenges/41

package cryptopals

import (
	"crypto/rand"
	"math/big"
)

type challenge41 struct {
}

func (challenge41) Client(key *publicKey, net Network) string {
	c := readInt(net)

	S, _ := rand.Int(rand.Reader, key.n)
	C := new(big.Int).Exp(S, key.e, key.n)
	C = C.Mul(C, c).Mod(C, key.n)

	net.Write(C)

	p := readInt(net)
	P := new(big.Int).ModInverse(p, key.n)
	P = P.Mul(P, p).Mod(P, key.n)

	return string(P.Bytes())
}

func (challenge41) Server(message string, key *privateKey, net Network) {
	p := new(big.Int).SetBytes([]byte(message))
	c := key.publicKey().encrypt(p)

	net.Write(c)

	C := readInt(net)
	P := key.decrypt(C)

	net.Write(P)
}
