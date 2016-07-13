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
	CS := readInt(net)

	S, _ := rand.Int(rand.Reader, key.n)
	CC := new(big.Int).Exp(S, key.e, key.n)
	CC = CC.Mul(CS, CC).Mod(CC, key.n)

	net.Write(CC)

	PS := readInt(net)
	PC := new(big.Int).ModInverse(S, key.n)
	PC = PC.Mul(PS, PC).Mod(PC, key.n)

	return string(PC.Bytes())
}

func (challenge41) Server(message string, key *privateKey, net Network) {
	m := new(big.Int).SetBytes([]byte(message))
	c := key.encrypt(m)

	net.Write(c)

	C := readInt(net)
	M := key.decrypt(C)

	net.Write(M)
}
