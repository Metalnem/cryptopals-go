// Challenge 35 - Implement DH with negotiated groups, and break with malicious "g" parameters
// http://cryptopals.com/sets/5/challenges/35

package cryptopals

import (
	"crypto/rand"
	"math/big"
)

type challenge35 struct {
}

func (x challenge35) Client(message []byte, net Network) {
	params := challenge33{}.defaultDhParams()
	p, g := params.p, params.g

	net.Write(p)
	net.Write(g)
	net.Read()

	a, _ := rand.Int(rand.Reader, p)
	A := new(big.Int).Exp(g, a, p)
	net.Write(A)

	B := readInt(net)
	s := new(big.Int).Exp(B, a, p)

	key := challenge34{}.generateKey(s)
	ciphertext := AesCbcEncrypt(message, key)

	net.Write(ciphertext)
	net.Read()
}

func (x challenge35) Server(net Network) {
	p := readInt(net)
	g := readInt(net)
	net.Write(struct{}{})

	A := readInt(net)
	b, _ := rand.Int(rand.Reader, p)
	B := new(big.Int).Exp(g, b, p)
	net.Write(B)

	s := new(big.Int)
	s.Exp(A, b, p)

	key := challenge34{}.generateKey(s)
	message := AesCbcDecrypt(readBytes(net), key)
	ciphertext := AesCbcEncrypt(message, key)

	net.Write(ciphertext)
}
