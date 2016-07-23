// Challenge 34 - Implement a MITM key-fixing attack on Diffie-Hellman with parameter injection
// http://cryptopals.com/sets/5/challenges/34

package cryptopals

import (
	"crypto/aes"
	"crypto/rand"
	"math/big"
)

type challenge34 struct {
}

func (challenge34) generateKey(s *big.Int) []byte {
	return sha1Digest(s.Bytes())[0:aes.BlockSize]
}

func (x challenge34) Client(message []byte, net Network) {
	params := challenge33{}.defaultDhParams()
	p, g := params.p, params.g

	a, _ := rand.Int(rand.Reader, p)
	A := new(big.Int)
	A.Exp(g, a, p)

	net.Write(p)
	net.Write(g)
	net.Write(A)

	B := readInt(net)

	s := new(big.Int)
	s.Exp(B, a, p)

	key := x.generateKey(s)
	ciphertext := AesCbcEncrypt(message, key)

	net.Write(ciphertext)
	net.Read()
}

func (x challenge34) Server(net Network) {
	p := readInt(net)
	g := readInt(net)
	A := readInt(net)

	b, _ := rand.Int(rand.Reader, p)
	B := new(big.Int)
	B.Exp(g, b, p)

	net.Write(B)

	s := new(big.Int)
	s.Exp(A, b, p)

	key := x.generateKey(s)
	message := AesCbcDecrypt(readBytes(net), key)
	ciphertext := AesCbcEncrypt(message, key)

	net.Write(ciphertext)
}

func (x challenge34) Attacker(client, server Network) ([]byte, []byte) {
	p := readInt(client)
	g := readInt(client)
	client.Read()

	server.Write(p)
	server.Write(g)
	server.Write(p)

	server.Read()
	client.Write(p)

	clientCiphertext := readBytes(client)
	server.Write(clientCiphertext)

	serverCiphertext := readBytes(server)
	client.Write(serverCiphertext)

	s := new(big.Int)
	key := x.generateKey(s)

	clientMessage := AesCbcDecrypt(clientCiphertext, key)
	serverMessage := AesCbcDecrypt(serverCiphertext, key)

	return clientMessage, serverMessage
}
