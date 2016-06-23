// Challenge 34 - Implement a MITM key-fixing attack on Diffie-Hellman with parameter injection
// http://cryptopals.com/sets/5/challenges/34

package cryptopals

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha1"
	"math/big"

	"github.com/d1str0/pkcs7"
)

type challenge34 struct {
}

func (challenge34) readInt(net Network) *big.Int {
	return net.Read().(*big.Int)
}

func (challenge34) readBytes(net Network) []byte {
	return net.Read().([]byte)
}

func (challenge34) generateKey(s *big.Int) []byte {
	h := sha1.New()
	h.Write(s.Bytes())

	return h.Sum(nil)[0:aes.BlockSize]
}

func (challenge34) generateIv() []byte {
	iv := make([]byte, aes.BlockSize)
	rand.Read(iv)

	return iv
}

func (x challenge34) encrypt(message, key []byte) []byte {
	iv := x.generateIv()
	padded, _ := pkcs7.Pad(message, aes.BlockSize)
	ciphertext := make([]byte, len(iv)+len(message))

	block, _ := aes.NewCipher(key)
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext[aes.BlockSize:], padded)

	return ciphertext
}

func (x challenge34) decrypt(ciphertext, key []byte) []byte {
	iv := ciphertext[0:aes.BlockSize]
	message := make([]byte, len(ciphertext)-len(iv))

	block, _ := aes.NewCipher(key)
	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(message, ciphertext[aes.BlockSize:])

	return message
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

	B := x.readInt(net)

	s := new(big.Int)
	s.Exp(B, a, p)

	key := x.generateKey(s)
	ciphertext := x.encrypt(message, key)

	net.Write(ciphertext)
	net.Read()
}

func (x challenge34) Server(net Network) {
	p := x.readInt(net)
	g := x.readInt(net)
	A := x.readInt(net)

	b, _ := rand.Int(rand.Reader, p)
	B := new(big.Int)
	B.Exp(g, b, p)

	net.Write(B)

	s := new(big.Int)
	s.Exp(A, b, p)

	key := x.generateKey(s)
	message := x.decrypt(x.readBytes(net), key)
	ciphertext := x.encrypt(message, key)

	net.Write(ciphertext)
}

func (x challenge34) Attacker(client, server Network) ([]byte, []byte) {
	p := x.readInt(client)
	g := x.readInt(client)
	client.Read()

	server.Write(p)
	server.Write(g)
	server.Write(p)

	server.Read()
	client.Write(p)

	clientCiphertext := x.readBytes(client)
	server.Write(clientCiphertext)

	serverCiphertext := x.readBytes(server)
	client.Write(serverCiphertext)

	key := make([]byte, aes.BlockSize)

	clientMessage := x.decrypt(clientCiphertext, key)
	serverMessage := x.decrypt(serverCiphertext, key)

	return clientMessage, serverMessage
}
