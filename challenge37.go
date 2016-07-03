// Challenge 37 - Break SRP with a zero key
// http://cryptopals.com/sets/5/challenges/37

package cryptopals

import "math/big"

type challenge37 struct {
}

func (challenge37) Client(net Network) bool {
	A := big.NewInt(0)
	net.Write(A)

	s := readBytes(net)
	net.Read()

	S := A
	K := sha256Digest(S.Bytes())

	mac := hmacSHA256(K, s)
	net.Write(mac)

	return net.Read().(bool)
}

func (challenge37) Server(params srpParams, info srpClientInfo, net Network) bool {
	return challenge36{}.Server(params, info, net)
}
