// Challenge 38 - Offline dictionary attack on simplified SRP
// http://cryptopals.com/sets/5/challenges/38

package cryptopals

import (
	"crypto/hmac"
	"crypto/rand"
	"math/big"
)

type challenge38 struct {
}

func (challenge38) Client(params srpParams, info srpClientInfo, net Network) bool {
	a, _ := rand.Int(rand.Reader, params.N)
	A := new(big.Int).Exp(params.g, a, params.N)

	net.Write(A)

	s := readBytes(net)
	B := readInt(net)
	u := readInt(net)

	xH := sha256Digest(append(s, []byte(info.P)...))
	x := new(big.Int).SetBytes(xH)

	S := new(big.Int).Mul(u, x)
	S = S.Add(a, S)
	S = S.Exp(B, S, params.N)

	K := sha256Digest(S.Bytes())
	mac := hmacSHA256(K, s)
	net.Write(mac)

	return net.Read().(bool)
}

func (challenge38) Server(params srpParams, info srpClientInfo, net Network) bool {
	s := randBytes(16)
	xH := sha256Digest(append(s, []byte(info.P)...))

	x := new(big.Int).SetBytes(xH)
	v := new(big.Int).Exp(params.g, x, params.N)

	b, _ := rand.Int(rand.Reader, params.N)
	B := new(big.Int).Exp(params.g, b, params.N)

	uB := randBytes(16)
	u := new(big.Int).SetBytes(uB)

	net.Write(s)
	net.Write(B)
	net.Write(u)

	A := readInt(net)

	S := new(big.Int).Exp(v, u, params.N)
	S = S.Mul(A, S)
	S = S.Exp(S, b, params.N)

	K := sha256Digest(S.Bytes())
	mac1 := hmacSHA256(K, s)
	mac2 := readBytes(net)

	ok := hmac.Equal(mac1, mac2)
	net.Write(ok)

	return ok
}
