// Challenge 36 - Implement Secure Remote Password (SRP)
// http://cryptopals.com/sets/5/challenges/36

package cryptopals

import (
	"crypto/hmac"
	"crypto/rand"
	"math/big"
)

type challenge36 struct {
}

type srpParams struct {
	N *big.Int
	g *big.Int
	k *big.Int
}

type srpClientInfo struct {
	I string
	P string
}

func (challenge36) defaultSrpParams() srpParams {
	var N = new(big.Int)
	var g = big.NewInt(2)
	var k = big.NewInt(3)

	N.SetString("EEAF0AB9ADB38DD69C33F80AFA8FC5E86072618775FF3C0B9EA2314C"+
		"9C256576D674DF7496EA81D3383B4813D692C6E0E0D5D8E250B98BE4"+
		"8E495C1D6089DAD15DC7D7B46154D6B6CE8EF4AD69B15D4982559B29"+
		"7BCF1885C529F566660E57EC68EDBC3C05726CC02FD4CBF4976EAA9A"+
		"FD5138FE8376435B9FC61D2FC0EB06E3", 16)

	return srpParams{N: N, g: g, k: k}
}

func (challenge36) Client(params srpParams, info srpClientInfo, net Network) bool {
	a, _ := rand.Int(rand.Reader, params.N)
	A := new(big.Int).Exp(params.g, a, params.N)

	net.Write(A)

	s := readBytes(net)
	B := readInt(net)

	uH := sha256Digest(append(A.Bytes(), B.Bytes()...))
	u := new(big.Int).SetBytes(uH)

	xH := sha256Digest(append(s, []byte(info.P)...))
	x := new(big.Int).SetBytes(xH)

	E := new(big.Int).Mul(u, x)
	E = E.Add(a, E)

	S := new(big.Int).Exp(params.g, x, params.N)
	S = S.Mul(S, params.k)
	S = S.Sub(B, S)
	S = S.Exp(S, E, params.N)

	K := sha256Digest(S.Bytes())
	mac := hmacSHA256(K, s)
	net.Write(mac)

	return net.Read().(bool)
}

func (challenge36) Server(params srpParams, info srpClientInfo, net Network) bool {
	s := randBytes(16)
	xH := sha256Digest(append(s, []byte(info.P)...))

	x := new(big.Int).SetBytes(xH)
	v := new(big.Int).Exp(params.g, x, params.N)

	b, _ := rand.Int(rand.Reader, params.N)
	B := new(big.Int).Exp(params.g, b, params.N)
	B = B.Add(B, new(big.Int).Mul(params.k, v))

	net.Write(s)
	net.Write(B)

	A := readInt(net)

	uH := sha256Digest(append(A.Bytes(), B.Bytes()...))
	u := new(big.Int).SetBytes(uH)

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
