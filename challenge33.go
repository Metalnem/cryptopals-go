// Challenge 33 - Implement Diffie-Hellman
// http://cryptopals.com/sets/5/challenges/33

package cryptopals

import (
	"crypto/rand"
	"math/big"
)

type challenge33 struct {
}

type dhParams struct {
	p *big.Int
	g *big.Int
}

func (challenge33) defaultDhParams() dhParams {
	var p = new(big.Int)
	var g = new(big.Int)

	p.SetString("ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024"+
		"e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd"+
		"3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec"+
		"6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f"+
		"24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361"+
		"c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552"+
		"bb9ed529077096966d670c354e4abc9804f1746c08ca237327fff"+
		"fffffffffffff", 16)

	g.SetInt64(2)

	return dhParams{p: p, g: g}
}

func (challenge33) DiffieHellman(params dhParams, net Network) []byte {
	p, g := params.p, params.g
	a, _ := rand.Int(rand.Reader, p)

	A := new(big.Int)
	A.Exp(g, a, p)

	net.Write(A)
	B := net.Read().(*big.Int)

	s := new(big.Int)
	s.Exp(B, a, p)

	return sha256Digest(s.Bytes())
}
