package cryptopals

import (
	"encoding/hex"
	"math/big"
)

type dsaParameters struct {
	p *big.Int
	q *big.Int
	g *big.Int
}

type dsaPrivateKey struct {
	dsaPublicKey
	x *big.Int
}

type dsaPublicKey struct {
	dsaParameters
	y *big.Int
}

type dsaSignature struct {
	r *big.Int
	s *big.Int
}

func defaultDsaParameters() dsaParameters {
	var p = new(big.Int)
	var q = new(big.Int)
	var g = new(big.Int)

	p.SetString("800000000000000089e1855218a0e7dac38136ffafa72eda7"+
		"859f2171e25e65eac698c1702578b07dc2a1076da241c76c6"+
		"2d374d8389ea5aeffd3226a0530cc565f3bf6b50929139ebe"+
		"ac04f48c3c84afb796d61e5a4f9a8fda812ab59494232c7d2"+
		"b4deb50aa18ee9e132bfa85ac4374d7f9091abc3d015efc87"+
		"1a584471bb1", 16)

	q.SetString("f4f47f05794b256174bba6e9b396a7707e563c5b", 16)

	g.SetString("5958c9d3898b224b12672c0b98e06c60df923cb8bc999d119"+
		"458fef538b8fa4046c8db53039db620c094c9fa077ef389b5"+
		"322a559946a71903f990f1f7e0e025e2d7f7cf494aff1a047"+
		"0f5b64c36b625a097f1651fe775323556fe00b3608c887892"+
		"878480e99041be601a62166ca6894bdd41a7054ec89f756ba"+
		"9fc95302291", 16)

	return dsaParameters{p: p, q: q, g: g}
}

func generateDsaPrivateKey(params dsaParameters) *dsaPrivateKey {
	x := new(big.Int)

	for {
		x.SetBytes(randBytes(params.q.BitLen() / 8))

		if x.Sign() != 0 && x.Cmp(params.q) < 0 {
			break
		}
	}

	y := new(big.Int).Exp(params.g, x, params.p)

	public := dsaPublicKey{dsaParameters: params, y: y}
	private := dsaPrivateKey{dsaPublicKey: public, x: x}

	return &private
}

func dsaHash(data []byte) *big.Int {
	h := sha1Digest(data)
	hx := hex.EncodeToString(h)
	H, _ := new(big.Int).SetString(hx, 16)

	return H
}

func (key *dsaPrivateKey) public() *dsaPublicKey {
	return &key.dsaPublicKey
}

func (key *dsaPrivateKey) sign(data []byte) *dsaSignature {
	for {
		k := new(big.Int)

		for {
			k.SetBytes(randBytes(key.q.BitLen() / 8))

			if k.Sign() != 0 && k.Cmp(key.q) < 0 {
				break
			}
		}

		r := new(big.Int).Exp(key.g, k, key.p)
		r = r.Mod(r, key.q)

		if r.Sign() == 0 {
			continue
		}

		s := dsaHash(data)
		s = s.Add(s, new(big.Int).Mul(key.x, r))
		s = s.Mul(k.ModInverse(k, key.q), s).Mod(s, key.q)

		if s.Sign() == 0 {
			continue
		}

		return &dsaSignature{r: r, s: s}
	}
}

func (key *dsaPrivateKey) verify(data []byte, signature *dsaSignature) bool {
	r := signature.r
	s := signature.s

	if r.Sign() == 0 || r.Cmp(key.q) >= 0 || s.Sign() == 0 || s.Cmp(key.q) >= 0 {
		return false
	}

	w := new(big.Int).ModInverse(s, key.q)

	u1 := new(big.Int).Mul(dsaHash(data), w)
	u1 = u1.Mod(u1, key.q)

	u2 := new(big.Int).Mul(r, w)
	u2 = u2.Mod(u2, key.q)

	v1 := new(big.Int).Exp(key.g, u1, key.p)
	v2 := new(big.Int).Exp(key.g, u2, key.p)

	v := new(big.Int).Mul(v1, v2)
	v = v.Mod(v, key.p).Mod(v, key.q)

	return v.Cmp(r) == 0
}
