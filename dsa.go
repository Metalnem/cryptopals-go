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

func (key *dsaPrivateKey) verify(data []byte, signature *big.Int) bool {
	return false
}
