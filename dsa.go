package cryptopals

import "math/big"

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

func generateDsaPrivateKey(params dsaParameters) *dsaPrivateKey {
	x := randInt(params.q)
	y := new(big.Int).Exp(params.g, x, params.p)

	public := dsaPublicKey{dsaParameters: params, y: y}
	private := dsaPrivateKey{dsaPublicKey: public, x: x}

	return &private
}

func (key *dsaPrivateKey) public() *dsaPublicKey {
	return &key.dsaPublicKey
}

func (key *dsaPrivateKey) sign(data []byte) *big.Int {
	return nil
}

func (key *dsaPrivateKey) verify(data []byte, signature *big.Int) bool {
	return false
}
