package cryptopals

import "math/big"

type privateKey struct {
	e *big.Int
	n *big.Int
	d *big.Int
}

type publicKey struct {
	e *big.Int
	n *big.Int
}

func generateRsaPrivateKey(bits int) *privateKey {
	p := randPrime(bits / 2)
	q := randPrime(bits / 2)

	e := big.NewInt(3)
	n := new(big.Int).Mul(p, q)

	t1 := new(big.Int).Sub(p, big.NewInt(1))
	t2 := new(big.Int).Sub(q, big.NewInt(1))

	t := new(big.Int).Mul(t1, t2)
	d := new(big.Int).ModInverse(e, t)

	return &privateKey{e: e, n: n, d: d}
}

func (key *privateKey) publicKey() *publicKey {
	return &publicKey{e: key.e, n: key.n}
}

func (key *publicKey) encrypt(m *big.Int) *big.Int {
	return new(big.Int).Exp(m, key.e, key.n)
}

func (key *privateKey) decrypt(c *big.Int) *big.Int {
	return new(big.Int).Exp(c, key.d, key.n)
}
