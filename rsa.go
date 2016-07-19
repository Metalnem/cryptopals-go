package cryptopals

import "math/big"

type privateKey struct {
	publicKey
	d *big.Int
}

type publicKey struct {
	e *big.Int
	n *big.Int
}

func generateRsaPrivateKey(bits int) *privateKey {
	e := big.NewInt(3)

	for {
		p := randPrime(bits / 2)
		t1 := new(big.Int).Sub(p, big.NewInt(1))

		if new(big.Int).Mod(t1, e).Int64() == 0 {
			continue
		}

		q := randPrime(bits / 2)
		t2 := new(big.Int).Sub(q, big.NewInt(1))

		if new(big.Int).Mod(t2, e).Int64() == 0 {
			continue
		}

		n := new(big.Int).Mul(p, q)
		t := new(big.Int).Mul(t1, t2)
		d := new(big.Int).ModInverse(e, t)

		return &privateKey{publicKey: publicKey{e: e, n: n}, d: d}
	}
}

func (key *publicKey) size() bitSize {
	return byteSize(len(key.n.Bytes())).toBitSize()
}

func (key *privateKey) public() *publicKey {
	return &key.publicKey
}

func (key *publicKey) encrypt(m *big.Int) *big.Int {
	return new(big.Int).Exp(m, key.e, key.n)
}

func (key *privateKey) decrypt(c *big.Int) *big.Int {
	return new(big.Int).Exp(c, key.d, key.n)
}
