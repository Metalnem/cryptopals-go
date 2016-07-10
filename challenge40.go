// Challenge 40 - Implement an E=3 RSA Broadcast attack
// http://cryptopals.com/sets/5/challenges/40

package cryptopals

import "math/big"

type challenge40 struct {
}

func (challenge40) cbrt(n *big.Int) *big.Int {
	two := big.NewInt(2)
	three := big.NewInt(3)
	root := n

	for pow := new(big.Int); pow.Exp(root, three, nil).Cmp(n) > 0; {
		x := new(big.Int).Mul(root, two)
		y := new(big.Int).Exp(root, two, nil)
		z := new(big.Int).Div(n, y)
		t := new(big.Int).Add(x, z)
		root = new(big.Int).Div(t, three)
	}

	return root
}

func (c challenge40) RsaBroadcastAttack(k0, k1, k2 *publicKey, c0, c1, c2 *big.Int) *big.Int {
	m0 := new(big.Int).Mul(k1.n, k2.n)
	m1 := new(big.Int).Mul(k0.n, k2.n)
	m2 := new(big.Int).Mul(k0.n, k1.n)

	x0 := new(big.Int).ModInverse(m0, k0.n)
	x1 := new(big.Int).ModInverse(m1, k1.n)
	x2 := new(big.Int).ModInverse(m2, k2.n)

	x0 = x0.Mul(x0, c0).Mul(x0, m0)
	x1 = x1.Mul(x1, c1).Mul(x1, m1)
	x2 = x2.Mul(x2, c2).Mul(x2, m2)

	n := new(big.Int)
	n = n.Mul(k0.n, k1.n).Mul(n, k2.n)

	x := new(big.Int)
	x = x.Add(x, x0).Add(x, x1).Add(x, x2).Mod(x, n)

	return c.cbrt(x)
}
