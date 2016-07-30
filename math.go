package cryptopals

import "math/big"

func cbrt(n *big.Int) *big.Int {
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

func max(x, y *big.Int) *big.Int {
	if x.Cmp(y) < 0 {
		return y
	}

	return x
}

func min(x, y *big.Int) *big.Int {
	if x.Cmp(y) < 0 {
		return x
	}

	return y
}
