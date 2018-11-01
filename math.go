package cryptopals

import (
	"errors"
	"math/big"
)

type equation struct {
	A *big.Int
	M *big.Int
}

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

func ceil(x, y *big.Int) *big.Int {
	ceil := new(big.Int)
	return ceil.Add(x, y).Sub(ceil, big.NewInt(1)).Div(ceil, y)
}

func floor(x, y *big.Int) *big.Int {
	return new(big.Int).Div(x, y)
}

func crt(eqs []equation) (equation, error) {
	if len(eqs) == 0 {
		return equation{}, errors.New("system of equations is empty")
	}

	var a, m, x, gcd, inv, one big.Int

	m.SetInt64(1)
	one.SetInt64(1)

	for _, eq := range eqs {
		gcd.GCD(nil, nil, &m, eq.M)

		if gcd.Cmp(&one) > 0 {
			return equation{}, errors.New("remainders are not pairwise relatively prime")
		}

		x.Sub(eq.A, &a)
		inv.ModInverse(&m, eq.M)
		x.Mul(&x, &inv)

		x.Mul(&x, &m)
		a.Add(&a, &x)

		m.Mul(&m, eq.M)
		a.Mod(&a, &m)
	}

	return equation{A: &a, M: &m}, nil
}

func primes(n int) []int {
	s := make([]bool, n)
	var p []int

	for i := 2; i < n; i++ {
		if !s[i] {
			p = append(p, i)

			for j := i * i; j < len(s); j += i {
				s[j] = true
			}
		}
	}

	return p
}
