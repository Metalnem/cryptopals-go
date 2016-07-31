// Challenge 47 - Bleichenbacher's PKCS 1.5 Padding Oracle (Simple Case)
// http://cryptopals.com/sets/6/challenges/47

package cryptopals

import (
	"crypto/rsa"
	"math/big"
)

type challenge47 struct {
}

type oracleFunc func([]byte) bool

type interval struct {
	a *big.Int
	b *big.Int
}

func (challenge47) mulEncrypt(m, e, n, c *big.Int) []byte {
	x := new(big.Int).Exp(m, e, n)
	return x.Mul(c, x).Mod(x, n).Bytes()
}

func (challenge47) union(M []interval, m interval) []interval {
	if m.a.Cmp(m.b) > 0 {
		return M
	}

	var result []interval

	for i, mi := range M {
		if mi.b.Cmp(m.a) < 0 {
			result = append(result, mi)
		} else if m.b.Cmp(mi.a) < 0 {
			return append(append(result, m), M[i:]...)
		} else {
			m = interval{a: min(mi.a, m.a), b: max(mi.b, m.b)}
		}
	}

	return append(result, m)
}

func (x challenge47) DecryptRsaPaddingOracleSimple(pub *rsa.PublicKey, ciphertext []byte, oracle oracleFunc) []byte {
	e, c0, s := big.NewInt(int64(pub.E)), new(big.Int).SetBytes(ciphertext), new(big.Int)
	k := big.NewInt(int64(pub.N.BitLen() / 8))
	one, two, three, eight := big.NewInt(1), big.NewInt(2), big.NewInt(3), big.NewInt(8)

	B := new(big.Int).Sub(k, two)
	B = B.Mul(eight, B).Exp(two, B, nil)

	twoB, threeB := new(big.Int).Mul(two, B), new(big.Int).Mul(three, B)
	M := []interval{interval{a: twoB, b: new(big.Int).Sub(threeB, one)}}

	// Step 2: Searching for PKCS conforming messages.
	for i := 1; ; i++ {
		if i == 1 { // Step 2a: Starting the search.
			for s = ceil(pub.N, threeB); !oracle(x.mulEncrypt(s, e, pub.N, c0)); s = s.Add(s, one) {
			}
		} else if len(M) > 1 { // Step 2.b: Searching with more than one interval left.
			for s = s.Add(s, one); !oracle(x.mulEncrypt(s, e, pub.N, c0)); s = s.Add(s, one) {
			}

		} else { // Step 2.c: Searching with one interval left.
			a, b, found := M[0].a, M[0].b, false

			r := new(big.Int).Mul(b, s)
			r = r.Sub(r, twoB).Mul(two, r).Div(r, pub.N)

			for ; !found; r = r.Add(r, one) {
				sMin := new(big.Int).Mul(r, pub.N)
				sMin = sMin.Add(twoB, sMin).Div(sMin, b)

				sMax := new(big.Int).Mul(r, pub.N)
				sMax = sMax.Add(threeB, sMax).Div(sMax, a)

				for s = sMin; s.Cmp(sMax) < 0; s = s.Add(s, one) {
					if oracle(x.mulEncrypt(s, e, pub.N, c0)) {
						found = true
						break
					}
				}
			}
		}

		var Mi []interval

		// Step 3: Narrowing the set of solutions.
		for _, m := range M {
			rMin := new(big.Int).Mul(m.a, s)
			rMin = rMin.Sub(rMin, threeB).Add(rMin, one).Div(rMin, pub.N)

			rMax := new(big.Int).Mul(m.b, s)
			rMax = rMax.Sub(rMax, twoB).Div(rMax, pub.N)

			for r := rMin; r.Cmp(rMax) <= 0; r = r.Add(r, one) {
				a := new(big.Int).Mul(r, pub.N)
				a = max(m.a, ceil(a.Add(twoB, a), s))

				b := new(big.Int).Mul(r, pub.N)
				b = min(m.b, floor(b.Add(threeB, b).Sub(b, one), s))

				mi := interval{a: a, b: b}
				Mi = x.union(Mi, mi)
			}
		}

		M = Mi

		// Step 4: Computing the solution.
		if len(M) == 1 && M[0].a.Cmp(M[0].b) == 0 {
			return M[0].a.Bytes()
		}
	}
}
