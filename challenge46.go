// Challenge 46 - RSA parity oracle
// http://cryptopals.com/sets/6/challenges/46

package cryptopals

import (
	"errors"
	"math/big"
)

type challenge46 struct {
}

type parityOracleServer struct {
	priv privateKey
}

func (server *parityOracleServer) isOdd(c *big.Int) bool {
	m := server.priv.decrypt(c)

	mod := big.NewInt(2)
	mod = mod.Mod(m, mod)

	return mod.Sign() > 0
}

func (challenge46) DecryptRsaParityOracle(server *parityOracleServer, pub *publicKey, c *big.Int) (*big.Int, error) {
	low := big.NewInt(0)
	high := new(big.Int).Set(pub.n)

	candidate := new(big.Int).Set(c)
	two := big.NewInt(2)
	multiplier := pub.encrypt(two)

	for low.Cmp(high) < 0 {
		candidate = candidate.Mul(candidate, multiplier)
		candidate = candidate.Mod(candidate, pub.n)

		mid := new(big.Int).Add(low, high)
		mid = mid.Div(mid, two)

		if server.isOdd(candidate) {
			low = mid
		} else {
			high = mid
		}
	}

	for i := 0; i < 256; i++ {
		b := high.Bytes()
		b[len(b)-1] = byte(i)
		high.SetBytes(b)

		if pub.encrypt(high).Cmp(c) == 0 {
			return high, nil
		}
	}

	return nil, errors.New("Failed to decrypt RSA enrypted message using parity oracle")
}
