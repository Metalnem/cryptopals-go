// Challenge 45 - DSA parameter tampering
// http://cryptopals.com/sets/6/challenges/45

package cryptopals

import "math/big"

type challenge45 struct {
}

func (challenge45) badDsaParameters() dsaParameters {
	params := defaultDsaParameters()
	params.g = new(big.Int).Add(params.p, big.NewInt(1))

	return params
}
