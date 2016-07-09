// Challenge 39 - Implement RSA
// http://cryptopals.com/sets/5/challenges/39

package cryptopals

import "math/big"

type challenge39 struct {
}

func (challenge39) RsaEncrypt(key *publicKey, m *big.Int) *big.Int {
	return new(big.Int).Exp(m, key.e, key.n)
}

func (challenge39) RsaDecrypt(key *privateKey, c *big.Int) *big.Int {
	return new(big.Int).Exp(c, key.d, key.n)
}
