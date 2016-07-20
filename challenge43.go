// Challenge 43 - DSA key recovery from nonce
// http://cryptopals.com/sets/6/challenges/43

package cryptopals

import (
	"errors"
	"math/big"
)

type challenge43 struct {
}

func (challenge43) RecoverDsaKeyFromNonce(data []byte, pub *dsaPublicKey, signature *dsaSignature) (*dsaPrivateKey, error) {
	priv := &dsaPrivateKey{dsaPublicKey: *pub}
	var i int64

	for i = 1; i < 65536; i++ {
		k := big.NewInt(i)

		x := new(big.Int).Mul(signature.s, k)
		x = x.Sub(x, dsaHash(data)).Mod(x, pub.q)
		x = x.Mul(x, new(big.Int).ModInverse(signature.r, pub.q))
		x = x.Mod(x, pub.q)

		priv.x = x

		if pub.verify(data, priv.sign(data)) {
			return priv, nil
		}
	}

	return nil, errors.New("Failed to recover DSA private key from nonce")
}
