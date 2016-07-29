// Challenge 47 - Bleichenbacher's PKCS 1.5 Padding Oracle (Complete Case)
// http://cryptopals.com/sets/6/challenges/48

package cryptopals

import "crypto/rsa"

type challenge48 struct {
}

func (challenge48) DecryptRsaPaddingOracleComplete(pub *rsa.PublicKey, ciphertext []byte) []byte {
	return challenge47{}.DecryptRsaPaddingOracleSimple(pub, ciphertext)
}
