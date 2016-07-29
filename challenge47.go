// Challenge 47 - Bleichenbacher's PKCS 1.5 Padding Oracle (Simple Case)
// http://cryptopals.com/sets/6/challenges/47

package cryptopals

import "crypto/rsa"

type challenge47 struct {
}

func (challenge47) DecryptRsaPaddingOracleSimple(pub *rsa.PublicKey, ciphertext []byte) []byte {
	return nil
}
