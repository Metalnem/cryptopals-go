// Challenge 50 - Hashing with CBC-MAC
// http://cryptopals.com/sets/7/challenges/50

package cryptopals

import "crypto/aes"

type challenge50 struct {
}

func (challenge50) ForgeCbcMacHash(message, key, target []byte) []byte {
	lastBlockXor := make([]byte, aes.BlockSize)
	cipher, _ := aes.NewCipher(key)
	cipher.Decrypt(lastBlockXor, lastBlockXor)

	padded := pkcs7Pad(target)
	lastBlockEnc := CbcMacHash(target, key)
	lastBlock := xor(lastBlockEnc, lastBlockXor)

	result := append(padded, lastBlock...)
	result = append(result, message...)

	return result
}
