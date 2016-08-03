// Challenge 49 - CBC-MAC Message Forgery
// http://cryptopals.com/sets/7/challenges/49

package cryptopals

import (
	"crypto/aes"
	"fmt"
)

type challenge49 struct {
}

type cbcMacClient struct {
	key []byte
}

type accountID uint32
type money uint32

func (client *cbcMacClient) transfer(from, to accountID, amount money) []byte {
	msg := fmt.Sprintf("from=#%010d&to=#%010d&amount=#%d", from, to, amount)
	return CbcMacSign([]byte(msg), client.key, randBytes(aes.BlockSize))
}

func (client *cbcMacClient) execute(transaction []byte) bool {
	return CbcMacVerify(transaction, client.key)
}

func (challenge49) ForgeCbcMacMessage(client *cbcMacClient, target, attacker accountID, amount money) []byte {
	message := client.transfer(attacker, attacker, amount)

	realFirstBlock := message[0:aes.BlockSize]
	fakeFirstBlock := []byte(fmt.Sprintf("from=#%010d", target))

	realIv := message[len(message)-2*aes.BlockSize : len(message)-aes.BlockSize]
	fakeIv := xor(xor(realFirstBlock, fakeFirstBlock), realIv)

	copy(message[:], fakeFirstBlock)
	copy(message[len(message)-2*aes.BlockSize:], fakeIv)

	return message
}
