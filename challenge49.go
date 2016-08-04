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

func (client *cbcMacClient) transferSingle(from, to accountID, amount money) []byte {
	msg := fmt.Sprintf("from=#%010d&to=#%010d&amount=#%d", from, to, amount)
	return CbcMacSign([]byte(msg), client.key, randBytes(aes.BlockSize))
}

func (client *cbcMacClient) transferMultiple(from, to accountID, amount money) []byte {
	msg := fmt.Sprintf("from=#%010d&tx_list=#%010d:%d", from, to, amount)
	return CbcMacSignFixedIv([]byte(msg), client.key)
}

func (client *cbcMacClient) executeSingle(transaction []byte) bool {
	return CbcMacVerify(transaction, client.key)
}

func (client *cbcMacClient) executeMultiple(transaction []byte) bool {
	return CbcMacVerifyFixedIv(transaction, client.key)
}

func (challenge49) ForgeCbcMacMessage(client *cbcMacClient, target, attacker accountID, amount money) []byte {
	message := client.transferSingle(attacker, attacker, amount)

	realFirstBlock := message[0:aes.BlockSize]
	fakeFirstBlock := []byte(fmt.Sprintf("from=#%010d", target))

	realIv := message[len(message)-2*aes.BlockSize : len(message)-aes.BlockSize]
	fakeIv := xor(xor(realFirstBlock, fakeFirstBlock), realIv)

	copy(message[:], fakeFirstBlock)
	copy(message[len(message)-2*aes.BlockSize:], fakeIv)

	return message
}

func (challenge49) CbcMacLengthExtension(client *cbcMacClient, target, other, attacker accountID, amount money) []byte {
	realMsg := client.transferMultiple(target, other, amount)
	realMessage := pkcs7Pad(realMsg[0 : len(realMsg)-aes.BlockSize])
	realMac := realMsg[len(realMsg)-aes.BlockSize:]

	fakeMessage := []byte(fmt.Sprintf(";%010d:%d", target, amount))
	fakeMsg := CbcMacSignFixedIv(xor(realMac, fakeMessage), client.key)
	fakeMac := fakeMsg[len(fakeMsg)-aes.BlockSize:]

	return append(append(realMessage, fakeMessage...), fakeMac...)
}
