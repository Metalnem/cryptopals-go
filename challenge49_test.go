package cryptopals

import (
	"crypto/aes"
	"testing"
)

func TestForgeCbcMacMessage(t *testing.T) {
	key := randBytes(aes.BlockSize)
	client := &cbcMacClient{key: key}

	target := accountID(115461)
	attacker := accountID(23451565)
	amount := money(1000000)

	transaction := challenge49{}.ForgeCbcMacMessage(client, target, attacker, amount)
	executed := client.executeSingle(transaction)

	if !executed {
		t.Fatalf("Failed to forge CBC-MAC message")
	}
}

func TestCbcMacLengthExtension(t *testing.T) {
	key := randBytes(aes.BlockSize)
	client := &cbcMacClient{key: key}

	target := accountID(2151617)
	other := accountID(85158)
	attacker := accountID(15620156)
	amount := money(1000000)

	transaction := challenge49{}.CbcMacLengthExtension(client, target, other, attacker, amount)
	executed := client.executeMultiple(transaction)

	if !executed {
		t.Fatalf("Failed to forge CBC-MAC message using length extension")
	}
}
