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
	executed := client.execute(transaction)

	if !executed {
		t.Fatalf("Failed to forge CBC-MAC message")
	}
}
