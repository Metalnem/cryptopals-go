package cryptopals

import (
	"encoding/base64"
	"math/big"
	"testing"
)

func TestDecryptRsaParityOracle(t *testing.T) {
	priv := generateRsaPrivateKey(1024)
	pub := priv.public()

	encoded := "VGhhdCdzIHdoeSBJIGZvdW5kIHlvdSBkb24ndCBwbGF5IGFyb3VuZCB3aXRoIHRoZSBGdW5reSBDb2xkIE1lZGluYQ=="
	message, _ := base64.StdEncoding.DecodeString(encoded)
	m1 := new(big.Int).SetBytes(message)

	server := &parityOracleServer{priv: *priv}
	c := pub.encrypt(m1)
	m2, err := challenge46{}.DecryptRsaParityOracle(server, pub, c)

	if err != nil {
		t.Fatal(err)
	}

	actual := string(m2.Bytes())
	expected := string(message)

	if actual != expected {
		t.Fatalf("Expected %v, was %v", expected, actual)
	}
}
