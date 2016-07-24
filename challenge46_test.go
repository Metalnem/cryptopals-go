package cryptopals

import (
	"encoding/base64"
	"fmt"
	"math/big"
	"testing"
)

func TestDecryptRsaParityOracle(t *testing.T) {
	priv := generateRsaPrivateKey(1024)
	pub := priv.public()

	encoded := "VGhhdCdzIHdoeSBJIGZvdW5kIHlvdSBkb24ndCBwbGF5IGFyb3VuZCB3aXRoIHRoZSBGdW5reSBDb2xkIE1lZGluYQ=="
	message, _ := base64.RawStdEncoding.DecodeString(encoded)
	m1 := new(big.Int).SetBytes(message)

	server := &parityOracleServer{priv: *priv}
	c := pub.encrypt(m1)
	m2 := challenge46{}.DecryptRsaParityOracle(server, pub, c)

	s1 := string(m1.Bytes())
	s2 := string(m2.Bytes())

	fmt.Println(s1)
	fmt.Println(s2)
}
