package cryptopals

import (
	"encoding/base64"
	"testing"
)

func TestDecryptAesCtrCompressed(t *testing.T) {
	c := challenge51{}
	prefix := "sessionid="
	oracle := compressionOracle{cookie: "sessionid=TmV2ZXIgcmV2ZWFsIHRoZSBXdS1UYW5nIFNlY3JldCE="}

	expected := "Never reveal the Wu-Tang Secret!"
	plaintext := c.DecryptAesCtrCompressed(prefix, oracle)
	cookie := string(plaintext[len(prefix):])
	bytes, _ := base64.StdEncoding.DecodeString(cookie)
	actual := string(bytes)

	if actual != expected {
		t.Fatalf("Expected %v, was %v", expected, actual)
	}
}
