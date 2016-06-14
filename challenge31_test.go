package cryptopals

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/hex"
	"testing"
	"time"
)

func TestBreakHmacSHA1(t *testing.T) {
	key := []byte("We all live in a yellow submarine")
	delay := 50 * time.Millisecond
	s := &hmacSHA1Server{key: key, delay: delay}

	go func() {
		s.start()
	}()

	time.Sleep(time.Second)

	file := "Vanilla Ice"
	h := hmac.New(sha1.New, key)
	h.Write([]byte(file))

	signature, success := challenge31{}.BreakHmacSHA1("http://localhost:9000/test", file)

	if !success {
		t.Fatalf("Failed to find the signature")
	}

	expected := hex.EncodeToString(h.Sum(nil))
	actual := hex.EncodeToString(signature)

	if expected != actual {
		t.Fatalf("Expected %v, was %v", expected, actual)
	}
}
