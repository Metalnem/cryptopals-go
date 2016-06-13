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
	s := &hmacSHA1Server{key: key}

	go func() {
		s.start()
	}()

	time.Sleep(time.Second)

	file := "Beatles"
	h := hmac.New(sha1.New, key)
	h.Write([]byte(file))

	expected := hex.EncodeToString(h.Sum(nil))
	actual := hex.EncodeToString(challenge31{}.BreakHmacSHA1("http://localhost:9000", file))

	if expected != actual {
		t.Errorf("Expected %v, was %v", expected, actual)
	}
}
