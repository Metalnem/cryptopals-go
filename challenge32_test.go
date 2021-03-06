package cryptopals

import (
	"encoding/hex"
	"testing"
	"time"
)

func TestForgeHmacSHA1SignaturePrecise(t *testing.T) {
	t.Skip("Skip this test, because it runs too long")

	key := []byte("We all live in a yellow submarine")
	delay := 5 * time.Millisecond
	s := &hmacSHA1Server{key: key, delay: delay}

	go func() {
		s.start()
	}()

	time.Sleep(time.Second)

	file := "Vanilla Ice"
	mac := hmacSHA1(key, []byte(file))

	signature := challenge32{}.ForgeHmacSHA1SignaturePrecise("http://localhost:9000/test", file)
	expected := hex.EncodeToString(mac)
	actual := hex.EncodeToString(signature)

	if expected != actual {
		t.Fatalf("Expected %v, was %v", expected, actual)
	}
}
