// Challenge 31 - Implement and break HMAC-SHA1 with an artificial timing leak
// http://cryptopals.com/sets/4/challenges/31

package cryptopals

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/hex"
	"hash"
	"net/http"
	"time"
)

type challenge31 struct {
}

type hmacSHA1Server struct {
	key []byte
	h   hash.Hash
}

func spawn(key []byte) {
	h := hmac.New(sha1.New, key)
	s := &hmacSHA1Server{key: key, h: h}

	http.Handle("/test", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		file := []byte(q.Get("file"))
		sig, _ := hex.DecodeString(q.Get("signature"))

		if s.insecureCompare(file, sig) == 0 {
			w.WriteHeader(http.StatusInternalServerError)
		}
	}))

	http.ListenAndServe(":9000", nil)
}

func (s *hmacSHA1Server) insecureCompare(file, sig []byte) int {
	mac := s.h.Sum(nil)

	if len(sig) != len(mac) {
		return 0
	}

	for i, b := range sig {
		if b != mac[i] {
			return 0
		}

		time.Sleep(50 * time.Millisecond)
	}

	return 1
}

func (challenge31) BreakHmacSHA1(server, file string) []byte {
	return nil
}
