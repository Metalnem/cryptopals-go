// Challenge 31 - Implement and break HMAC-SHA1 with an artificial timing leak
// http://cryptopals.com/sets/4/challenges/31

package cryptopals

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"log"
	"net/http"
	"time"
)

type challenge31 struct {
}

type hmacSHA1Server struct {
	key   []byte
	delay time.Duration
}

func (s *hmacSHA1Server) start() {
	http.Handle("/test", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		file := []byte(q.Get("file"))
		sig, _ := hex.DecodeString(q.Get("signature"))

		if s.insecureCompare(file, sig) == 0 {
			w.WriteHeader(http.StatusInternalServerError)
		}
	}))

	log.Fatal(http.ListenAndServe(":9000", nil))
}

func (s *hmacSHA1Server) insecureCompare(file, sig []byte) int {
	h := hmac.New(sha1.New, s.key)
	h.Write(file)
	mac := h.Sum(nil)

	if len(sig) != len(mac) {
		return 0
	}

	for i, b := range sig {
		if b != mac[i] {
			return 0
		}

		time.Sleep(s.delay)
	}

	return 1
}

func (challenge31) BreakHmacSHA1(server, file string) []byte {
	sig := make([]byte, sha1.Size)

	for i := 0; i < len(sig); i++ {
		var valBest byte
		var timeBest time.Duration

		for j := 0; j < 256; j++ {
			sig[i] = byte(j)
			start := time.Now()
			url := fmt.Sprintf("%s/test?file=%s&signature=%s", server, file, hex.EncodeToString(sig))

			if resp, err := http.Get(url); err == nil {
				resp.Body.Close()
			}

			elapsed := time.Since(start)

			if elapsed > timeBest {
				valBest = byte(j)
				timeBest = elapsed
			}
		}

		sig[i] = valBest
	}

	return sig
}
