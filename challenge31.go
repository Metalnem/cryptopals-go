// Challenge 31 - Implement and break HMAC-SHA1 with an artificial timing leak
// http://cryptopals.com/sets/4/challenges/31

package cryptopals

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/hex"
	"log"
	"net/http"
	"net/url"
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

func (challenge31) buildURL(addr, file string, sig []byte) *url.URL {
	params := url.Values{}

	params.Add("file", file)
	params.Add("signature", hex.EncodeToString(sig))

	url, _ := url.Parse(addr)
	url.RawQuery = params.Encode()

	return url
}

func (x challenge31) BreakHmacSHA1(addr, file string) ([]byte, bool) {
	sig := make([]byte, sha1.Size)

	for i := 0; i < len(sig); i++ {
		var valBest byte
		var timeBest time.Duration

		for j := 0; j < 256; j++ {
			sig[i] = byte(j)
			url := x.buildURL(addr, file, sig)
			start := time.Now()

			if resp, err := http.Get(url.String()); err == nil {
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

	return sig, true
}
