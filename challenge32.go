// Challenge 32 - Break HMAC-SHA1 with a slightly less artificial timing leak
// http://cryptopals.com/sets/4/challenges/32

package cryptopals

import (
	"crypto/sha1"
	"net/http"
	"time"
)

type challenge32 struct {
}

func (challenge32) ForgeHmacSHA1SignaturePrecise(addr, file string) []byte {
	sig := make([]byte, sha1.Size)
	x := challenge31{}

	for i := 0; i < len(sig); i++ {
		var valBest byte
		var timeBest time.Duration

		for j := 0; j < 256; j++ {
			sig[i] = byte(j)
			url := x.buildURL(addr, file, sig)
			start := time.Now()

			for k := 0; k < 15; k++ {
				resp, _ := http.Get(url)
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
