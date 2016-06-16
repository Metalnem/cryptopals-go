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
			fastest := time.Hour

			for k := 0; k < 10; k++ {
				start := time.Now()
				resp, _ := http.Get(url)
				elapsed := time.Since(start)
				resp.Body.Close()

				if elapsed < fastest {
					fastest = elapsed
				}
			}

			if fastest > timeBest {
				valBest = byte(j)
				timeBest = fastest
			}
		}

		sig[i] = valBest
	}

	return sig
}
