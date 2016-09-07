// Challenge 51 - Compression Ratio Side-Channel Attacks
// http://cryptopals.com/sets/7/challenges/51

package cryptopals

import (
	"bytes"
	"compress/flate"
	"crypto/aes"
	"crypto/cipher"
	"io"
	"math"
	"text/template"
)

type challenge51 struct {
}

const (
	alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="
	cookie   = "sessionid=TmV2ZXIgcmV2ZWFsIHRoZSBXdS1UYW5nIFNlY3JldCE="
)

var t = template.Must(template.New("request").Parse(`POST / HTTP/1.1
Host: hapless.com
Cookie: {{ .Cookie }}
Content-Length: {{ len .Data }}
{{ .Data }}`))

func (challenge51) compressionOracle(data string) int {
	req := new(bytes.Buffer)

	t.Execute(req, struct {
		Cookie string
		Data   string
	}{
		Cookie: cookie,
		Data:   data,
	})

	b := new(bytes.Buffer)
	w, _ := flate.NewWriter(b, flate.BestCompression)

	io.Copy(w, req)
	w.Close()

	block, _ := aes.NewCipher(randBytes(aes.BlockSize))
	ctr := cipher.NewCTR(block, randBytes(aes.BlockSize))

	var ciphertext []byte
	ciphertext = append(ciphertext, b.Bytes()...)
	ctr.XORKeyStream(ciphertext, ciphertext)

	return len(ciphertext)
}

func (x challenge51) DecryptUsingCompressionOracle() string {
	body := "sessionid="

	for len(body) < len(cookie) {
		best := int(math.MaxInt32)
		var next rune

		for _, c := range alphabet {
			guess := body + string(c)
			l := x.compressionOracle(guess)

			if l < best {
				best = l
				next = c
			}
		}

		body += string(next)
	}

	return body
}
