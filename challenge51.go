// Challenge 51 - Compression Ratio Side-Channel Attacks
// http://cryptopals.com/sets/7/challenges/51

package cryptopals

import (
	"bytes"
	"compress/flate"
	"io"
	"math"
	"text/template"
)

type challenge51 struct {
}

type encryptor func([]byte) []byte

type compressionOracle struct {
	cookie string
	cipher encryptor
}

var t = template.Must(template.New("request").Parse(`POST / HTTP/1.1
Host: hapless.com
Cookie: {{ .Cookie }}
Content-Length: {{ len .Data }}
{{ .Data }}`))

func (oracle compressionOracle) process(data string) int {
	req := new(bytes.Buffer)

	t.Execute(req, struct {
		Cookie string
		Data   string
	}{
		Cookie: oracle.cookie,
		Data:   data,
	})

	b := new(bytes.Buffer)
	w, _ := flate.NewWriter(b, flate.BestCompression)

	io.Copy(w, req)
	w.Close()

	ciphertext := oracle.cipher(b.Bytes())
	return len(ciphertext)
}

func (oracle compressionOracle) cookieLength() int {
	return len(oracle.cookie)
}

func (x challenge51) DecryptAesCtrCompressed(prefix string, oracle compressionOracle) string {
	body := prefix
	alphabet := "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="

	for len(body) < oracle.cookieLength() {
		best := int(math.MaxInt32)
		var next rune

		for _, c := range alphabet {
			guess := body + string(c)
			l := oracle.process(guess)

			if l < best {
				best = l
				next = c
			}
		}

		body += string(next)
	}

	return body
}
