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
type decryptor func(compressionOracle) string

type compressionOracle struct {
	cookie  string
	prefix  string
	encrypt encryptor
}

const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="

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

	ciphertext := oracle.encrypt(b.Bytes())
	return len(ciphertext)
}

func (oracle compressionOracle) cookieLength() int {
	return len(oracle.cookie)
}

func (x challenge51) DecryptAesCtrCompressed(oracle compressionOracle) string {
	body := oracle.prefix

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

func (x challenge51) DecryptAesCbcCompressed(oracle compressionOracle) string {
	body := oracle.prefix

	for len(body) < oracle.cookieLength() {
		best := int(math.MaxInt32)
		var next rune

		for _, c := range alphabet {
			guess := body + string(c)
			l := oracle.process(guess)

			for i := 0; ; i++ {
				guess += string(i % 10)

				if l < oracle.process(guess) {
					l = l - i - 1
					break
				}
			}

			if l < best {
				best = l
				next = c
			}
		}

		body += string(next)
	}

	return body
}
