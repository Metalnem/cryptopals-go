// Challenge 51 - Compression Ratio Side-Channel Attacks
// http://cryptopals.com/sets/7/challenges/51

package cryptopals

import (
	"bytes"
	"compress/flate"
	"crypto/aes"
	"crypto/cipher"
	"io"
	"text/template"
)

type challenge51 struct {
}

var t = template.Must(template.New("request").Parse(`POST / HTTP/1.1
Host: hapless.com
Cookie: sessionid=TmV2ZXIgcmV2ZWFsIHRoZSBXdS1UYW5nIFNlY3JldCE=
Content-Length: {{ len . }}
{{ . }}`))

func (challenge51) CompressionOracle(data string) int {
	req := new(bytes.Buffer)
	t.Execute(req, data)

	b := new(bytes.Buffer)
	w, _ := flate.NewWriter(b, flate.BestCompression)

	io.Copy(w, req)
	w.Close()

	block, _ := aes.NewCipher(randBytes(aes.BlockSize))
	ctr := cipher.NewCTR(block, randBytes(aes.BlockSize))

	ciphertext := make([]byte, len(b.Bytes()))
	ctr.XORKeyStream(ciphertext, ciphertext)

	return len(ciphertext)
}
