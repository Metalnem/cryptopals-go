// Challenge 51 - Compression Ratio Side-Channel Attacks
// http://cryptopals.com/sets/7/challenges/51

package cryptopals

import (
	"bytes"
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
	b := new(bytes.Buffer)
	t.Execute(b, data)

	return len(b.String())
}
