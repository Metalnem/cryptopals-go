// Challenge 30 - Break an MD4 keyed MAC using length extension
// http://cryptopals.com/sets/4/challenges/29

package main

import (
	"crypto/sha1"
	"hash"
)

func macSha1(key, message []byte) []byte {
	h := sha1.New()

	h.Write(key)
	h.Write(message)

	return h.Sum(nil)
}

func forge(s [4]uint32) hash.Hash {
	d := new(digest)

	d.Reset()
	copy(d.s[:], s[:])

	return d
}
