// Challenge 30 - Break an MD4 keyed MAC using length extension
// http://cryptopals.com/sets/4/challenges/29

package main

import (
	"crypto/subtle"
	"encoding/binary"
)

type challenge30 struct {
}

type macMD4Server struct {
	key []byte
}

func (s *macMD4Server) sign(message []byte) []byte {
	h := New()

	h.Write(s.key)
	h.Write(message)

	return h.Sum(nil)
}

func (s *macMD4Server) validate(message, mac []byte) bool {
	return subtle.ConstantTimeCompare(s.sign(message), mac) == 1
}

func (challenge30) forgePadding(keyLength int, message []byte) []byte {
	size := keyLength + len(message)
	padLen := 64 - size%64

	if size%64 >= 56 {
		padLen += 64
	}

	padding := make([]byte, padLen)
	padding[0] = 0x80
	binary.LittleEndian.PutUint64(padding[padLen-8:], uint64(8*size))

	return padding
}

func (challenge30) forgeHash(mac []byte, len uint64) *digest {
	d := new(digest)
	d.Reset()

	for i := 0; i < 4; i++ {
		from, to := 4*i, 4*(i+1)
		d.s[i] = binary.LittleEndian.Uint32(mac[from:to])
	}

	d.len = len
	return d
}

func (x challenge30) ForgeMessage(s *macMD4Server, message, suffix []byte) []byte {
	mac := s.sign(message)

	for keyLength := 1; ; keyLength++ {
		padding := x.forgePadding(keyLength, message)
		len := keyLength + len(message) + len(padding)

		h := x.forgeHash(mac, uint64(len))
		h.Write(suffix)

		var forged []byte
		forged = append(forged, message...)
		forged = append(forged, padding...)
		forged = append(forged, suffix...)

		if s.validate(forged, h.Sum(nil)) {
			return forged
		}
	}
}
