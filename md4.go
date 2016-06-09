package main

import (
	"hash"
)

const (
	_A = 0x67452301
	_B = 0xefcdab89
	_C = 0x98badcfe
	_D = 0x10325476
)

// Size represents the size of MD4 checksum in bytes.
const Size = 16

// BlockSize represents the block size of MD4 function in bytes.
const BlockSize = 64

type digest struct {
	buffer [4]uint32
}

// New returns a new hash.Hash computing the MD4 checksum.
func New() hash.Hash {
	d := new(digest)
	d.Reset()

	return d
}

func (d *digest) Write(p []byte) (int, error) {
	return 0, nil
}

func (d *digest) Sum(b []byte) []byte {
	return nil
}

func (d *digest) Reset() {
	d.buffer[0] = _A
	d.buffer[1] = _B
	d.buffer[2] = _C
	d.buffer[3] = _D
}

func (d *digest) Size() int {
	return Size
}

func (d *digest) BlockSize() int {
	return BlockSize
}

func f(x, y, z uint32) uint32 {
	return (x & y) | (^x & z)
}

func g(x, y, z uint32) uint32 {
	return (x & y) | (x & z) | (y & z)
}

func h(x, y, z uint32) uint32 {
	return x ^ y ^ z
}
