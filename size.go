package cryptopals

type bitSize int
type byteSize int

func (size bitSize) toByteSize() byteSize {
	return byteSize(8 * size)
}

func (size byteSize) toBitSize() bitSize {
	return bitSize(size / 8)
}
