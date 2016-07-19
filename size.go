package cryptopals

type bitSize int
type byteSize int

func (size bitSize) toByteSize() byteSize {
	return byteSize(size / 8)
}

func (size byteSize) toBitSize() bitSize {
	return bitSize(8 * size)
}
