package cryptopals

import (
	"encoding/binary"
	"reflect"
	"testing"
)

func TestForgeMessage(t *testing.T) {
	server := &macMD4Server{
		key: []byte("We all live in a yellow submarine"),
	}

	message := []byte("comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon")
	suffix := []byte(";admin=true")

	size := len(server.key) + len(message)
	padding := make([]byte, 128-size)

	padding[0] = 0x80
	binary.LittleEndian.PutUint64(padding[len(padding)-8:], uint64(8*size))

	var expected []byte
	actual := challenge30{}.ForgeMessage(server, message, suffix)

	expected = append(expected, message...)
	expected = append(expected, padding...)
	expected = append(expected, suffix...)

	if !reflect.DeepEqual(expected, actual) {
		t.Errorf("Expected %v, was %v", expected, actual)
	}
}
