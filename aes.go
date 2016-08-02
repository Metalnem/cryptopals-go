package cryptopals

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/subtle"

	"github.com/d1str0/pkcs7"
)

// AesCbcEncrypt encrypts the message using given key and random IV.
// IV is prepended to the ciphertext.
func AesCbcEncrypt(message, key []byte) []byte {
	padded, _ := pkcs7.Pad(message, aes.BlockSize)
	ciphertext := make([]byte, aes.BlockSize+len(padded))

	iv := ciphertext[0:aes.BlockSize]
	rand.Read(iv)

	block, _ := aes.NewCipher(key)
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext[aes.BlockSize:], padded)

	return ciphertext
}

// AesCbcDecrypt decrypts the ciphertext using given key.
// It assumes that IV is prepended to the ciphertext.
func AesCbcDecrypt(ciphertext, key []byte) []byte {
	iv := ciphertext[0:aes.BlockSize]
	message := make([]byte, len(ciphertext)-len(iv))

	block, _ := aes.NewCipher(key)
	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(message, ciphertext[aes.BlockSize:])
	unpadded, _ := pkcs7.Unpad(message)

	return unpadded
}

// CbcMacSign calculates CBC-MAC for a given message.
func CbcMacSign(message, key []byte, iv []byte) []byte {
	padded, _ := pkcs7.Pad(message, aes.BlockSize)
	ciphertext := make([]byte, len(padded))

	block, _ := aes.NewCipher(key)
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext[:], padded)

	return ciphertext[len(ciphertext)-aes.BlockSize:]
}

// CbcMacVerify verifies CBC-MAC for a given message.
func CbcMacVerify(msg, key []byte) bool {
	size := len(msg) - 2*aes.BlockSize

	if size < 0 {
		return false
	}

	message := msg[0:size]
	iv := msg[size : size+aes.BlockSize]
	mac := msg[size+aes.BlockSize : size+2*aes.BlockSize]

	return subtle.ConstantTimeCompare(CbcMacSign(message, key, iv), mac) == 1
}
