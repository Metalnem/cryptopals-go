package cryptopals

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/subtle"

	"github.com/d1str0/pkcs7"
)

func pkcs7Pad(message []byte) []byte {
	message = message[:len(message):len(message)]
	padded, _ := pkcs7.Pad(message, aes.BlockSize)

	return padded
}

// AesCbcEncrypt encrypts the message using given key and random IV.
// IV is prepended to the ciphertext.
func AesCbcEncrypt(message, key []byte) []byte {
	padded := pkcs7Pad(message)
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
// IV and MAC are appended to the plaintext.
func CbcMacSign(message, key []byte, iv []byte) []byte {
	message = message[:len(message):len(message)]
	padded, _ := pkcs7.Pad(message, aes.BlockSize)
	ciphertext := make([]byte, len(padded))

	block, _ := aes.NewCipher(key)
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext[:], padded)

	size := len(message)
	msg := make([]byte, size+2*aes.BlockSize)
	mac := ciphertext[len(ciphertext)-aes.BlockSize:]

	copy(msg[:], message)
	copy(msg[size:], iv)
	copy(msg[size+aes.BlockSize:], mac)

	return msg
}

// CbcMacVerify verifies CBC-MAC for a given message.
// It assumes that IV and MAC are appended to the plaintext.
func CbcMacVerify(msg, key []byte) bool {
	size := len(msg) - 2*aes.BlockSize

	if size < 0 {
		return false
	}

	message := msg[0:size]
	iv := msg[size : size+aes.BlockSize]
	sig := CbcMacSign(message, key, iv)

	return subtle.ConstantTimeCompare(sig, msg) == 1
}

// CbcMacSignFixedIv calculates CBC-MAC for a given message using zero IV.
// MAC is appended to the plaintext.
func CbcMacSignFixedIv(message, key []byte) []byte {
	padded := pkcs7Pad(message)
	ciphertext := make([]byte, len(padded))

	block, _ := aes.NewCipher(key)
	iv := make([]byte, aes.BlockSize)

	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext[:], padded)
	mac := ciphertext[len(ciphertext)-aes.BlockSize:]

	return append(message[:len(message):len(message)], mac...)
}

// CbcMacVerifyFixedIv verifies CBC-MAC for a given message.
// It assumes that IV is zero and MAC is appended to the plaintext.
func CbcMacVerifyFixedIv(msg, key []byte) bool {
	size := len(msg) - aes.BlockSize

	if size < 0 {
		return false
	}

	message := msg[0:size]
	sig := CbcMacSignFixedIv(message, key)

	return subtle.ConstantTimeCompare(sig, msg) == 1
}
