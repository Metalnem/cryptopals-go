// Challenge 44 - DSA nonce recovery from repeated nonce
// http://cryptopals.com/sets/6/challenges/44

package cryptopals

import (
	"bufio"
	"errors"
	"math/big"
	"os"
	"strings"
)

type challenge44 struct {
}

type dsaMessage struct {
	msg string
	s   *big.Int
	r   *big.Int
	m   *big.Int
}

func (challenge44) readMessages() []dsaMessage {
	file, _ := os.Open("challenge44.txt")
	defer file.Close()

	scanner := bufio.NewScanner(file)

	var buffer []string
	var messages []dsaMessage

	for scanner.Scan() {
		value := strings.Split(scanner.Text(), ": ")[1]
		buffer = append(buffer, value)

		if len(buffer) == 4 {
			s, _ := new(big.Int).SetString(buffer[1], 10)
			r, _ := new(big.Int).SetString(buffer[2], 10)
			m, _ := new(big.Int).SetString(buffer[3], 16)

			message := dsaMessage{msg: buffer[0], s: s, r: r, m: m}
			messages = append(messages, message)

			buffer = nil
		}
	}

	return messages
}

func (x challenge44) RecoverDsaKeyFromRepeatedNonce(pub *dsaPublicKey) (*dsaPrivateKey, error) {
	messages := x.readMessages()

	for i := 0; i < len(messages); i++ {
		for j := i + 1; j < len(messages); j++ {
			if messages[i].r.Cmp(messages[j].r) == 0 {
				r := messages[i].r
				m1, m2 := messages[i].m, messages[j].m
				s1, s2 := messages[i].s, messages[j].s

				mDiff := new(big.Int).Sub(m1, m2)
				mDiff = mDiff.Mod(mDiff, pub.q)

				sDiff := new(big.Int).Sub(s1, s2)
				sDiff = sDiff.Mod(sDiff, pub.q)

				k := mDiff.Mul(mDiff, sDiff.ModInverse(sDiff, pub.q))
				k = k.Mod(k, pub.q)

				x := new(big.Int).Mul(s1, k)
				x = x.Sub(x, m1).Mod(x, pub.q)
				x = x.Mul(x, new(big.Int).ModInverse(r, pub.q))
				x = x.Mod(x, pub.q)

				return &dsaPrivateKey{dsaPublicKey: *pub, x: x}, nil
			}
		}
	}

	return nil, errors.New("Failed to recover DSA private key from repeated nonce")
}
