package set

import (
	"bytes"
	"crypto/aes"
	"errors"
	"fmt"
	"math/rand"
)

func PCKS7Padding(input []byte, blocklength int) []byte {
	return PCKS7PaddingVarBlockLen(input, 16)
}

func PCKS7PaddingVarBlockLen(input []byte, blocklength int) []byte {
	if l := len(input); l%blocklength == 0 {
		return append(input, bytes.Repeat([]byte{byte(blocklength)}, blocklength)...)
	} else {
		return append(input, bytes.Repeat([]byte{byte(blocklength - l)}, blocklength-l)...)
	}
}

func XOR(a, b []byte) (res []byte) {
	length := 0

	if l1, l2 := len(a), len(b); l1 > l2 {
		length = l2
	} else {
		length = l1
	}

	res = make([]byte, length)

	for i, _ := range res {
		res[i] = a[i] ^ b[i]
	}

	return
}

func CBCEncrypt(input, key []byte) []byte {

	c, err := aes.NewCipher(key)

	if err != nil {
		panic(fmt.Sprintf("Could not create AES-Cipher with key [%x] (%d)", key, len(key)))
	}

	blocksize := c.BlockSize()
	padded := PCKS7Padding(input, blocksize)
	// space for IV and padding
	ciphertext := make([]byte, len(padded)+blocksize)
	rand.Read(ciphertext[:blocksize])

	for processed := blocksize; processed < len(ciphertext); processed += blocksize {
		prev := ciphertext[processed-blocksize : processed]
		block := padded[processed-blocksize : processed]
		xored := XOR(prev, block)
		c.Encrypt(ciphertext[processed:processed+blocksize], xored)
	}
	return ciphertext
}

func CBCDecrypt(input, key []byte) (error, []byte) {

	c, err := aes.NewCipher(key)

	if err != nil {
		panic(fmt.Sprintf("Could not create AES-Cipher with key [%x] (%d)", key, len(key)))
	}

	blocksize := c.BlockSize()
	plaintext := make([]byte, len(input)-blocksize)

	if len(input)%blocksize > 0 || len(input) < 32 {
		panic(fmt.Sprintf("Input size of %d not a multiple of %d or to small", len(input), blocksize))
	}

	// start afer the iv
	for processed := blocksize; processed < len(input); processed += blocksize {
		previous := input[processed-blocksize : processed]

		c.Decrypt(plaintext[processed-blocksize:processed],
			input[processed:processed+blocksize])

		copy(plaintext[processed-blocksize:processed],
			XOR(previous, plaintext[processed-blocksize:processed]))
	}

	pad_val := plaintext[len(plaintext)-1]
	padding := bytes.Repeat([]byte{pad_val}, int(pad_val))

	if pad_val <= byte(blocksize) && bytes.HasSuffix(plaintext, padding) {
		return nil, plaintext[:len(plaintext)-int(pad_val)]
	} else {
		return errors.New("invalid padding"), plaintext
	}

}
