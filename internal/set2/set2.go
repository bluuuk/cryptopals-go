package set

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
	insecureRand "math/rand"
)

func PCKS7Padding(input []byte) []byte {
	return PCKS7PaddingVarBlockLen(input, 16)
}

func PCKS7PaddingVarBlockLen(input []byte, blocklength int) []byte {

	if blocklength < 1 {
		return []byte{}
	}

	if l := len(input); l%blocklength == 0 {
		return append(input, bytes.Repeat([]byte{byte(blocklength)}, blocklength)...)
	} else {
		return append(input, bytes.Repeat([]byte{byte(blocklength - l%blocklength)}, blocklength-l%blocklength)...)
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

	for i := range res {
		res[i] = a[i] ^ b[i]
	}

	return res
}

func CBCEncrypt(input, key []byte) []byte {

	c, err := aes.NewCipher(key)

	if err != nil {
		panic(fmt.Sprintf("Could not create AES-Cipher with key [%x] (%d)", key, len(key)))
	}

	blocksize := c.BlockSize()
	padded := PCKS7PaddingVarBlockLen(input, blocksize)
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

func CBCDecrypt(input, key []byte) ([]byte, error) {

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
		return plaintext[:len(plaintext)-int(pad_val)], nil
	} else {
		return plaintext, errors.New("invalid padding")
	}

}

func generateSecureRandomNumber(nonInclusiveUpperBound int) int {

	choice, err := rand.Int(rand.Reader, big.NewInt(int64(nonInclusiveUpperBound)))

	if err != nil {
		panic("Not enough randomness, retry")
	}
	return int(choice.Int64())
}

func ECBorCBC(plaintext []byte) (ciphertext []byte, isECB bool) {

	isECB = generateSecureRandomNumber(2) == 0
	key := make([]byte, 16)

	if _, err := rand.Reader.Read(key); err != nil {
		panic("Not enough randomness")
	}

	randomSuffix := make([]byte, generateSecureRandomNumber(5+1)+5)
	randomPrefix := make([]byte, generateSecureRandomNumber(5+1)+5)

	if _, err := rand.Reader.Read(randomSuffix); err != nil {
		panic("Not enough randomness")
	}

	if _, err := rand.Reader.Read(randomPrefix); err != nil {
		panic("Not enough randomness")
	}

	aes, err := aes.NewCipher(key)

	if err != nil {
		panic("AES not available with key size 16")
	}

	blocksize := aes.BlockSize()
	paddedPlaintext := PCKS7Padding(append(append(randomPrefix, plaintext...), randomSuffix...))
	ciphertextLength := len(paddedPlaintext)
	ciphertext = make([]byte, len(paddedPlaintext))

	if isECB {

		for i := 0; i < ciphertextLength; i += blocksize {
			aes.Encrypt(ciphertext[i:i+blocksize], paddedPlaintext[i:i+blocksize])
		}

	} else {

		iv := make([]byte, blocksize)
		if _, err := rand.Reader.Read(iv); err != nil {
			panic("Not enough randomness")
		}

		cbc := cipher.NewCBCEncrypter(aes, iv)
		cbc.CryptBlocks(ciphertext, paddedPlaintext)
		ciphertext = append(iv, ciphertext...)
	}

	return ciphertext, isECB

}

func ByteAtATimeECBOracleFactory(prefix []byte, unkownString []byte, shufflePrefix bool) func([]byte) []byte {

	key := make([]byte, 16)

	if _, err := rand.Reader.Read(key); err != nil {
		panic("Not enough randomness")
	}

	return func(input []byte) []byte {

		aes, err := aes.NewCipher(key)

		if err != nil {
			panic("AES not available with key size 16")
		}

		if shufflePrefix {
			insecureRand.Shuffle(len(prefix), func(i, j int) { prefix[i], prefix[j] = prefix[j], prefix[i] })
		}

		paddedPrefixedPlaintext := PCKS7Padding(append(append(prefix, input...), unkownString...))

		ciphertextLength := len(paddedPrefixedPlaintext)
		ciphertext := make([]byte, ciphertextLength)
		blocksize := aes.BlockSize()

		for i := 0; i < ciphertextLength; i += blocksize {
			aes.Encrypt(ciphertext[i:i+blocksize], paddedPrefixedPlaintext[i:i+blocksize])
		}

		return ciphertext

	}
}
