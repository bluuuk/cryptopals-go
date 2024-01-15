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

func XOR(a, b []byte) []byte {

	min := len(a)
	if b := len(b); min > b {
		min = b
	}

	output := make([]byte, min)

	for i := range a {
		output[i] = a[i] ^ b[i]
	}

	return output
}

func PCKS7Padding(input []byte) []byte {
	return PCKS7PaddingVarBlockLen(input, 16)
}

func PCKS7Unpad(input []byte) ([]byte, error) {
	padding := input[len(input)-1]
	if !bytes.HasSuffix(input, bytes.Repeat([]byte{padding}, int(padding))) {
		return nil, errors.New("does not end with padding string")
	}

	if len(input) <= int(padding) {
		return nil, errors.New("padding too big")
	}

	return input[:len(input)-int(padding)], nil
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

func ByteAtATimeECBOracleSimple(oracle func([]byte) []byte) []byte {

	// determine blocksize
	emptyEncrpytion := oracle([]byte{})
	startLength := len(emptyEncrpytion)

	blocksize := 0
	prefixLengthForcePaddingBlock := 1

	for ; ; prefixLengthForcePaddingBlock++ {
		if testLength := len(oracle(bytes.Repeat([]byte("\x00"), prefixLengthForcePaddingBlock))) - startLength; testLength > 0 {
			blocksize = testLength
			break
		}
	}

	unkownStringLength := startLength - prefixLengthForcePaddingBlock
	unkownStringLengthBlocks := startLength / blocksize
	guessedUnkownString := NewSlidingBuffer(bytes.Repeat([]byte("\x00"), blocksize-1), blocksize-1)

mainloop:
	for currentBlockCounter := 0; currentBlockCounter < unkownStringLengthBlocks; currentBlockCounter++ {
		for currentBytePosition := 15; currentBytePosition > -1; currentBytePosition-- {
			comparisionBlock := oracle(bytes.Repeat([]byte("\x00"), currentBytePosition))[currentBlockCounter*16 : (currentBlockCounter+1)*16]

			currentPayload, err := guessedUnkownString.Window()

			if err != nil {
				break mainloop
			}

			var byteValue byte = 0
			circuitBreaker := false

			for ; byteValue != 255; byteValue++ {
				payload := append(currentPayload, byteValue)
				response := oracle(payload)[:16]
				if bytes.Equal(comparisionBlock, response) {
					circuitBreaker = true
					break
				}
			}

			if !circuitBreaker {
				break mainloop
			}

			guessedUnkownString.Append(byteValue)

			err = guessedUnkownString.AdvanceWindow(1)

			if err != nil {
				break mainloop
			}
		}
	}

	// ignore written zeros
	return guessedUnkownString.GetBuffer()[blocksize-1 : unkownStringLength+blocksize-1]
}

func ByteAtATimeECBOracleHard(oracle func([]byte) []byte) []byte {

	// constant prefix, at most 4 blocks
	/*
		Variations:

		1. Changing but constant length prefix
			we would try to look when two constant blocks are changing to get the prefix length
			if the prefix length is recovered, we can fill up a space block with 0 such that we do not need to care about the prefix anymore
			-> This version supports this kind of prefix

		2. Completly changing prefix
			kinda hard, we would need to make repeated guesses
			-> This version does not support this kind of prefix
	*/

	// determine blocksize
	emptyEncrpytion := oracle([]byte{})
	startLength := len(emptyEncrpytion)

	blocksize := 0
	forcePaddingSize := 1

	for ; ; forcePaddingSize++ {
		if testLength := len(oracle(bytes.Repeat([]byte("\x00"), forcePaddingSize))) - startLength; testLength > 0 {
			blocksize = testLength
			break
		}
	}

	// determine prefix placement by forcing repeated blocks, we need 3 blocks of input to force it
	response := oracle(bytes.Repeat([]byte("\x00"), forcePaddingSize+3*blocksize))
	collisionIndex := 0

	//							   | <- collisionIndex
	// [PREFIX|PREFIX|PREFIX + 0000|00000|00000|SECRET]
	// we want to move the index back to infer the prefix length

	for ; collisionIndex < len(response)-2*blocksize; collisionIndex += blocksize {
		if bytes.Equal(
			response[collisionIndex:collisionIndex+blocksize],
			response[collisionIndex+blocksize:collisionIndex+2*blocksize],
		) {
			break
		}
	}

	comparisionBlock := response[collisionIndex : collisionIndex+blocksize]
	prefixLength := 0

	//						|prefix| <- collisionIndex
	// [PREFIX|PREFIX|PREFIX + 0000|00000|00000|SECRET]
	// we place a \x01 to see right after the prefix and move it to the right
	// in order to see at which point the prefix string with the input
	// does not change anymore. If we compare the block after the collision index,
	// we can even get the length if the prefix is changing!

	/*							|--COMPARE--|
	[PREFIX|PREFIX|PREFIX + 1000|00000|00000|SECRET]
	[PREFIX|PREFIX|PREFIX + 0100|00000|00000|SECRET]
	[PREFIX|PREFIX|PREFIX + 0010|00000|00000|SECRET]
	[PREFIX|PREFIX|PREFIX + 0001|00000|00000|SECRET]
	[PREFIX|PREFIX|PREFIX + 0000|10000|00000|SECRET]
	*/

	for ; prefixLength < blocksize; prefixLength++ {
		payload := append(bytes.Repeat([]byte("\x00"), prefixLength), []byte("\x01")...)
		// two block just to make sure we do not run into to short ciphertexts
		payload = append(payload, bytes.Repeat([]byte("\x00"), blocksize*2)...)

		if !bytes.Equal(comparisionBlock, oracle(payload)[collisionIndex:collisionIndex+blocksize]) {
			break
		}
	}

	prefixLength = collisionIndex - prefixLength

	// determine prefix length
	unkownStringLength := startLength - forcePaddingSize - prefixLength
	startblock := collisionIndex / blocksize
	// we want to start with a clean block, so we add pad the prefix
	nextBlockPadding := (blocksize - (prefixLength % blocksize))
	if nextBlockPadding == blocksize {
		nextBlockPadding = 0
	}

	// always assume padding
	unkownStringLengthBlocks := (unkownStringLength / blocksize) + 1
	guessedUnkownString := NewSlidingBuffer(bytes.Repeat([]byte("\x00"), blocksize-1+nextBlockPadding), blocksize-1+nextBlockPadding)

mainloop:
	for currentBlockCounter := startblock; currentBlockCounter < unkownStringLengthBlocks+startblock; currentBlockCounter++ {
		for currentBytePosition := 15; currentBytePosition > -1; currentBytePosition-- {
			comparisionBlock := oracle(bytes.Repeat([]byte("\x00"), currentBytePosition+nextBlockPadding))[currentBlockCounter*16 : (currentBlockCounter+1)*16]

			currentPayload, err := guessedUnkownString.Window()

			if err != nil {
				break mainloop
			}

			var byteValue byte = 0
			circuitBreaker := false

			for ; byteValue != 255; byteValue++ {
				payload := append(currentPayload, byteValue)
				response := oracle(payload)[collisionIndex : collisionIndex+blocksize]
				if bytes.Equal(comparisionBlock, response) {
					circuitBreaker = true
					break
				}
			}

			if !circuitBreaker {
				break mainloop
			}

			guessedUnkownString.Append(byteValue)

			err = guessedUnkownString.AdvanceWindow(1)

			if err != nil {
				break mainloop
			}
		}
	}

	// ignore written zeros
	return guessedUnkownString.GetBuffer()[blocksize-1+nextBlockPadding : unkownStringLength+blocksize-1+nextBlockPadding]
}
