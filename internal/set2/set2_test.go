package set_test

import (
	"bufio"
	"bytes"
	set "cryptopals/internal/set2"
	"encoding/base64"
	"fmt"
	"os"
	"reflect"
	"strings"
	"testing"
)

func TestVarPadding(t *testing.T) {

	input := []byte("YELLOW SUBMARINE")
	expected := []byte("YELLOW SUBMARINE\x04\x04\x04\x04")

	if observed := set.PCKS7PaddingVarBlockLen(input, 20); !bytes.Equal(observed, expected) {
		t.Fatalf("Expected %s, but got %s", expected, observed)
	}
}

func TestPCKS7PaddingVarBlockLen(t *testing.T) {
	tests := []struct {
		name        string
		input       []byte
		blocklength int
		want        []byte
	}{
		{
			name:        "happy path empty",
			input:       []byte{},
			blocklength: 16,
			want:        bytes.Repeat([]byte{16}, 16),
		},
		{
			name:        "happy path half",
			input:       bytes.Repeat([]byte{16}, 16),
			blocklength: 16,
			want:        bytes.Repeat([]byte{16}, 32),
		}, {
			name:        "happy path full",
			input:       bytes.Repeat([]byte{8}, 8),
			blocklength: 16,
			want:        bytes.Repeat([]byte{8}, 16),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := set.PCKS7PaddingVarBlockLen(tt.input, tt.blocklength); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("PCKS7PaddingVarBlockLen() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestPadNewBlock(t *testing.T) {

	input := []byte("YELLOW SUBMARINE")

	if observed := set.PCKS7PaddingVarBlockLen(input, len(input)); len(observed) != 2*len(input) {
		t.Fatalf("Got %s", observed)
	}
}

func TestCBC1(t *testing.T) {

	key := []byte("YELLOW SUBMARINE")
	input := []byte("SUBMARINE")

	if decenc, err := set.CBCDecrypt(set.CBCEncrypt(input, key), key); err != nil && !bytes.Equal(input, decenc) {
		t.Fatalf("Expected %s - [%x], but got %s - [%x]", input, input, decenc, decenc)
	}

}

func TestCBC2(t *testing.T) {

	key := []byte("YELLOW SUBMARINE")
	input := []byte("")

	if decenc, err := set.CBCDecrypt(set.CBCEncrypt(input, key), key); err != nil || !bytes.Equal(input, decenc) {
		t.Fatalf("Expected %s - [%x], but got %s - [%x]", input, input, decenc, decenc)
	}

}

func TestCBCDecryptOracle(t *testing.T) {

	key := []byte("YELLOW SUBMARINE")
	input := []byte("01234567012345670123456701234567")

	if decenc, err := set.CBCDecrypt(input, key); err == nil {
		t.Fatalf("got [%x] but we have bad padding %s", decenc, err)
	}

}

func TestCBCDecryptFile(t *testing.T) {

	key := []byte("YELLOW SUBMARINE")
	iv := bytes.Repeat([]byte{0}, 16)
	f, err := os.Open("testdata/set2-ch2.txt")

	if err != nil {
		panic("Could not open file")
	}

	defer f.Close()

	reader := bufio.NewScanner(f)
	reader.Split(bufio.ScanLines)

	var sb strings.Builder

	for reader.Scan() {
		sb.WriteString(reader.Text())
	}

	ciphertext, _ := base64.RawStdEncoding.DecodeString(sb.String())
	ciphertext = append(iv, ciphertext...)

	dec, err := set.CBCDecrypt(ciphertext, key)
	if err != nil {
		t.Fatal("Could not decrypt")
	}

	t.Log(string(dec))

}

func TestECBorCBCOracle(t *testing.T) {

	tries := 1000
	sucess := 0

	for i := 0; i < tries; i++ {

		/*
			According to `https://cryptopals.com/sets/2/challenges/11`, it is said that the oracle
			> Under the hood, have the function append 5-10 bytes (count chosen randomly) before the plaintext and 5-10 bytes after the plaintext.

			We can mount two attack:
			1. Length wise
				Assume we had a empty plaintext, it's length is between 10 and 20 bytes. After padding, we have 16 or 32.

				For ECB, we always have 1 or 2 blocks ciphertext
				For CBC, we always have 2 or 3 blocks ciphertext due to the IV

				So we can guess based on the length with probability > 1/2 but we still need to guess when it is 2 blocks ciphertext
			2. Repetive ECB abuse

				We assume that the first, second and last block are to no interest due the random suffix, prefix and iv. We choose a
				reapeating plaintext(PL1=PL2=PL3=PL4=PL5) such that we have the following setup:

				ECB : C=|PREFIX + PL1	|PL2			|PL3|PL4|PL5 + SUFFIX + PADDING|(PADDING)|
				CBC : C=|IV				|PREFIX + PL1	|PL2|PL3|PL4|PL5 + SUFFIX + PADDING|(PADDING)|

				Therefore, we are in ECB mode if C3 == C4. If it unlikely, that both are the same in CBC (around 1/256 <= 0.004)

				To not worry about padding and the prefix and suffix, let's calculate the plaintext size:

				Force a new block with 11 A'S to have at least two blocks. However, due to the IV, we need 3 blocks
				PL = PREFIX ~|~ A*(16-5=11) || A*16 || A*16 || A*16


		*/
		plaintext := bytes.Repeat([]byte("\x00"), 11+16*3)
		ciphertext, isECB := set.ECBorCBC(plaintext)

		if bytes.Equal(ciphertext[2*16:3*16], ciphertext[3*16:4*16]) == isECB {
			sucess += 1
		}

	}

	ratio := float32(sucess) / float32(tries)
	t.Logf("Won this sucess rate of %f", ratio)

	if ratio < 1-0.004 {
		t.Errorf("Winning ratio to low %f", ratio)
	}

}

func TestByteAtATimeECBOracle(t *testing.T) {

	unkownString, err := base64.StdEncoding.DecodeString(
		"Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg" +
			"aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq" +
			"dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg" +
			"YnkK",
	)

	if err != nil {
		t.Error(err)
	}

	oracle := set.ByteAtATimeECBOracleFactory(unkownString)
	fmt.Print(string(unkownString))
	fmt.Print(err)

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

	t.Logf("Determined blocksize %d", blocksize)

	unkownStringLength := startLength - prefixLengthForcePaddingBlock

	if len(unkownString) != unkownStringLength {
		t.Errorf("Unkown string length: Have %d Want %d", unkownStringLength, len(unkownString))
	}

	unkownStringLengthBlocks := startLength / blocksize
	guessedUnkownString := set.NewSlidingBuffer(bytes.Repeat([]byte("\x00"), blocksize-1), blocksize-1)

mainloop:
	for currentBlockCounter := 0; currentBlockCounter < unkownStringLengthBlocks; currentBlockCounter++ {
		for currentBytePosition := 15; currentBytePosition > -1; currentBytePosition-- {
			comparisionBlock := oracle(bytes.Repeat([]byte("\x00"), currentBytePosition))[currentBlockCounter*16 : (currentBlockCounter+1)*16]

			currentPayload, err := guessedUnkownString.Window()

			if err != nil {
				t.Fatal("insuficient learned bytes")
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
				t.Fatal("Not enough bytes")
			}
		}
	}

	// ignore written zeros
	result := guessedUnkownString.GetBuffer()[blocksize-1 : unkownStringLength+blocksize-1]
	t.Log(string(result))
	if !bytes.Equal(result, unkownString) {
		t.Error("Did not decrypt sucessfully")
	}
}
