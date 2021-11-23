package set1_test

import (
	"bytes"
	set1 "cryptopals/set"
	"encoding/hex"
	"fmt"
	"testing"
)

func TestHexToBase64(t *testing.T) {

	input := "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
	expected := "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"
	observed := set1.HexToBase64(input)

	if observed != expected {
		t.Fatal(fmt.Sprintf("Expected %s, but got %s", expected, observed))
	}
}

func TestFixedXor(t *testing.T) {

	input := "1c0111001f010100061a024b53535009181c"
	key := "686974207468652062756c6c277320657965"
	expected := "746865206b696420646f6e277420706c6179"
	observed := set1.FixedXor(input, key)

	if observed != expected {
		t.Fatal(fmt.Sprintf("Expected %s, but got %s", expected, observed))
	}
}

func TestSingleXorCipher(t *testing.T) {

	input := "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
	var most_common_plaintext byte = ' '
	observed := set1.SingleXorDecrpytion(input, most_common_plaintext)

	t.Logf("Key is likely %x with most common char (%x)", observed, most_common_plaintext)

	b_len := len(input) / 2 // |input|//2 => 2 hex chars make up one byte

	encoded, _ := hex.DecodeString(set1.FixedXor(input, hex.EncodeToString(bytes.Repeat([]byte{observed}, b_len))))

	t.Log(string(encoded))
}
