package set_test

import (
	"bufio"
	"bytes"
	set "cryptopals/internal/set1"
	"encoding/base64"
	"encoding/hex"
	"os"
	"strings"
	"testing"
)

func TestHexToBase64(t *testing.T) {

	input := "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
	expected := "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"
	observed := set.HexToBase64(input)

	if observed != expected {
		t.Fatalf("Expected %s, but got %s", expected, observed)
	}
}

func TestFixedXor(t *testing.T) {

	input := "1c0111001f010100061a024b53535009181c"
	key := "686974207468652062756c6c277320657965"
	expected := "746865206b696420646f6e277420706c6179"
	observed := set.FixedXor(input, key)

	if observed != expected {
		t.Fatalf("Expected %s, but got %s", expected, observed)
	}
}

func TestSingleXorCipher(t *testing.T) {

	input := "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
	var most_common_plaintext byte = ' '
	observed := set.SingleXorDecrpytion(input, most_common_plaintext)

	t.Logf("Key is likely %x with most common char (%x)", observed, most_common_plaintext)

	b_len := len(input) / 2 // |input|//2 => 2 hex chars make up one byte

	encoded, _ := hex.DecodeString(set.FixedXor(input, hex.EncodeToString(bytes.Repeat([]byte{observed}, b_len))))

	t.Log(string(encoded))
}

func TestRepeatingXor(t *testing.T) {
	const (
		m1 = "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"
		c1 = "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"
	)

	type Pair struct {
		plaintext, ciphertext string
	}

	pairs := []Pair{
		{plaintext: m1, ciphertext: c1},
	}

	key := []byte("ICE")

	for _, pair := range pairs {
		expected, err := hex.DecodeString(pair.ciphertext)
		if enc := set.RepeatingXor([]byte(pair.plaintext), key); err != nil || !bytes.Equal(enc, expected) {
			t.Errorf("Failed for message `%s`, instead got `%s`", pair.plaintext, string(set.RepeatingXor(enc, key)))
		}
	}

}

func TestAesECB(t *testing.T) {

	key := []byte("YELLOW SUBMARINE")

	f, err := os.Open("testdata/set1-ch7.txt")

	if err != nil {
		panic("Could not open file testdata")
	}

	defer f.Close()

	reader := bufio.NewScanner(f)
	reader.Split(bufio.ScanLines)

	var sb strings.Builder

	for reader.Scan() {
		sb.WriteString(reader.Text())
	}

	text, _ := base64.RawStdEncoding.DecodeString(sb.String())
	plaintext := set.DecryptAESECB(text, key)

	t.Log(string(plaintext))

}

func TestAesECBDetector(t *testing.T) {
	f, err := os.Open("testdata/set1-ch8.txt")

	if err != nil {
		panic("Could not open file")
	}

	defer f.Close()

	reader := bufio.NewScanner(f)
	reader.Split(bufio.ScanLines)

	const blocksize = 16

	for i := 0; reader.Scan(); i++ {
		cipher_bytes, err := hex.DecodeString(reader.Text())

		if err == nil && set.DetectECB(cipher_bytes, blocksize) {
			t.Logf("Ciphertext %d is in ECB", i)
		}
	}
}
