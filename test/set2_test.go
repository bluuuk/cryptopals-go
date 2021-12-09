package set1_test

import (
	"bufio"
	"bytes"
	"cryptopals/set"
	"encoding/base64"
	"fmt"
	"os"
	"strings"
	"testing"
)

func TestVarPadding(t *testing.T) {

	input := []byte("YELLOW SUBMARINE")
	expected := []byte("YELLOW SUBMARINE\x04\x04\x04\x04")

	if observed := set.PCKS7PaddingVarBlockLen(input, 20); !bytes.Equal(observed, expected) {
		t.Fatal(fmt.Sprintf("Expected %s, but got %s", expected, observed))
	}
}

func TestPadNewBlock(t *testing.T) {

	input := []byte("YELLOW SUBMARINE")

	if observed := set.PCKS7PaddingVarBlockLen(input, len(input)); len(observed) != 2*len(input) {
		t.Fatal(fmt.Sprintf("Got %s", observed))
	}
}

func TestCBC1(t *testing.T) {

	key := []byte("YELLOW SUBMARINE")
	input := []byte("SUBMARINE")

	if err, decenc := set.CBCDecrypt(set.CBCEncrypt(input, key), key); err != nil && !bytes.Equal(input, decenc) {
		t.Fatal(fmt.Sprintf("Expected %s - [%x], but got %s - [%x]", input, input, decenc, decenc))
	}

}

func TestCBC2(t *testing.T) {

	key := []byte("YELLOW SUBMARINE")
	input := []byte("")

	if err, decenc := set.CBCDecrypt(set.CBCEncrypt(input, key), key); err != nil || !bytes.Equal(input, decenc) {
		t.Fatal(fmt.Sprintf("Expected %s - [%x], but got %s - [%x]", input, input, decenc, decenc))
	}

}

func TestCBCDecryptOracle(t *testing.T) {

	key := []byte("YELLOW SUBMARINE")
	input := []byte("01234567012345670123456701234567")

	if err, decenc := set.CBCDecrypt(input, key); err == nil {
		t.Fatal(fmt.Sprintf("got [%x] but we have bad padding %s", decenc, err))
	}

}

func TestCBCDecryptFile(t *testing.T) {

	key := []byte("YELLOW SUBMARINE")
	iv := bytes.Repeat([]byte{0}, 16)

	f, err := os.Open("set2-ch2.txt")

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

	err, dec := set.CBCDecrypt(ciphertext, key)
	if err != nil {
		t.Fatal("Could not decrypt")
	}

	t.Log(string(dec))

}
