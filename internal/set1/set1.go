package set

import (
	"crypto/aes"
	"encoding/base64"
	"encoding/hex"
	"fmt"
)

func HexToBase64(s string) string {
	bytes, _ := hex.DecodeString(s)
	return base64.RawStdEncoding.EncodeToString(bytes)
}

func FixedXor(message, key string) string {
	key_bytes, e2 := hex.DecodeString(key)
	message_bytes, e1 := hex.DecodeString(message)

	if e1 != nil || e2 != nil || len(message_bytes) != len(key_bytes) {
		return ""
	} else {
		arr_len := len(message_bytes)
		output_bytes := make([]byte, arr_len)

		for i, value := range message_bytes {
			output_bytes[i] = value ^ key_bytes[i]
		}

		return hex.EncodeToString(output_bytes)
	}
}

func SingleXorDecrpytion(message string, mostcommon byte) byte {

	/*
		we have prior knowledge that the message is in english
	*/

	message_bytes, _ := hex.DecodeString(message)

	frequency_map := make(map[byte]int)

	for _, b := range message_bytes {
		frequency_map[b] = frequency_map[b] + 1
	}

	// https://stackoverflow.com/questions/62055988/golang-a-map-interface-how-to-print-key-and-value
	// just a dirty way to spit out the map fast
	//bs, _ := json.Marshal(frequency_map)
	//fmt.Println(string(bs))

	var best byte = 0
	var high int = 0

	for key, val := range frequency_map {
		if val > high {
			best = key
			high = val
		}
	}

	/*
		the most frequent plaintext byte is likely an e or a space

		c = key xor 'e' => key = c xor 'e'
	*/

	return mostcommon ^ best
}

func RepeatingXor(message, key []byte) []byte {

	output_bytes := make([]byte, len(message))

	for i, value := range message {
		output_bytes[i] = value ^ key[i%len(key)]
	}

	return output_bytes

}

func DecryptAESECB(message, key []byte) (res []byte) {

	cipher, err := aes.NewCipher(key)

	if err != nil {
		panic("Could not create cipher")
	}

	bs := cipher.BlockSize()

	if len(message)%bs > 0 {
		panic(fmt.Sprintf("Message size %d not a multiple of %d", len(message), bs))
	}

	res = make([]byte, len(message))

	for processed := 0; processed < len(message); processed += bs {
		cipher.Decrypt(res[processed:processed+bs], message[processed:processed+bs])
	}

	return

}

func DetectECB(ciphertext []byte, blocksize int) bool {
	// string is just a workaround, because go does not support []byte as keys
	hashset := make(map[string]bool)

	for processed := 0; processed < len(ciphertext); processed += blocksize {
		block := string(ciphertext[processed : processed+blocksize])
		if _, contains := hashset[block]; !contains {
			hashset[block] = true
		} else {
			return true
		}
	}

	return false
}
