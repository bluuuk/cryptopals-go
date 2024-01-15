package set

import (
	"crypto/aes"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
)

type CutAndPasteHandler struct {
	key      []byte
	profiles map[string]Profile
}

type Profile struct {
	email []byte
	id    int
	role  string
}

func (cp *CutAndPasteHandler) profileFor(w http.ResponseWriter, r *http.Request) {

	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	values := r.URL.Query()
	email := values.Get("email")
	realMail, err := hex.DecodeString(email)
	email = string(realMail)

	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	profile, ok := cp.profiles[email]

	if !ok {
		profile = Profile{
			email: realMail,
			id:    len(cp.profiles),
			role:  "guest",
		}
		cp.profiles[email] = profile
	}

	payload := append([]byte("email="), realMail...)
	payload = append(payload, []byte(fmt.Sprintf("&id=%d&role=%s", profile.id, profile.role))...)

	aes, err := aes.NewCipher(cp.key)

	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	blocksize := aes.BlockSize()
	paddedPlaintext := PCKS7Padding([]byte(payload))
	ciphertextLength := len(paddedPlaintext)
	ciphertext := make([]byte, len(paddedPlaintext))

	for i := 0; i < ciphertextLength; i += blocksize {
		aes.Encrypt(ciphertext[i:i+blocksize], paddedPlaintext[i:i+blocksize])
	}

	w.Header().Add("Content-Type", "application/octet-stream")
	if _, err := w.Write(ciphertext); err != nil {
		log.Print(err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
}

func (cp *CutAndPasteHandler) isAdmin(w http.ResponseWriter, r *http.Request) {

	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	ciphertext, err := io.ReadAll(r.Body)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	aes, err := aes.NewCipher(cp.key)

	if err != nil || len(ciphertext) == 0 {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	blocksize := aes.BlockSize()
	ciphertextLength := len(ciphertext)
	plaintext := make([]byte, len(ciphertext))

	for i := 0; i < ciphertextLength; i += blocksize {
		aes.Decrypt(plaintext[i:i+blocksize], ciphertext[i:i+blocksize])
	}

	padding := int(plaintext[len(plaintext)-1])
	plaintext = plaintext[:len(plaintext)-padding]

	parsed, err := url.ParseQuery(string(plaintext))

	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	switch parsed.Get("role") {
	case "admin":
		w.WriteHeader(http.StatusAccepted)
	case "guest":
		w.WriteHeader(http.StatusForbidden)
	case "":
		w.WriteHeader(http.StatusBadRequest)
	}
}

func CreateHandler() *http.ServeMux {

	key := make([]byte, 16)

	if _, err := rand.Reader.Read(key); err != nil {
		panic("Not enough randomness")
	}

	handler := CutAndPasteHandler{
		key:      key,
		profiles: make(map[string]Profile),
	}

	mux := http.NewServeMux()

	mux.HandleFunc("/isAdmin", handler.isAdmin)
	mux.HandleFunc("/profileFor", handler.profileFor)

	return mux
}
