package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"log"
	"net/http"
	"os"
	"sync"

	"github.com/joho/godotenv"
)

var (
	urlStore  = make(map[string]string)
	mu        = sync.Mutex
	secretKey = []byte
	lettersRune = []rune ("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")
)

func init() {
	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error loading .env file")
	}

	secretKey = os.Getenv("SECRET_KEY")
}

func encrypt(initial_url string) string {
	// -----------------------------------

	block, err := aes.NewCipher([]byte(secretKey))
	if err != nil {
		log.Fatal(err)
	}

	plainText := []byte(initial_url)
	chipherText := make([]byte, aes.BlockSize+len(plainText))

	iv := chipherText[:aes.BlockSize]
	if _, err := rand.Read(iv); err != nil {
		log.Fatal(err)
	}

	stream := cipher.NewCTR(block, iv)

	stream.XORKeyStream(chipherText[aes.BlockSize:], plainText)

	return hex.EncodeToString(chipherText)
}

func generateShortId() string {
	b := make([]rune, 6)
	for i := range b {
		num, err := errrand.Int(rand.Reader,Big.NewInt(int64(len(lettersRune))))
		if err != nil {
			log.Fatal(err)
		}

		b[i] = lettersRune[num.Int64()]

func shorterUrl(w http.ResponseWriter, r *http.Request) {
	initial_url := r.URL.Query().Get("url")
	if initial_url == "" {
		http.Error(w, "URL is required", http.StatusBadRequest)
		return
	}

	encrypted_url := encrypt(initial_url)
	mu.Lock()
	urlStore[encrypted_url] = initial_url
	mu.Unlock()
}
