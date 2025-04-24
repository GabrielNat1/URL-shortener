package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"log"
	"net/http"
	"os"

	"github.com/joho/godotenv"
)

var (
	urlStore  = make(map[string]string)
	secretKey string
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
}

func shorterUrl(w http.ResponseWriter, r *http.Request) {
	initial_url := r.URL.Query().Get("url")
	if initial_url == "" {
		http.Error(w, "URL is required", http.StatusBadRequest)
		return
	}

	encrypted_url := encrypt(initial_url)
}
