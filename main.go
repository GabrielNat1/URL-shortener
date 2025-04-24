package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"os"
	"sync"

	"github.com/joho/godotenv"
)

var (
	mu        sync.Mutex
	secretKey string

	urlStore    = make(map[string]string)
	lettersRune = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")
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
		num, err := rand.Int(rand.Reader, big.NewInt(int64(len(lettersRune))))
		if err != nil {
			log.Fatal(err)
		}

		b[i] = lettersRune[num.Int64()]
	}

	return string(b)
}

func shorterUrl(w http.ResponseWriter, r *http.Request) {
	initial_url := r.URL.Query().Get("url")
	if initial_url == "" {
		http.Error(w, "URL is required", http.StatusBadRequest)
		return
	}

	encrypted_url := encrypt(initial_url)
	short_id := generateShortId()
	mu.Lock()
	urlStore[short_id] = encrypted_url
	mu.Unlock()

	shortUrl := fmt.Sprintf("http://localhost:8080/%s", short_id)
	//w.Write([]byte(shortUrl))
	fmt.Fprintf(w, "This is the shortened : %s", shortUrl)
}
