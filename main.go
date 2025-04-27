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
	"strings"
	"sync"

	"github.com/joho/godotenv"
)

var (
	mu        sync.Mutex
	secretKey string

	urlStore    = make(map[string]string)
	lettersRune = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")
)

func main() {
	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error loading .env file")
	}

	secretKey = os.Getenv("SECRET_KEY")

	http.HandleFunc("/shorten", shorterUrl)
	http.HandleFunc("/", redirectHandler)

	fmt.Println("Server started at :8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
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

func decrypt(encrypted_url string) string {
	block, err := aes.NewCipher([]byte(secretKey))
	if err != nil {
		log.Fatal(err)
	}

	chiperText, err := hex.DecodeString(encrypted_url)
	if err != nil {
		log.Fatal(err)
	}

	iv := chiperText[:aes.BlockSize]
	chiperText = chiperText[aes.BlockSize:]

	stream := cipher.NewCTR(block, iv)
	stream.XORKeyStream(chiperText, chiperText)

	return string(chiperText)
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

func redirectHandler(w http.ResponseWriter, r *http.Request) {
	shortId := r.URL.Path[1:]

	mu.Lock()
	encryptedUrl, ok := urlStore[shortId]
	mu.Unlock()

	if !ok {
		http.Error(w, "URL not found", http.StatusNotFound)
		return
	}

	decryptedUrl := decrypt(encryptedUrl)
	http.Redirect(w, r, decryptedUrl, http.StatusFound)
}

func shorterUrl(w http.ResponseWriter, r *http.Request) {
	initial_url := r.URL.Query().Get("url")
	if initial_url == "" {
		http.Error(w, "URL is required", http.StatusBadRequest)
		return
	}

	// => Validate URL format (basic check)
	if !(strings.HasPrefix(initial_url, "http://") || strings.HasPrefix(initial_url, "https://")) {
		http.Error(w, "Invalid URL format. URL must start with http:// or https://", http.StatusBadRequest)

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
