package main

import (
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

func encrypt(url string) string {
	// -----------------------------------

	//aes.NewCipher
}

func shorterUrl(w http.ResponseWriter, r *http.Request) {
	initial_url := r.URL.Query().Get("url")
	if initial_url == "" {
		http.Error(w, "URL is required", http.StatusBadRequest)
		return
	}

	encrypted_url := encrypt(initial_url)
}
