package main

import (
	"net/http"
)

var (
	urlStore = make(map[string]string)
	secretKey = 
)

func encrypt(url string) string {
	//aes.NewCipher
}


func shorterUrl(w http.ResponseWriter, r *http.Request) {
	initial_url := r.URL.Query().Get("url")
	if initial_url== "" {
		http.Error(w, "URL is required", http.StatusBadRequest)
		return
	}

	encrypted_url := encrypt(initial_url)
}
