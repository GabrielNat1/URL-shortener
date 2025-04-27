package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/joho/godotenv"
	"golang.org/x/time/rate"
)

type IPRateLimiter struct {
	ips map[string]*rate.Limiter
	mu  sync.Mutex
	r   rate.Limit
	b   int
}

type URLStats struct {
	Visits    int       `json:"visits"`
	LastVisit time.Time `json:"last_visit"`
	UserAgent []string  `json:"user_agent"`
}

type Url struct {
	EncryptedURL string
	ExpiresAt    string
	Stats        URLStats
}

var (
	mu          sync.Mutex
	secretKey   string
	urlStore    = make(map[string]Url)
	lettersRune = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")
)

func NewIPRateLimiter(r rate.Limit, b int) *IPRateLimiter {
	return &IPRateLimiter{
		ips: make(map[string]*rate.Limiter),
		r:   r,
		b:   b,
	}
}

func (i *IPRateLimiter) AddIP(ip string) *rate.Limiter {
	i.mu.Lock()
	defer i.mu.Unlock()

	limiter := rate.NewLimiter(i.r, i.b)
	i.ips[ip] = limiter
	return limiter
}

func (i *IPRateLimiter) GetIP(ip string) *rate.Limiter {
	i.mu.Lock()
	defer i.mu.Unlock()

	limiter, exists := i.ips[ip]
	if !exists {
		limiter = rate.NewLimiter(i.r, i.b)
		i.ips[ip] = limiter
	}
	return limiter
}

func rateLimitMiddleware(next http.HandlerFunc, limiter *IPRateLimiter) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ip := r.RemoteAddr
		limiter := limiter.GetIP(ip)

		if !limiter.Allow() {
			http.Error(w, "Too many requests", http.StatusTooManyRequests)
			return
		}

		next(w, r)
	}
}

func main() {
	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error loading .env file")
	}

	secretKey = os.Getenv("SECRET_KEY")
	if len(secretKey) != 16 && len(secretKey) != 24 && len(secretKey) != 32 {
		log.Fatal("SECRET_KEY must be 16, 24, or 32 bytes long")
	}

	limiter := NewIPRateLimiter(1, 5)

	cleanupExpiredUrls()

	http.HandleFunc("/shorten", rateLimitMiddleware(shorterUrl, limiter))
	http.HandleFunc("/stats/", rateLimitMiddleware(statsHandler, limiter))
	http.HandleFunc("/", rateLimitMiddleware(redirectHandler, limiter))

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
	cipherText := make([]byte, aes.BlockSize+len(plainText))

	iv := cipherText[:aes.BlockSize]
	if _, err := rand.Read(iv); err != nil {
		log.Fatal(err)
	}

	stream := cipher.NewCTR(block, iv)

	stream.XORKeyStream(cipherText[aes.BlockSize:], plainText)

	return hex.EncodeToString(cipherText)
}

func decrypt(encrypted_url string) string {
	block, err := aes.NewCipher([]byte(secretKey))
	if err != nil {
		log.Fatal(err)
	}

	cipherText, err := hex.DecodeString(encrypted_url)
	if err != nil {
		log.Fatal(err)
	}

	iv := cipherText[:aes.BlockSize]
	cipherText = cipherText[aes.BlockSize:]

	stream := cipher.NewCTR(block, iv)
	stream.XORKeyStream(cipherText, cipherText)

	return string(cipherText)
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
	urlEntry, ok := urlStore[shortId]
	expiresAt, err := time.Parse(time.RFC3339, urlEntry.ExpiresAt)
	if err != nil {
		http.Error(w, "Invalid expiration format", http.StatusInternalServerError)
		return
	}

	if ok && time.Now().After(expiresAt) {
		delete(urlStore, shortId)
		mu.Unlock()
		http.Error(w, "URL has expired", http.StatusGone)
		return
	}

	if !ok {
		http.Error(w, "URL not found", http.StatusNotFound)
		return
	}

	// Update stats
	urlEntry.Stats.Visits++
	urlEntry.Stats.LastVisit = time.Now()
	userAgent := r.UserAgent()
	if !contains(urlEntry.Stats.UserAgent, userAgent) {
		urlEntry.Stats.UserAgent = append(urlEntry.Stats.UserAgent, userAgent)
	}

	urlStore[shortId] = urlEntry
	mu.Unlock()

	/* Redirect to the original URL
	   Decrypt the URL before redirecting */
	decryptedUrl := decrypt(urlEntry.EncryptedURL)
	http.Redirect(w, r, decryptedUrl, http.StatusFound)
}

func cleanupExpiredUrls() {
	ticker := time.NewTicker(10 * time.Minute)
	go func() {
		for range ticker.C {
			mu.Lock()
			for id, entry := range urlStore {
				expiresAt, _ := time.Parse(time.RFC3339, entry.ExpiresAt)
				if time.Now().After(expiresAt) {
					delete(urlStore, id)
				}
			}
			mu.Unlock()
		}
	}()
}

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return s == item
		}
	}
	return false
}

func statsHandler(w http.ResponseWriter, r *http.Request) {
	shortId := r.URL.Path[1:]

	mu.Lock()
	urlEntry, ok := urlStore[shortId]
	mu.Unlock()

	if !ok {
		http.Error(w, "URL not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	stats := struct {
		ShortURL   string    `json:"short_url"`
		Visits     int       `json:"visits"`
		LastVisit  time.Time `json:"last_visit"`
		UserAgent  []string  `json:"user_agent"`
		Expiration string    `json:"expiration"`
	}{
		ShortURL:   fmt.Sprintf("http://localhost:8080/%s", shortId),
		Visits:     urlEntry.Stats.Visits,
		LastVisit:  urlEntry.Stats.LastVisit,
		UserAgent:  urlEntry.Stats.UserAgent,
		Expiration: urlEntry.ExpiresAt,
	}

	json.NewEncoder(w).Encode(stats)
}

func shorterUrl(w http.ResponseWriter, r *http.Request) {
	initial_url := r.URL.Query().Get("url")

	expirationStr := r.URL.Query().Get("expires_at")
	expirationMinutes := 24 * 60

	if expirationStr != "" {
		parsed, err := strconv.Atoi(expirationStr)
		if err == nil && parsed > 0 {
			expirationMinutes = parsed
		}
	}

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
	expiresAt := time.Now().Add(time.Duration(expirationMinutes) * time.Minute).Format(time.RFC3339)

	mu.Lock()
	urlStore[short_id] = Url{
		EncryptedURL: encrypted_url,
		ExpiresAt:    expiresAt,
	}
	mu.Unlock()

	shortUrl := fmt.Sprintf("http://localhost:8080/%s", short_id)
	/*w.Write([]byte(shortUrl))
	  fmt.Fprintf(w, "This is the shortened : %s", shortUrl) */

	fmt.Fprintf(w, "This is the shortened URL: %s (expires in %d minutes)", shortUrl, expirationMinutes)
}
