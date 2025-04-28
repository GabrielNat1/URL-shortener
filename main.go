package main

import (
	"compress/gzip"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/go-redis/redis/v8"
	"github.com/joho/godotenv"
	"golang.org/x/time/rate"
)

type Cache struct {
	client *redis.Client
}

type LoadBalancer struct {
	servers []*url.URL
	mu      sync.Mutex
	current int
}

type gzipResponseWriter struct {
	io.Writer
	http.ResponseWriter
}

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

	urlsCreated = promauto.NewCounter(prometheus.CounterOpts{
		Name: "url_shortener_urls_created_total",
		Help: "The total number of shortened URLs created",
	})

	urlRedirects = promauto.NewCounter(prometheus.CounterOpts{
		Name: "url_shortener_redirects_total",
		Help: "The total number of redirects performed",
	})

	activeUrls = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "url_shortener_active_urls",
		Help: "The current number of active shortened URLs",
	})

	rateLimitExceeded = promauto.NewCounter(prometheus.CounterOpts{
		Name: "url_shortener_rate_limit_exceeded_total",
		Help: "The total number of rate limit exceeded events",
	})
)

func NewCache(Addr string) *Cache {
	client := redis.NewClient(&redis.Options{
		Addr:         Addr,
		PoolSize:     10,
		MinIdleConns: 5,
	})

	return &Cache{client: client}
}

func (c *Cache) Set(key string, value interface{}, expiration time.Duration) error {
	ctx := context.Background()
	return c.client.Set(ctx, key, value, expiration).Err()
}

func (c *Cache) Get(key string) (string, error) {
	ctx := context.Background()
	return c.client.Get(ctx, key).Result()
}

func NewLoadBalancer(serversUrls []string) (*LoadBalancer, error) {
	var servers []*url.URL
	for _, s := range serversUrls {
		url, err := url.Parse(s)
		if err != nil {
			return nil, err
		}
		servers = append(servers, url)
	}

	return &LoadBalancer{
		servers: servers,
	}, nil
}

func (lb *LoadBalancer) NextServer() *url.URL {
	lb.mu.Lock()
	defer lb.mu.Unlock()

	server := lb.servers[lb.current]
	lb.current = (lb.current + 1) % len(lb.servers)
	return server
}

func (lb *LoadBalancer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	server := lb.NextServer()
	proxy := httputil.NewSingleHostReverseProxy(server)
	proxy.ServeHTTP(w, r)
}

func (w *gzipResponseWriter) Write(b []byte) (int, error) {
	return w.Writer.Write(b)
}

func gzipMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") {
			next(w, r)
			return
		}

		w.Header().Set("Content-Encoding", "gzip")
		gz := gzip.NewWriter(w)
		defer gz.Close()

		gzw := &gzipResponseWriter{Writer: gz, ResponseWriter: w}
		next(gzw, r)
	}
}

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

func getRealIP(r *http.Request) (string, error) {
	// Check X-Forwarded-For header
	forwardedIP := r.Header.Get("X-Forwarded-For")
	if forwardedIP != "" {
		// Get the first IP in case of multiple forwards
		ips := strings.Split(forwardedIP, ",")
		return strings.TrimSpace(ips[0]), nil
	}

	// Fall back to RemoteAddr if no forwarded IP
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return "", err
	}
	return ip, nil
}

func rateLimitMiddleware(next http.HandlerFunc, limiter *IPRateLimiter) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ip, err := getRealIP(r)
		if err != nil {
			log.Printf("Error getting real IP: %v", err)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}

		limiter := limiter.GetIP(ip)
		if !limiter.Allow() {
			rateLimitExceeded.Inc()
			log.Printf("Rate limit exceeded for IP %s", ip)
			http.Error(w, "Too many requests", http.StatusTooManyRequests)
			return
		}

		next(w, r)
	}
}

func recoverMiddleware(next http.Handler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if err := recover(); err != nil {
				log.Printf("Recovered from panic: %v", err)
				http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			}
		}()
		next.ServeHTTP(w, r)
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

	lb, err := NewLoadBalancer([]string{
		"http://localhost:8081",
		"http://localhost:8082",
		"http://localhost:8083",
	})
	if err != nil {
		log.Fatal(err)
	}

	http.Handle("/shorten", recoverMiddleware(gzipMiddleware(rateLimitMiddleware(shortenURLHandler, limiter))))
	http.Handle("/stats/", recoverMiddleware(gzipMiddleware(rateLimitMiddleware(statsHandler, limiter))))
	http.Handle("/", recoverMiddleware(gzipMiddleware(rateLimitMiddleware(redirectHandler, limiter))))

	http.Handle("/api/", recoverMiddleware(lb))

	// Add metrics endpoint
	http.Handle("/metrics", promhttp.Handler())

	log.Println("Server started at :8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}

func encrypt(initialURL string) string {
	// -----------------------------------

	block, err := aes.NewCipher([]byte(secretKey))
	if err != nil {
		log.Fatal(err)
	}

	plainText := []byte(initialURL)
	cipherText := make([]byte, aes.BlockSize+len(plainText))

	iv := cipherText[:aes.BlockSize]
	if _, err := rand.Read(iv); err != nil {
		log.Fatal(err)
	}

	stream := cipher.NewCTR(block, iv)

	stream.XORKeyStream(cipherText[aes.BlockSize:], plainText)

	return hex.EncodeToString(cipherText)
}

func decrypt(encryptedURL string) string {
	block, err := aes.NewCipher([]byte(secretKey))
	if err != nil {
		log.Fatal(err)
	}

	cipherText, err := hex.DecodeString(encryptedURL)
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
	clientIP, _ := getRealIP(r)

	mu.Lock()
	urlEntry, ok := urlStore[shortId]
	expiresAt, err := time.Parse(time.RFC3339, urlEntry.ExpiresAt)
	if err != nil {
		log.Printf("Error parsing expiration for %s: %v", shortId, err)
		http.Error(w, "Invalid expiration format", http.StatusInternalServerError)
		return
	}

	if ok && time.Now().After(expiresAt) {
		delete(urlStore, shortId)
		mu.Unlock()
		log.Printf("Attempted access to expired URL %s from %s", shortId, clientIP)
		http.Error(w, "URL has expired", http.StatusGone)
		return
	}

	if !ok {
		log.Printf("Attempted access to non-existent URL %s from %s", shortId, clientIP)
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
	urlRedirects.Inc()
	log.Printf("Redirecting %s to %s (visit #%d)", shortId, decryptedUrl, urlEntry.Stats.Visits)
	http.Redirect(w, r, decryptedUrl, http.StatusFound)
}

func cleanupExpiredUrls() {
	ticker := time.NewTicker(10 * time.Minute)
	go func() {
		for range ticker.C {
			mu.Lock()
			deletedCount := 0
			for id, entry := range urlStore {
				expiresAt, _ := time.Parse(time.RFC3339, entry.ExpiresAt)
				if time.Now().After(expiresAt) {
					delete(urlStore, id)
					deletedCount++
					log.Printf("Cleaned up expired URL %s", id)
				}
			}
			if deletedCount > 0 {
				log.Printf("Cleanup complete: removed %d expired URLs", deletedCount)
			}
			activeUrls.Sub(float64(deletedCount))
			mu.Unlock()
		}
	}()
}

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
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

func shortenURLHandler(w http.ResponseWriter, r *http.Request) {
	initialURL := r.URL.Query().Get("url")

	expirationStr := r.URL.Query().Get("expires_at")
	expirationMinutes := 24 * 60

	if expirationStr != "" {
		parsed, err := strconv.Atoi(expirationStr)
		if err == nil && parsed > 0 {
			expirationMinutes = parsed
		}
	}

	if initialURL == "" {
		http.Error(w, "URL is required", http.StatusBadRequest)
		return
	}

	if !(strings.HasPrefix(initialURL, "http://") || strings.HasPrefix(initialURL, "https://")) {
		http.Error(w, "Invalid URL format. URL must start with http:// or https://", http.StatusBadRequest)
		return
	}

	encryptedURL := encrypt(initialURL)
	shortID := generateShortId()
	expiresAt := time.Now().Add(time.Duration(expirationMinutes) * time.Minute).Format(time.RFC3339)

	mu.Lock()
	urlStore[shortID] = Url{
		EncryptedURL: encryptedURL,
		ExpiresAt:    expiresAt,
	}
	activeUrls.Inc()
	mu.Unlock()

	urlsCreated.Inc()
	log.Printf("Created shortened URL: %s for %s (expires: %s)", shortID, initialURL, expiresAt)

	/*w.Write([]byte(shortUrl))
	  fmt.Fprintf(w, "This is the shortened : %s", shortUrl) */

	shortURL := fmt.Sprintf("http://localhost:8080/%s", shortID)
	fmt.Fprintf(w, "This is the shortened URL: %s (expires in %d minutes)", shortURL, expirationMinutes)
}
