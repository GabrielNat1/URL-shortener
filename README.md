# URL Shortener

A secure URL shortener service written in Go with load balancing, compression, rate limiting, encryption, and automatic cleanup.

## Features

- **URL Shortening**
  - Generates 6-character random short IDs
  - Supports custom expiration times
  - Basic URL format validation
  - AES encryption for URL storage

- **Performance & Reliability**
  - Load balancing across multiple backend servers
  - Gzip compression support
  - Panic recovery middleware
  - Redis caching support (optional)

- **Security**
  - Rate limiting per IP (1 request/second, burst of 5)
  - AES-CTR encryption for stored URLs
  - Environment-based secret key configuration
  - Thread-safe operations using mutex

- **Statistics**
  - Track number of visits
  - Record last visit timestamp
  - Log unique user agents
  - View URL expiration time

- **Maintenance**
  - Automatic cleanup of expired URLs every 10 minutes
  - Configurable URL expiration (default 24 hours)
  - Graceful panic recovery

## Requirements

- Go 1.24+
- Redis (optional)
- Environment variables setup (.env file)

## Installation

1. Clone the repository
2. Install dependencies:
```bash
go mod tidy
```

3. Create a `.env` file:
```env
SECRET_KEY=your-32-byte-secret-key
```
Note: SECRET_KEY must be 16, 24, or 32 bytes long

## Usage

1. Start the server:
```bash
go run main.go
```

2. The server starts at `http://localhost:8080` with load balancing across:
   - http://localhost:8081
   - http://localhost:8082
   - http://localhost:8083

### API Endpoints

#### 1. Shorten URL
```
GET /shorten?url=https://example.com&expires_at=1440
```
Parameters:
- `url`: The URL to shorten (required)
- `expires_at`: Expiration time in minutes (optional, default: 1440)

Response:
```
This is the shortened URL: http://localhost:8080/Ab3Cd5 (expires in 1440 minutes)
```

#### 2. Access URL
```
GET /{shortId}
```
- Redirects to original URL if valid
- Returns 410 Gone if expired
- Returns 404 if not found

#### 3. Get Statistics
```
GET /stats/{shortId}
```
Returns:
```json
{
    "short_url": "http://localhost:8080/Ab3Cd5",
    "visits": 10,
    "last_visit": "2025-04-27T15:30:00Z",
    "user_agent": ["Mozilla/5.0...", "curl/7.64.1"],
    "expiration": "2025-04-28T15:30:00Z"
}
```

## Features Details

### Load Balancing
- Round-robin distribution across backend servers
- Automatic failover support
- Easy addition of new backend servers

### Compression
- Gzip compression for all responses
- Automatic content negotiation
- Reduces bandwidth usage

### Rate Limiting
- 1 request per second per IP
- Burst allowance of 5 requests
- Returns 429 Too Many Requests when limit exceeded

### Error Handling
- Panic recovery middleware prevents server crashes
- Detailed logging of recovered panics
- Graceful error responses

## Error Responses

- 400: Bad Request (Invalid URL format)
- 404: Not Found
- 410: Gone (URL expired)
- 429: Too Many Requests (Rate limit exceeded)
- 500: Internal Server Error

## Security Considerations

- Uses AES-CTR mode for encryption
- Cryptographically secure random number generation
- Thread-safe operations
- Rate limiting prevents abuse
- Automatic cleanup of expired data
- Panic recovery for stability

## Metrics

The service exposes Prometheus metrics at `/metrics` endpoint:

- `url_shortener_urls_created_total`: Total number of shortened URLs created
- `url_shortener_redirects_total`: Total number of redirects performed
- `url_shortener_active_urls`: Current number of active shortened URLs
- `url_shortener_rate_limit_exceeded_total`: Total number of rate limit exceeded events
