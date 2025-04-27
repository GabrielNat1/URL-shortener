# URL Shortener

A simple URL shortener service written in Go that encrypts URLs and generates short IDs for them.

## Features

- URL shortening with AES encryption
- Configurable URL expiration time
- URL statistics tracking (visits, last visit, user agents)
- Automatic cleanup of expired URLs
- Secure random short ID generation
- Basic URL validation
- URL redirection

## Requirements

- Go 1.24+
- Environment variables setup (.env file)

## Setup

1. Clone the repository
2. Create a `.env` file in the root directory with your secret key:
```
SECRET_KEY=your-secret-key
```
Note: The secret key must be either 16, 24, or 32 bytes long for AES encryption.

3. Run `go mod tidy` to install dependencies

## Usage

Start the server:
```
go run main.go
```

The server will start at `http://localhost:8080`

### API Endpoints

1. Shorten URL:
   ```
   GET /shorten?url=https://your-long-url.com&expires_at=1440
   ```
   - `url`: The URL to shorten (required)
   - `expires_at`: Expiration time in minutes (optional, defaults to 24 hours)

2. Access shortened URL:
   ```
   GET /{shortId}
   ```

3. Get URL statistics:
   ```
   GET /stats/{shortId}
   ```
   Returns JSON with:
   - Number of visits
   - Last visit timestamp
   - List of user agents
   - Expiration time
   - Short URL

## How it works

- URLs are encrypted using AES encryption in CTR mode
- Short IDs are 6 characters long, generated using cryptographically secure random numbers
- URLs are stored in memory using a thread-safe map with mutex protection
- URLs automatically expire after a configurable time (default 24 hours)
- Background task runs every 10 minutes to clean up expired URLs
- Basic URL validation ensures proper URL format (must start with http:// or https://)

## Security

- Uses AES encryption for URL storage
- Implements secure random generation for short IDs
- Thread-safe operations using mutex
- Environment-based secret key configuration
- URL expiration for temporary access
