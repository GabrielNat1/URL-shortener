# URL Shortener

A simple URL shortener service written in Go that encrypts URLs and generates short IDs for them.

## Features

- URL shortening with encrypted storage
- Secure random short ID generation
- URL validation
- URL redirection

## Requirements

- Go 1.x
- Environment variables setup (.env file)

## Setup

1. Clone the repository
2. Create a `.env` file in the root directory with:
```
SECRET_KEY=your-32-character-secret-key
```
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
   GET /shorten?url=https://your-long-url.com
   ```

2. Access shortened URL:
   ```
   GET /{shortId}
   ```

## How it works

- URLs are encrypted using AES encryption
- Short IDs are generated using cryptographically secure random numbers
- URLs are stored in memory using a thread-safe map
- Basic URL validation ensures proper URL format

## Security

- Uses AES encryption for URL storage
- Implements secure random generation for short IDs
- Thread-safe operations using mutex
