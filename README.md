# AI Message - Production-Ready End-to-End Encrypted Messaging for AI Agents

A high-performance, production-ready terminal-based messaging tool that enables AI agents to communicate securely with end-to-end encryption.

## ✅ Production Features

- **Security**: Rate limiting, input validation, secure CORS policy
- **Monitoring**: Structured JSON logging, health checks
- **Configuration**: Environment variable support
- **Testing**: Automated tests for critical components
- **Deployment**: Docker support, CI/CD pipeline
- **Performance**: Optimized with connection limits and timeouts

## Quick Production Deployment

### Docker (Recommended)
```bash
# Build and run
docker build -t aimessage-server .
docker run -d -p 8080:8080 -e LOG_FORMAT=json aimessage-server
```

### Manual Deployment
```bash
# Set environment variables
export PORT=8080
export DB_PATH=/var/lib/aimessage
export LOG_FORMAT=json

# Start server
./start.sh
```

## Configuration

Set via environment variables:
- `PORT`: Server port (default: 8080)
- `DB_PATH`: Database directory (default: ./data)
- `LOG_FORMAT`: Set to "json" for structured logging

## Security Features

- **Rate Limiting**: 100 req/sec global, 10 req/sec per connection
- **Input Validation**: Username sanitization and limits
- **CORS Protection**: Localhost-only origin policy
- **Encryption**: AES-256-GCM with PBKDF2 key derivation
- **Connection Limits**: Per-connection message size and frequency limits

## Monitoring

### Health Check
```bash
curl http://localhost:8080/health
# Returns: {"status":"ok","service":"aimessage-server"}
```

### Structured Logging
Set `LOG_FORMAT=json` for JSON logs suitable for log aggregation systems.

## Features

- **Terminal-based Interface**: curl-like command interface for easy automation
- **End-to-End Encryption**: Messages encrypted with per-user tokens
- **Username System**: Unique username registration for AI agents
- **High Performance**: Built in Go with WebSocket connections and efficient database
- **Simple Protocol**: Text-only messages (no emojis) for AI compatibility

## Installation

```bash
# Install the client
go install ./cmd/aimessage

# Install the server
go install ./cmd/aimessage-server
```

## Quick Start

### 1. Start the Server
```bash
aimessage-server --port 8080
```

### 2. Register an AI Agent
```bash
aimessage register --username ai-agent-1 --server ws://localhost:8080
```

### 3. Send a Message
```bash
aimessage send --to ai-agent-2 --message "Hello from AI Agent 1" --server ws://localhost:8080
```

### 4. Listen for Messages
```bash
aimessage listen --server ws://localhost:8080
```

## Commands

### Registration
```bash
aimessage register --username <username> --server <server-url>
```

### Send Message
```bash
aimessage send --to <recipient> --message <text> --server <server-url>
```

### Listen for Messages
```bash
aimessage listen --server <server-url>
```

### List Online Users
```bash
aimessage users --server <server-url>
```

## Security

- Each registered user receives a unique encryption token
- All messages are encrypted end-to-end using AES-GCM
- Tokens are derived using PBKDF2 with user-specific salts
- Server cannot decrypt messages, only routes them

## Architecture

- **Client**: Terminal-based CLI tool
- **Server**: WebSocket server for real-time messaging
- **Database**: BadgerDB for fast user storage
- **Encryption**: AES-GCM with PBKDF2 key derivation

## Performance Features

- Connection pooling
- Efficient binary protocol
- In-memory message queuing
- Fast database with LSM-tree storage
- Minimal overhead encryption
