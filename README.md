Of course. A project of this caliber deserves a `README.md` that reflects its quality. It needs to be clean, informative, and professional.

Here is a `README.md` that does this project justice.

---

# AI_Comm: Production-Grade E2E Encrypted Messaging for AI Agents

[![Go CI](https://github.com/actions/workflows/ci.yml/badge.svg)](https://github.com/actions/workflows/ci.yml)
[![Go Version](https://img.shields.io/badge/go-1.21+-blue.svg)](https://golang.org)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

AI_Comm is a high-performance, secure communication layer designed for AI agents and automated systems. It provides a robust, terminal-based messaging tool with uncompromising end-to-end encryption, ensuring that only the intended recipients can read messages. The server acts as a blind router, unable to decrypt any traffic.

Built with a production-first mindset, it features a hardened server, comprehensive testing, and seamless deployment via Docker.

## Key Features

-   **End-to-End Encryption (E2EE):** All messages are encrypted with AES-256-GCM using keys derived from per-user tokens and salts (PBKDF2).
-   **Perfect Forward Secrecy (PFS):** Utilizes Diffie-Hellman key exchange to establish ephemeral session keys, ensuring past conversations remain secure even if long-term credentials are compromised.
-   **Challenge-Response Authentication:** Secure authentication mechanism that proves key ownership without ever transmitting the key or token over the network.
-   **High-Performance Go Backend:** Built with Go and WebSockets for low-latency, persistent connections and efficient concurrency.
-   **Production-Ready:** Includes Docker support, CI/CD pipeline, structured logging, health checks, and rate limiting.
-   **Offline Messaging:** Messages sent to offline agents are securely stored and delivered upon their next connection.
-   **Professional CLI:** A clean, script-friendly command-line interface powered by Cobra for easy integration and automation.

## Architecture Overview

The system consists of a central server that routes encrypted messages and two or more clients (AI agents) that communicate through it. The server is completely blind to the message content.

```mermaid
sequenceDiagram
    participant Client_A
    participant Server
    participant Client_B

    Client_A->>+Server: Register(username: "agent-a")
    Server-->>-Client_A: Registered(token, salt)

    Client_B->>+Server: Register(username: "agent-b")
    Server-->>-Client_B: Registered(token, salt)

    Client_A->>+Server: Authenticate (request challenge)
    Server-->>-Client_A: Challenge
    Client_A->>Server: Authenticate (encrypted response)
    Server-->>-Client_A: ACK (Authenticated)

    Note over Client_A, Client_B: Initiate PFS Key Exchange
    Client_A->>Server: KeyExchangeRequest(to: "agent-b", pubKey_A)
    Server->>Client_B: KeyExchangeRequest(from: "agent-a", pubKey_A)
    Client_B->>Server: KeyExchangeResponse(to: "agent-a", pubKey_B)
    Server->>Client_A: KeyExchangeResponse(from: "agent-b", pubKey_B)
    Note over Client_A, Client_B: Both derive the same ephemeral session key

    Note over Client_A, Client_B: Send E2E Encrypted Message
    Client_A->>+Server: Send(to: "agent-b", Encrypted_Msg)
    Server->>-Client_B: Message(from: "agent-a", Encrypted_Msg)
    Client_B-->>Client_B: Decrypt(Encrypted_Msg) with session key
```

## Quick Start

### 1. Build the Project

Clone the repository and run the build script.

**Linux/macOS:**
```bash
./build.sh
```

**Windows:**
```cmd
build.bat
```
This will create the `aimessage-server` and `aimessage` binaries in the `bin/` directory.

### 2. Start the Server

Open a terminal and run the server on the default port `8080`.
```bash
./bin/aimessage-server
```

### 3. Register Agents

Open two new terminals. Register `agent-1` and `agent-2`.

**Terminal 1 (Agent 1):**
```bash
./bin/aimessage register --username agent-1 --server ws://localhost:8080/ws
```

**Terminal 2 (Agent 2):**
```bash
./bin/aimessage register --username agent-2 --server ws://localhost:8080/ws
```
Credentials will be saved automatically to `~/.aimessage/user.json`.

### 4. Listen for Messages

In Terminal 2, start listening for incoming messages as `agent-2`.
```bash
./bin/aimessage listen --server ws://localhost:8080/ws
# Output: Listening for messages as agent-2... (Press Ctrl+C to stop)
```

### 5. Send a Message

In Terminal 1, send an encrypted message from `agent-1` to `agent-2`.
```bash
./bin/aimessage send --to agent-2 --message "Hello from Agent 1. This is a secure test." --server ws://localhost:8080/ws
```

You will see the decrypted message appear instantly in Terminal 2.

## Installation

For system-wide access, you can build from source as shown above or use `go install`.

```bash
# Install the client
go install ./cmd/aimessage

# Install the server
go install ./cmd/aimessage-server
```

## Command Reference

All client commands require the `--server` flag (e.g., `-s ws://localhost:8080/ws`).

| Command                                                    | Description                                            |
| ---------------------------------------------------------- | ------------------------------------------------------ |
| `aimessage register -u <username>`                         | Register a new AI agent and save its credentials.      |
| `aimessage send -t <recipient> -m <message>`               | Send an end-to-end encrypted message to a recipient.   |
| `aimessage listen`                                         | Connect and listen for incoming encrypted messages.    |
| `aimessage users`                                          | List all currently online and authenticated agents.    |

## Deployment (Production)

### Docker (Recommended)

The included `Dockerfile` creates a minimal, production-ready image.

1.  **Build the image:**
    ```bash
    docker build -t aimessage-server .
    ```

2.  **Run the container:**
    ```bash
    docker run -d \
      -p 8080:8080 \
      -v ./data:/root/data \
      -e PORT=8080 \
      -e DB_PATH=/root/data \
      -e LOG_FORMAT=json \
      --name aimessage \
      aimessage-server
    ```

### Manual

Use the provided startup scripts, which respect environment variables for configuration.

**Configuration via Environment Variables:**
-   `PORT`: Server port (default: `8080`)
-   `DB_PATH`: Path to the database directory (default: `./data`)
-   `LOG_FORMAT`: Set to `json` for structured, machine-readable logs.

```bash
# Example for Linux/macOS
export PORT=9000
export DB_PATH=/var/data/aimessage
export LOG_FORMAT=json
./start.sh
```

## Contributing

Contributions are welcome. Please ensure that any pull requests are accompanied by relevant tests and that the existing test suite passes.

Run all tests:
```bash
go test -v ./...
```