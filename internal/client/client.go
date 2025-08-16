package client

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/url"
	"os"
	"path/filepath"
	"time"

	"aimessage/internal/crypto"
	"aimessage/internal/logging"
	"aimessage/internal/protocol"

	"github.com/google/uuid"
	"github.com/gorilla/websocket"
)

// Client represents the messaging client
type Client struct {
	conn               *websocket.Conn
	serverURL          string
	configDir          string
	username           string
	userCrypto         *crypto.UserCrypto
	isListening        bool
	authenticated      bool
	sessionKeys        map[string]*crypto.SessionKeys      // Map of sessionID to session keys
	recipientSessions  map[string]string                   // Map of recipient to current sessionID
	pendingKeyExchange map[string]*crypto.DHKeyPair        // Map of sessionID to our DH key pair (for pending exchanges)
	keyExchangeWaiters map[string]chan *crypto.SessionKeys // Map of sessionID to completion channels
	readBuffer         []byte                              // Reusable read buffer
	writeBuffer        []byte                              // Reusable write buffer
}

// UserConfig stores user credentials locally
type UserConfig struct {
	Username string `json:"username"`
	Token    string `json:"token"`
	Salt     string `json:"salt"`
}

// NewClient creates a new client instance
func NewClient(serverURL string) *Client {
	homeDir, _ := os.UserHomeDir()
	configDir := filepath.Join(homeDir, ".aimessage")
	os.MkdirAll(configDir, 0700)

	return &Client{
		serverURL:          serverURL,
		configDir:          configDir,
		sessionKeys:        make(map[string]*crypto.SessionKeys),
		recipientSessions:  make(map[string]string),
		pendingKeyExchange: make(map[string]*crypto.DHKeyPair),
		keyExchangeWaiters: make(map[string]chan *crypto.SessionKeys),
		readBuffer:         make([]byte, 0, 512), // Pre-allocate read buffer
		writeBuffer:        make([]byte, 0, 512), // Pre-allocate write buffer
	}
}

// Connect establishes WebSocket connection to the server
func (c *Client) Connect() error {
	u, err := url.Parse(c.serverURL)
	if err != nil {
		return fmt.Errorf("invalid server URL: %w", err)
	}

	conn, _, err := websocket.DefaultDialer.Dial(u.String(), nil)
	if err != nil {
		return fmt.Errorf("failed to connect to server: %w", err)
	}

	c.conn = conn
	return nil
}

// Disconnect closes the WebSocket connection
func (c *Client) Disconnect() error {
	if c.conn != nil {
		return c.conn.Close()
	}
	return nil
}

// Register registers a new user with the server
func (c *Client) Register(username string) error {
	if err := c.Connect(); err != nil {
		return err
	}
	defer c.Disconnect()

	// Send registration request
	req := protocol.RegisterRequest{Username: username}
	msg := protocol.NewMessage(protocol.MsgTypeRegister, req)
	msg.ID = uuid.New().String()

	if err := c.sendMessage(msg); err != nil {
		return fmt.Errorf("failed to send registration: %w", err)
	}

	// Wait for response
	response, err := c.readMessage()
	if err != nil {
		return fmt.Errorf("failed to read registration response: %w", err)
	}

	if response.Type == protocol.MsgTypeError {
		var errorResp protocol.ErrorResponse
		if err := response.ParseData(&errorResp); err != nil {
			return fmt.Errorf("registration failed with unknown error")
		}
		return fmt.Errorf("registration failed: %s", errorResp.Message)
	}

	if response.Type != protocol.MsgTypeRegistered {
		return fmt.Errorf("unexpected response type: %s", response.Type)
	}

	var regResp protocol.RegisterResponse
	if err := response.ParseData(&regResp); err != nil {
		return fmt.Errorf("failed to parse registration response: %w", err)
	}

	// Save user config locally
	config := UserConfig{
		Username: regResp.Username,
		Token:    regResp.Token,
		Salt:     regResp.Salt,
	}

	if err := c.saveUserConfig(&config); err != nil {
		return fmt.Errorf("failed to save user config: %w", err)
	}

	fmt.Printf("Registration successful!\n")
	fmt.Printf("Username: %s\n", regResp.Username)
	fmt.Printf("Token saved to: %s\n", c.getUserConfigPath())

	return nil
}

// initiateKeyExchange starts a DH key exchange with a recipient
func (c *Client) initiateKeyExchange(recipient string) (string, error) {
	// Generate session ID
	sessionID := uuid.New().String()

	// Generate our DH key pair
	keyPair, err := crypto.GenerateDHKeyPair()
	if err != nil {
		return "", fmt.Errorf("failed to generate DH key pair: %w", err)
	}

	// Store our key pair for when we receive the response
	c.pendingKeyExchange[sessionID] = keyPair

	// Send key exchange request
	publicKeyB64 := base64.StdEncoding.EncodeToString(keyPair.PublicKey)
	keyReq := protocol.KeyExchangeRequest{
		To:        recipient,
		PublicKey: publicKeyB64,
		SessionID: sessionID,
	}

	msg := protocol.NewMessage(protocol.MsgTypeKeyExchange, keyReq)
	msg.ID = uuid.New().String()

	if err := c.sendMessage(msg); err != nil {
		delete(c.pendingKeyExchange, sessionID)
		return "", fmt.Errorf("failed to send key exchange request: %w", err)
	}

	return sessionID, nil
}

// getOrCreateSession gets an existing session or creates a new one via key exchange
func (c *Client) getOrCreateSession(recipient string) (string, *crypto.SessionKeys, error) {
	// Check if we have an existing session
	if sessionID, exists := c.recipientSessions[recipient]; exists {
		if sessionKeys, exists := c.sessionKeys[sessionID]; exists {
			return sessionID, sessionKeys, nil
		}
	}

	// No existing session, initiate key exchange
	sessionID, err := c.initiateKeyExchange(recipient)
	if err != nil {
		return "", nil, fmt.Errorf("failed to initiate key exchange: %w", err)
	}

	// Create a channel to wait for the key exchange completion
	waiterChan := make(chan *crypto.SessionKeys, 1)
	c.keyExchangeWaiters[sessionID] = waiterChan

	// Wait for key exchange response (with timeout)
	timeout := time.After(30 * time.Second)

	select {
	case <-timeout:
		delete(c.pendingKeyExchange, sessionID)
		delete(c.keyExchangeWaiters, sessionID)
		return "", nil, fmt.Errorf("key exchange timeout for session %s", sessionID)
	case sessionKeys := <-waiterChan:
		delete(c.keyExchangeWaiters, sessionID)
		c.recipientSessions[recipient] = sessionID
		return sessionID, sessionKeys, nil
	}
}

// SendMessage sends an encrypted message to another user with Perfect Forward Secrecy
func (c *Client) SendMessage(to, message string) error {
	if err := c.loadUserConfig(); err != nil {
		return fmt.Errorf("not registered or config missing: %w", err)
	}

	if err := c.Connect(); err != nil {
		return err
	}
	defer c.Disconnect()

	// Authenticate first
	if err := c.authenticate(); err != nil {
		return fmt.Errorf("authentication failed: %w", err)
	}

	// Get or create session with Perfect Forward Secrecy
	sessionID, sessionKeys, err := c.getOrCreateSession(to)
	if err != nil {
		// Fall back to static encryption if PFS fails
		logging.WarnWithError("PFS failed, falling back to static encryption", err, map[string]string{"recipient": to})
		return c.sendMessageFallback(to, message)
	}

	// Encrypt with session key (PFS)
	sessionCrypto := crypto.NewSessionCrypto(sessionKeys)
	encryptedMessage, err := sessionCrypto.Encrypt(message)
	if err != nil {
		return fmt.Errorf("failed to encrypt message with session key: %w", err)
	}

	// Send the message using SecureMessage format with session ID
	req := protocol.SecureMessage{
		To:        to,
		Message:   encryptedMessage,
		SessionID: sessionID,
	}

	msg := protocol.NewMessage(protocol.MsgTypeSend, req)
	msg.ID = uuid.New().String()

	if err := c.sendMessage(msg); err != nil {
		return fmt.Errorf("failed to send message: %w", err)
	}

	// Wait for acknowledgment
	response, err := c.readMessage()
	if err != nil {
		return fmt.Errorf("failed to read response: %w", err)
	}

	if response.Type == protocol.MsgTypeError {
		var errorResp protocol.ErrorResponse
		if err := response.ParseData(&errorResp); err != nil {
			return fmt.Errorf("send failed with unknown error")
		}
		return fmt.Errorf("send failed: %s", errorResp.Message)
	}

	if response.Type == protocol.MsgTypeAck {
		var ackData map[string]string
		if err := response.ParseData(&ackData); err == nil {
			if status, ok := ackData["status"]; ok {
				if status == "stored_offline" {
					fmt.Printf("Message sent to %s (stored for offline delivery, PFS enabled)\n", to)
				} else {
					fmt.Printf("Message sent to %s (PFS enabled)\n", to)
				}
			}
		}
		return nil
	}

	if response.Type == protocol.MsgTypeMessage {
		// Message was delivered immediately (e.g., sending to self or online recipient)
		fmt.Printf("Message sent to %s (delivered immediately)\n", to)
		return nil
	}

	return fmt.Errorf("unexpected response type: %s", response.Type)
}

// sendMessageFallback sends a message using static encryption (fallback when PFS fails)
func (c *Client) sendMessageFallback(to, message string) error {
	// Use static encryption
	encryptedMessage, err := c.userCrypto.Encrypt(message)
	if err != nil {
		return fmt.Errorf("failed to encrypt message: %w", err)
	}

	// Send the message using SecureMessage format without session ID
	req := protocol.SecureMessage{
		To:      to,
		Message: encryptedMessage,
		// No SessionID for fallback static encryption
	}

	msg := protocol.NewMessage(protocol.MsgTypeSend, req)
	msg.ID = uuid.New().String()

	if err := c.sendMessage(msg); err != nil {
		return fmt.Errorf("failed to send message: %w", err)
	}

	// Wait for acknowledgment
	response, err := c.readMessage()
	if err != nil {
		return fmt.Errorf("failed to read response: %w", err)
	}

	if response.Type == protocol.MsgTypeError {
		var errorResp protocol.ErrorResponse
		if err := response.ParseData(&errorResp); err != nil {
			return fmt.Errorf("send failed with unknown error")
		}
		return fmt.Errorf("send failed: %s", errorResp.Message)
	}

	if response.Type == protocol.MsgTypeAck {
		var ackData map[string]string
		if err := response.ParseData(&ackData); err == nil {
			if status, ok := ackData["status"]; ok {
				if status == "stored_offline" {
					fmt.Printf("Message sent to %s (stored for offline delivery, static encryption)\n", to)
				} else {
					fmt.Printf("Message sent to %s (static encryption)\n", to)
				}
			}
		}
		return nil
	}

	return fmt.Errorf("unexpected response type: %s", response.Type)
}

// authenticate performs challenge-response authentication
func (c *Client) authenticate() error {
	if c.authenticated {
		return nil
	}

	// Send authentication request (first step)
	authReq := protocol.AuthenticationRequest{
		Username: c.username,
		Token:    "", // Will be filled by server challenge
	}

	msg := protocol.NewMessage(protocol.MsgTypeAuthenticate, authReq)
	msg.ID = uuid.New().String()

	if err := c.sendMessage(msg); err != nil {
		return fmt.Errorf("failed to send authentication request: %w", err)
	}

	// Wait for challenge
	response, err := c.readMessage()
	if err != nil {
		return fmt.Errorf("failed to read challenge: %w", err)
	}

	if response.Type == protocol.MsgTypeError {
		var errorResp protocol.ErrorResponse
		if err := response.ParseData(&errorResp); err != nil {
			return fmt.Errorf("authentication failed with unknown error")
		}
		return fmt.Errorf("authentication failed: %s", errorResp.Message)
	}

	if response.Type != protocol.MsgTypeChallenge {
		return fmt.Errorf("unexpected response type: %s", response.Type)
	}

	var challenge protocol.ChallengeRequest
	if err := response.ParseData(&challenge); err != nil {
		return fmt.Errorf("failed to parse challenge: %w", err)
	}

	// Encrypt the challenge with our key as response
	challengeResponse, err := c.userCrypto.Encrypt(challenge.Challenge)
	if err != nil {
		return fmt.Errorf("failed to encrypt challenge response: %w", err)
	}

	// Send challenge response
	authResp := protocol.AuthenticationRequest{
		Username:  c.username,
		Challenge: challengeResponse,
	}

	msg = protocol.NewMessage(protocol.MsgTypeAuthenticate, authResp)
	msg.ID = uuid.New().String()

	if err := c.sendMessage(msg); err != nil {
		return fmt.Errorf("failed to send challenge response: %w", err)
	}

	// Wait for authentication result
	response, err = c.readMessage()
	if err != nil {
		return fmt.Errorf("failed to read authentication result: %w", err)
	}

	if response.Type == protocol.MsgTypeError {
		var errorResp protocol.ErrorResponse
		if err := response.ParseData(&errorResp); err != nil {
			return fmt.Errorf("authentication failed with unknown error")
		}
		return fmt.Errorf("authentication failed: %s", errorResp.Message)
	}

	if response.Type == protocol.MsgTypeAck {
		c.authenticated = true
		fmt.Printf("Authentication successful for %s\n", c.username)
		return nil
	}

	return fmt.Errorf("unexpected authentication response: %s", response.Type)
}

// Listen starts listening for incoming messages
func (c *Client) Listen() error {
	if err := c.loadUserConfig(); err != nil {
		return fmt.Errorf("not registered or config missing: %w", err)
	}

	if err := c.Connect(); err != nil {
		return err
	}
	defer c.Disconnect()

	// Authenticate first
	if err := c.authenticate(); err != nil {
		return fmt.Errorf("authentication failed: %w", err)
	}

	// Send listen request
	msg := protocol.NewMessage(protocol.MsgTypeListen, nil)
	msg.ID = uuid.New().String()

	if err := c.sendMessage(msg); err != nil {
		return fmt.Errorf("failed to send listen request: %w", err)
	}

	fmt.Printf("Listening for messages as %s... (Press Ctrl+C to stop)\n", c.username)
	c.isListening = true

	// Start heartbeat goroutine
	go c.heartbeat()

	// Listen for messages
	for c.isListening {
		response, err := c.readMessage()
		if err != nil {
			if c.isListening {
				logging.ErrorWithError("Error reading message during listen", err)
				time.Sleep(time.Second)
				continue
			}
			break
		}

		switch response.Type {
		case protocol.MsgTypeMessage:
			c.handleIncomingMessage(response)
		case protocol.MsgTypeOfflineMsg:
			c.handleOfflineMessage(response)
		case protocol.MsgTypeKeyRequest:
			c.handleKeyExchangeRequest(response)
		case protocol.MsgTypeKeyResponse:
			c.handleKeyExchangeResponse(response)
		}
	}

	return nil
}

// handleIncomingMessage handles real-time message delivery
func (c *Client) handleIncomingMessage(response *protocol.Message) {
	// Try to parse as OfflineMessage first (which includes SessionID)
	var offlineMsg protocol.OfflineMessage
	if err := response.ParseData(&offlineMsg); err == nil && offlineMsg.SessionID != "" {
		// This is a message with session info, try to decrypt with session keys
		if sessionKeys, exists := c.sessionKeys[offlineMsg.SessionID]; exists {
			sessionCrypto := crypto.NewSessionCrypto(sessionKeys)
			decryptedMessage, err := sessionCrypto.Decrypt(offlineMsg.Message)
			if err != nil {
				log.Printf("Failed to decrypt PFS message from %s: %v", offlineMsg.From, err)
				return
			}

			timestamp := time.Unix(offlineMsg.Timestamp, 0)
			fmt.Printf("\n[%s] %s: %s (PFS)\n", timestamp.Format("15:04:05"), offlineMsg.From, decryptedMessage)
			return
		} else {
			log.Printf("No session keys found for session %s from %s", offlineMsg.SessionID, offlineMsg.From)
		}
	}

	// Fall back to old MessageDelivery format or static encryption
	var delivery protocol.MessageDelivery
	if err := response.ParseData(&delivery); err != nil {
		log.Printf("Failed to parse message delivery: %v", err)
		return
	}

	// Decrypt the message using static encryption
	decryptedMessage, err := c.userCrypto.Decrypt(delivery.Message)
	if err != nil {
		log.Printf("Failed to decrypt message from %s: %v", delivery.From, err)
		return
	}

	timestamp := time.Unix(delivery.Timestamp, 0)
	fmt.Printf("\n[%s] %s: %s\n", timestamp.Format("15:04:05"), delivery.From, decryptedMessage)
}

// handleOfflineMessage handles offline message delivery
func (c *Client) handleOfflineMessage(response *protocol.Message) {
	var offline protocol.OfflineMessage
	if err := response.ParseData(&offline); err != nil {
		log.Printf("Failed to parse offline message: %v", err)
		return
	}

	// Decrypt the message using appropriate key (session or static)
	var decryptedMessage string
	var err error

	if offline.SessionID != "" {
		// Use session key if available
		if sessionKeys, exists := c.sessionKeys[offline.SessionID]; exists {
			sessionCrypto := crypto.NewSessionCrypto(sessionKeys)
			decryptedMessage, err = sessionCrypto.Decrypt(offline.Message)
		} else {
			log.Printf("Session key not found for session %s, falling back to static key", offline.SessionID)
			decryptedMessage, err = c.userCrypto.Decrypt(offline.Message)
		}
	} else {
		// Use static key
		decryptedMessage, err = c.userCrypto.Decrypt(offline.Message)
	}

	if err != nil {
		log.Printf("Failed to decrypt offline message from %s: %v", offline.From, err)
		return
	}

	timestamp := time.Unix(offline.Timestamp, 0)
	fmt.Printf("\n[OFFLINE %s] %s: %s\n", timestamp.Format("15:04:05"), offline.From, decryptedMessage)
}

// handleKeyExchangeRequest handles incoming key exchange requests for PFS
func (c *Client) handleKeyExchangeRequest(response *protocol.Message) {
	var keyReq protocol.KeyExchangeRequest
	if err := response.ParseData(&keyReq); err != nil {
		log.Printf("Failed to parse key exchange request: %v", err)
		return
	}

	fmt.Printf("Received key exchange request from %s for session %s\n", keyReq.To, keyReq.SessionID)

	// 1. Generate our DH key pair
	keyPair, err := crypto.GenerateDHKeyPair()
	if err != nil {
		log.Printf("Failed to generate DH key pair: %v", err)
		return
	}

	// 2. Decode their public key
	theirPublicKey, err := base64.StdEncoding.DecodeString(keyReq.PublicKey)
	if err != nil {
		log.Printf("Failed to decode their public key: %v", err)
		return
	}

	// 3. Compute shared secret
	sharedSecret, err := crypto.ComputeSharedSecret(keyPair.PrivateKey, theirPublicKey)
	if err != nil {
		log.Printf("Failed to compute shared secret: %v", err)
		return
	}

	// 4. Derive session keys
	salt, err := crypto.GenerateSalt()
	if err != nil {
		log.Printf("Failed to generate salt: %v", err)
		return
	}

	sessionKeys, err := crypto.DeriveSessionKeys(sharedSecret, keyReq.SessionID, salt)
	if err != nil {
		log.Printf("Failed to derive session keys: %v", err)
		return
	}

	// 5. Store session keys
	c.sessionKeys[keyReq.SessionID] = sessionKeys
	// Note: keyReq.To is actually the sender (initiator)
	c.recipientSessions[keyReq.To] = keyReq.SessionID

	// 6. Send our public key back
	publicKeyB64 := base64.StdEncoding.EncodeToString(keyPair.PublicKey)
	keyResp := protocol.KeyExchangeResponse{
		From:      c.username,
		PublicKey: publicKeyB64,
		SessionID: keyReq.SessionID,
	}

	msg := protocol.NewMessage(protocol.MsgTypeKeyResponse, keyResp)
	msg.ID = uuid.New().String()

	if err := c.sendMessage(msg); err != nil {
		log.Printf("Failed to send key exchange response: %v", err)
		// Clean up on failure
		delete(c.sessionKeys, keyReq.SessionID)
		delete(c.recipientSessions, keyReq.To)
		return
	}

	fmt.Printf("Key exchange completed with %s (session: %s)\n", keyReq.To, keyReq.SessionID)
}

// handleKeyExchangeResponse handles key exchange responses
func (c *Client) handleKeyExchangeResponse(response *protocol.Message) {
	var keyResp protocol.KeyExchangeResponse
	if err := response.ParseData(&keyResp); err != nil {
		logging.ErrorWithError("Failed to parse key exchange response", err, map[string]string{"from": keyResp.From})
		return
	}

	fmt.Printf("Received key exchange response from %s for session %s\n", keyResp.From, keyResp.SessionID)

	// 1. Check if we have a pending key exchange for this session
	ourKeyPair, exists := c.pendingKeyExchange[keyResp.SessionID]
	if !exists {
		logging.Warn("No pending key exchange found", map[string]string{"session_id": keyResp.SessionID})
		return
	}

	// 2. Decode their public key
	theirPublicKey, err := base64.StdEncoding.DecodeString(keyResp.PublicKey)
	if err != nil {
		log.Printf("Failed to decode their public key: %v", err)
		delete(c.pendingKeyExchange, keyResp.SessionID)
		return
	}

	// 3. Compute shared secret
	sharedSecret, err := crypto.ComputeSharedSecret(ourKeyPair.PrivateKey, theirPublicKey)
	if err != nil {
		log.Printf("Failed to compute shared secret: %v", err)
		delete(c.pendingKeyExchange, keyResp.SessionID)
		return
	}

	// 4. Derive session keys
	salt, err := crypto.GenerateSalt()
	if err != nil {
		log.Printf("Failed to generate salt: %v", err)
		delete(c.pendingKeyExchange, keyResp.SessionID)
		return
	}

	sessionKeys, err := crypto.DeriveSessionKeys(sharedSecret, keyResp.SessionID, salt)
	if err != nil {
		log.Printf("Failed to derive session keys: %v", err)
		delete(c.pendingKeyExchange, keyResp.SessionID)
		return
	}

	// 5. Store session keys
	c.sessionKeys[keyResp.SessionID] = sessionKeys
	c.recipientSessions[keyResp.From] = keyResp.SessionID

	// 6. Signal any waiting goroutines
	if waiterChan, exists := c.keyExchangeWaiters[keyResp.SessionID]; exists {
		select {
		case waiterChan <- sessionKeys:
			// Successfully signaled the waiter
		default:
			// Channel is full or closed, just continue
		}
	}

	// 7. Clean up pending exchange
	delete(c.pendingKeyExchange, keyResp.SessionID)

	fmt.Printf("Key exchange completed with %s (session: %s)\n", keyResp.From, keyResp.SessionID)
}

// ListUsers gets the list of online users
func (c *Client) ListUsers() error {
	if err := c.loadUserConfig(); err != nil {
		return fmt.Errorf("not registered or config missing: %w", err)
	}

	if err := c.Connect(); err != nil {
		return err
	}
	defer c.Disconnect()

	// Authenticate first
	if err := c.authenticate(); err != nil {
		return fmt.Errorf("authentication failed: %w", err)
	}

	// Send list users request
	msg := protocol.NewMessage(protocol.MsgTypeListUsers, nil)
	msg.ID = uuid.New().String()

	if err := c.sendMessage(msg); err != nil {
		return fmt.Errorf("failed to send list users request: %w", err)
	}

	// Wait for response
	response, err := c.readMessage()
	if err != nil {
		return fmt.Errorf("failed to read response: %w", err)
	}

	if response.Type == protocol.MsgTypeError {
		var errorResp protocol.ErrorResponse
		if err := response.ParseData(&errorResp); err != nil {
			return fmt.Errorf("list users failed with unknown error")
		}
		return fmt.Errorf("list users failed: %s", errorResp.Message)
	}

	if response.Type != protocol.MsgTypeUserList {
		return fmt.Errorf("unexpected response type: %s", response.Type)
	}

	var userList protocol.UserListResponse
	if err := response.ParseData(&userList); err != nil {
		return fmt.Errorf("failed to parse user list: %w", err)
	}

	fmt.Printf("Online users:\n")
	for _, user := range userList.Users {
		fmt.Printf("- %s\n", user)
	}

	return nil
}

// heartbeat sends periodic heartbeat messages
func (c *Client) heartbeat() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		if !c.isListening {
			return
		}

		msg := protocol.NewMessage(protocol.MsgTypeHeartbeat, nil)
		msg.ID = uuid.New().String()

		if err := c.sendMessage(msg); err != nil {
			log.Printf("Failed to send heartbeat: %v", err)
		}
	}
}

// sendMessage sends a message over WebSocket
func (c *Client) sendMessage(msg *protocol.Message) error {
	msgBytes, err := msg.Marshal()
	if err != nil {
		return err
	}

	return c.conn.WriteMessage(websocket.TextMessage, msgBytes)
}

// readMessage reads a message from WebSocket
func (c *Client) readMessage() (*protocol.Message, error) {
	_, messageData, err := c.conn.ReadMessage()
	if err != nil {
		return nil, err
	}

	return protocol.UnmarshalMessage(messageData)
}

// saveUserConfig saves user configuration to disk
func (c *Client) saveUserConfig(config *UserConfig) error {
	configPath := c.getUserConfigPath()

	data, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(configPath, data, 0600)
}

// loadUserConfig loads user configuration from disk
func (c *Client) loadUserConfig() error {
	configPath := c.getUserConfigPath()

	data, err := os.ReadFile(configPath)
	if err != nil {
		return err
	}

	var config UserConfig
	if err := json.Unmarshal(data, &config); err != nil {
		return err
	}

	c.username = config.Username

	// Decode salt and create crypto instance
	salt, err := base64.StdEncoding.DecodeString(config.Salt)
	if err != nil {
		return fmt.Errorf("failed to decode salt: %w", err)
	}

	c.userCrypto = crypto.NewUserCrypto(config.Token, salt)
	return nil
}

// getUserConfigPath returns the path to user configuration file
func (c *Client) getUserConfigPath() string {
	return filepath.Join(c.configDir, "user.json")
}

// StopListening stops the listening loop
func (c *Client) StopListening() {
	c.isListening = false
}
