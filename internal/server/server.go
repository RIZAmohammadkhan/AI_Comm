package server

import (
	"encoding/base64"
	"fmt"
	"log"
	"net/http"
	"sync"
	"time"

	"aimessage/internal/crypto"
	"aimessage/internal/db"
	"aimessage/internal/logging"
	"aimessage/internal/protocol"

	"github.com/google/uuid"
	"github.com/gorilla/websocket"
	"golang.org/x/time/rate"
)

// Connection represents a WebSocket connection
type Connection struct {
	ws            *websocket.Conn
	username      string
	send          chan []byte
	server        *Server
	limiter       *rate.Limiter
	authenticated bool
	readBuffer    []byte // Reusable read buffer
}

// Server manages WebSocket connections and message routing
type Server struct {
	database    *db.Database
	connections map[string]*Connection
	register    chan *Connection
	unregister  chan *Connection
	broadcast   chan []byte
	mutex       sync.RWMutex
	upgrader    websocket.Upgrader
	globalRate  *rate.Limiter
}

// NewServer creates a new server instance
func NewServer(dbPath string) (*Server, error) {
	database, err := db.NewDatabase(dbPath)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize database: %w", err)
	}

	server := &Server{
		database:    database,
		connections: make(map[string]*Connection),
		register:    make(chan *Connection),
		unregister:  make(chan *Connection),
		broadcast:   make(chan []byte),
		globalRate:  rate.NewLimiter(rate.Limit(100), 200), // 100 req/sec, burst 200
		upgrader: websocket.Upgrader{
			CheckOrigin: func(r *http.Request) bool {
				// Allow localhost and same-origin only for security
				origin := r.Header.Get("Origin")
				return origin == "" || origin == "http://localhost:8080" || origin == "https://localhost:8080"
			},
		},
	}

	// Start cleanup routine
	go server.cleanupRoutine()

	return server, nil
}

// Run starts the server hub
func (s *Server) Run() {
	for {
		select {
		case conn := <-s.register:
			s.mutex.Lock()
			s.connections[conn.username] = conn
			s.mutex.Unlock()
			logging.Info("User connected", map[string]string{"username": conn.username})

		case conn := <-s.unregister:
			s.mutex.Lock()
			if _, ok := s.connections[conn.username]; ok {
				delete(s.connections, conn.username)
				close(conn.send)
				logging.Info("User disconnected", map[string]string{"username": conn.username})
			}
			s.mutex.Unlock()

		case message := <-s.broadcast:
			s.mutex.RLock()
			for _, conn := range s.connections {
				select {
				case conn.send <- message:
				default:
					delete(s.connections, conn.username)
					close(conn.send)
				}
			}
			s.mutex.RUnlock()
		}
	}
}

// HandleWebSocket handles WebSocket connections
func (s *Server) HandleWebSocket(w http.ResponseWriter, r *http.Request) {
	// Rate limiting check
	if !s.globalRate.Allow() {
		http.Error(w, "Rate limit exceeded", http.StatusTooManyRequests)
		return
	}

	ws, err := s.upgrader.Upgrade(w, r, nil)
	if err != nil {
		logging.Error("WebSocket upgrade failed", map[string]string{"error": err.Error()})
		return
	}

	conn := &Connection{
		ws:         ws,
		send:       make(chan []byte, 64), // Reduced from 256 to 64 for memory efficiency
		server:     s,
		limiter:    rate.NewLimiter(rate.Limit(10), 20), // 10 req/sec per connection
		readBuffer: make([]byte, 0, 512),                // Pre-allocate read buffer
	}

	go conn.writePump()
	go conn.readPump()
}

// readPump handles incoming messages from the WebSocket
func (c *Connection) readPump() {
	defer func() {
		if c.username != "" {
			c.server.unregister <- c
		}
		c.ws.Close()
	}()

	c.ws.SetReadLimit(512) // Reduced from 1024 for memory efficiency
	c.ws.SetReadDeadline(time.Now().Add(60 * time.Second))
	c.ws.SetPongHandler(func(string) error {
		c.ws.SetReadDeadline(time.Now().Add(60 * time.Second))
		return nil
	})

	for {
		// Rate limit per connection
		if !c.limiter.Allow() {
			c.sendError(429, "Rate limit exceeded")
			// Break out of loop to avoid spamming rate limit errors
			break
		}

		_, messageData, err := c.ws.ReadMessage()
		if err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
				log.Printf("WebSocket error: %v", err)
			}
			break
		}

		msg, err := protocol.UnmarshalMessage(messageData)
		if err != nil {
			c.sendError(400, "Invalid message format")
			continue
		}

		c.handleMessage(msg)
	}
}

// writePump handles outgoing messages to the WebSocket
func (c *Connection) writePump() {
	ticker := time.NewTicker(54 * time.Second)
	defer func() {
		ticker.Stop()
		c.ws.Close()
	}()

	for {
		select {
		case message, ok := <-c.send:
			c.ws.SetWriteDeadline(time.Now().Add(10 * time.Second))
			if !ok {
				c.ws.WriteMessage(websocket.CloseMessage, []byte{})
				return
			}

			if err := c.ws.WriteMessage(websocket.TextMessage, message); err != nil {
				return
			}

		case <-ticker.C:
			c.ws.SetWriteDeadline(time.Now().Add(10 * time.Second))
			if err := c.ws.WriteMessage(websocket.PingMessage, nil); err != nil {
				return
			}
		}
	}
}

// handleMessage processes incoming messages based on type
func (c *Connection) handleMessage(msg *protocol.Message) {
	switch msg.Type {
	case protocol.MsgTypeRegister:
		c.handleRegister(msg)
	case protocol.MsgTypeAuthenticate:
		c.handleAuthenticate(msg)
	case protocol.MsgTypeSend:
		c.handleSend(msg)
	case protocol.MsgTypeKeyExchange:
		c.handleKeyExchange(msg)
	case protocol.MsgTypeListen:
		c.handleListen(msg)
	case protocol.MsgTypeListUsers:
		c.handleListUsers(msg)
	case protocol.MsgTypeHeartbeat:
		c.handleHeartbeat(msg)
	default:
		c.sendError(400, "Unknown message type")
	}
}

// handleRegister processes user registration
func (c *Connection) handleRegister(msg *protocol.Message) {
	var req protocol.RegisterRequest
	if err := msg.ParseData(&req); err != nil {
		c.sendError(400, "Invalid registration data")
		return
	}

	// Validate username (simple but effective)
	if len(req.Username) < 3 || len(req.Username) > 32 {
		c.sendError(400, "Username must be 3-32 characters")
		return
	}

	// Only allow alphanumeric, dash, underscore
	for _, char := range req.Username {
		if !((char >= 'a' && char <= 'z') || (char >= 'A' && char <= 'Z') ||
			(char >= '0' && char <= '9') || char == '-' || char == '_') {
			c.sendError(400, "Username contains invalid characters")
			return
		}
	}

	// Generate token and salt for the user
	token, err := crypto.GenerateUserToken()
	if err != nil {
		c.sendError(500, "Failed to generate user token")
		return
	}

	salt, err := crypto.GenerateSalt()
	if err != nil {
		c.sendError(500, "Failed to generate salt")
		return
	}

	user := &db.User{
		Username: req.Username,
		Token:    token,
		Salt:     salt,
	}

	if err := c.server.database.CreateUser(user); err != nil {
		c.sendError(409, fmt.Sprintf("Registration failed: %v", err))
		return
	}

	// Don't automatically authenticate - user must authenticate separately
	// Send registration response
	response := protocol.RegisterResponse{
		Token:    token,
		Salt:     base64.StdEncoding.EncodeToString(salt),
		Username: req.Username,
	}

	c.sendMessage(protocol.MsgTypeRegistered, response)
}

// handleSend processes message sending
func (c *Connection) handleSend(msg *protocol.Message) {
	if !c.authenticated {
		c.sendError(401, "Not authenticated")
		return
	}

	var req protocol.SecureMessage
	if err := msg.ParseData(&req); err != nil {
		c.sendError(400, "Invalid send data")
		return
	}

	// Find target connection
	c.server.mutex.RLock()
	targetConn, exists := c.server.connections[req.To]
	c.server.mutex.RUnlock()

	if !exists {
		// Store message for offline delivery
		offlineMsg := &db.OfflineMessage{
			MessageID: uuid.New().String(),
			From:      c.username,
			To:        req.To,
			Message:   req.Message,
			SessionID: req.SessionID,
			Timestamp: time.Now().Unix(),
			Delivered: false,
		}

		if err := c.server.database.StoreOfflineMessage(offlineMsg); err != nil {
			c.sendError(500, "Failed to store offline message")
			return
		}

		c.sendMessage(protocol.MsgTypeAck, map[string]string{"status": "stored_offline"})
		c.server.database.UpdateLastSeen(c.username)
		return
	}

	// Create message delivery with session info
	delivery := protocol.OfflineMessage{
		From:      c.username,
		Message:   req.Message,
		SessionID: req.SessionID,
		Timestamp: time.Now().Unix(),
		MessageID: uuid.New().String(),
	}

	targetConn.sendMessage(protocol.MsgTypeMessage, delivery)
	c.sendMessage(protocol.MsgTypeAck, map[string]string{"status": "delivered"})

	// Update last seen
	c.server.database.UpdateLastSeen(c.username)
}

// handleAuthenticate processes authentication with challenge-response
func (c *Connection) handleAuthenticate(msg *protocol.Message) {
	var req protocol.AuthenticationRequest
	if err := msg.ParseData(&req); err != nil {
		c.sendError(400, "Invalid authentication data")
		return
	}

	// Get user from database
	user, err := c.server.database.GetUser(req.Username)
	if err != nil {
		c.sendError(401, "Invalid credentials")
		return
	}

	if req.Challenge == "" {
		// First step: send challenge
		challenge, err := crypto.GenerateUserToken() // Reuse secure token generation
		if err != nil {
			c.sendError(500, "Failed to generate challenge")
			return
		}

		authChallenge := &db.AuthChallenge{
			Username:  req.Username,
			Challenge: challenge,
			CreatedAt: time.Now(),
			ExpiresAt: time.Now().Add(5 * time.Minute),
		}

		if err := c.server.database.StoreAuthChallenge(authChallenge); err != nil {
			c.sendError(500, "Failed to store challenge")
			return
		}

		challengeResp := protocol.ChallengeRequest{
			Challenge: challenge,
			Timestamp: time.Now().Unix(),
		}

		c.sendMessage(protocol.MsgTypeChallenge, challengeResp)
		return
	}

	// Second step: verify challenge response
	storedChallenge, err := c.server.database.GetAuthChallenge(req.Username)
	if err != nil {
		c.sendError(401, "Challenge expired or invalid")
		return
	}

	if time.Now().After(storedChallenge.ExpiresAt) {
		c.server.database.DeleteAuthChallenge(req.Username)
		c.sendError(401, "Challenge expired")
		return
	}

	// Verify the challenge response using user's crypto
	userCrypto := crypto.NewUserCrypto(user.Token, user.Salt)
	decryptedChallenge, err := userCrypto.Decrypt(req.Challenge)
	if err != nil {
		c.sendError(401, "Invalid challenge response")
		return
	}

	if decryptedChallenge != storedChallenge.Challenge {
		c.sendError(401, "Invalid challenge response")
		return
	}

	// Authentication successful
	c.username = req.Username
	c.authenticated = true
	c.server.register <- c

	// Clean up challenge
	c.server.database.DeleteAuthChallenge(req.Username)

	// Send offline messages if any
	c.deliverOfflineMessages()

	c.sendMessage(protocol.MsgTypeAck, map[string]string{"status": "authenticated"})
}

// handleKeyExchange processes Diffie-Hellman key exchange for PFS
func (c *Connection) handleKeyExchange(msg *protocol.Message) {
	if !c.authenticated {
		c.sendError(401, "Not authenticated")
		return
	}

	var req protocol.KeyExchangeRequest
	if err := msg.ParseData(&req); err != nil {
		c.sendError(400, "Invalid key exchange data")
		return
	}

	// Find target connection
	c.server.mutex.RLock()
	targetConn, exists := c.server.connections[req.To]
	c.server.mutex.RUnlock()

	if !exists {
		c.sendError(404, "User not found or offline")
		return
	}

	// Forward key exchange request
	keyRequest := protocol.KeyExchangeRequest{
		To:        req.To,
		PublicKey: req.PublicKey,
		SessionID: req.SessionID,
	}

	// Store session info
	session := &db.Session{
		SessionID:    req.SessionID,
		Participants: []string{c.username, req.To},
		CreatedAt:    time.Now(),
		LastUsed:     time.Now(),
		ExpiresAt:    time.Now().Add(24 * time.Hour), // Sessions expire after 24 hours
	}

	if err := c.server.database.StoreSession(session); err != nil {
		c.sendError(500, "Failed to store session")
		return
	}

	targetConn.sendMessage(protocol.MsgTypeKeyRequest, keyRequest)
	c.sendMessage(protocol.MsgTypeAck, map[string]string{"status": "key_exchange_initiated"})
}

// deliverOfflineMessages delivers any stored offline messages to the user
func (c *Connection) deliverOfflineMessages() {
	messages, err := c.server.database.GetOfflineMessages(c.username)
	if err != nil {
		logging.Error("Failed to get offline messages", map[string]string{
			"username": c.username,
			"error":    err.Error(),
		})
		return
	}

	for _, msg := range messages {
		offlineDelivery := protocol.OfflineMessage{
			From:      msg.From,
			Message:   msg.Message,
			SessionID: msg.SessionID,
			Timestamp: msg.Timestamp,
			MessageID: msg.MessageID,
		}

		c.sendMessage(protocol.MsgTypeOfflineMsg, offlineDelivery)

		// Mark as delivered
		if err := c.server.database.MarkMessageDelivered(c.username, msg.MessageID); err != nil {
			logging.Error("Failed to mark message as delivered", map[string]string{
				"username":   c.username,
				"message_id": msg.MessageID,
				"error":      err.Error(),
			})
		}
	}

	if len(messages) > 0 {
		logging.Info("Delivered offline messages", map[string]string{
			"username": c.username,
			"count":    fmt.Sprintf("%d", len(messages)),
		})
	}
}

// handleListen acknowledges that the client is ready to receive messages
func (c *Connection) handleListen(msg *protocol.Message) {
	if !c.authenticated {
		c.sendError(401, "Not authenticated")
		return
	}

	c.sendMessage(protocol.MsgTypeAck, map[string]string{"status": "listening"})
	c.server.database.UpdateLastSeen(c.username)
}

// handleListUsers returns list of online users
func (c *Connection) handleListUsers(msg *protocol.Message) {
	if !c.authenticated {
		c.sendError(401, "Not authenticated")
		return
	}

	c.server.mutex.RLock()
	users := make([]string, 0, len(c.server.connections))
	for username := range c.server.connections {
		if username != c.username { // Don't include self
			users = append(users, username)
		}
	}
	c.server.mutex.RUnlock()

	response := protocol.UserListResponse{Users: users}
	c.sendMessage(protocol.MsgTypeUserList, response)
}

// handleHeartbeat processes heartbeat messages
func (c *Connection) handleHeartbeat(msg *protocol.Message) {
	if c.authenticated && c.username != "" {
		c.server.database.UpdateLastSeen(c.username)
	}
	c.sendMessage(protocol.MsgTypeAck, map[string]string{"status": "ok"})
}

// sendMessage sends a message to the client
func (c *Connection) sendMessage(msgType protocol.MessageType, data interface{}) {
	msg := protocol.NewMessage(msgType, data)
	msg.ID = uuid.New().String()

	msgBytes, err := msg.Marshal()
	if err != nil {
		log.Printf("Failed to marshal message: %v", err)
		return
	}

	select {
	case c.send <- msgBytes:
	default:
		// Channel is full, connection is likely dead - don't close here
		// Let the unregister process handle cleanup
		log.Printf("Failed to send message: channel full")
	}
}

// sendError sends an error message to the client
func (c *Connection) sendError(code int, message string) {
	errorResp := protocol.ErrorResponse{
		Code:    code,
		Message: message,
	}
	c.sendMessage(protocol.MsgTypeError, errorResp)
}

// Close shuts down the server
func (s *Server) Close() error {
	return s.database.Close()
}

// cleanupRoutine periodically cleans up expired sessions and challenges
func (s *Server) cleanupRoutine() {
	cleanupTicker := time.NewTicker(5 * time.Minute) // More frequent cleanup for memory efficiency
	gcTicker := time.NewTicker(15 * time.Minute)     // Garbage collection every 15 minutes
	defer cleanupTicker.Stop()
	defer gcTicker.Stop()

	for {
		select {
		case <-cleanupTicker.C:
			// Run cleanup operations asynchronously to avoid blocking
			go func() {
				if err := s.database.CleanupExpiredSessions(); err != nil {
					logging.Error("Failed to cleanup expired sessions", map[string]string{"error": err.Error()})
				}
			}()

			go func() {
				if err := s.database.CleanupExpiredChallenges(); err != nil {
					logging.Error("Failed to cleanup expired challenges", map[string]string{"error": err.Error()})
				}
			}()

		case <-gcTicker.C:
			// Run garbage collection to reclaim space
			go func() {
				if err := s.database.RunGarbageCollection(); err != nil {
					logging.Warn("Garbage collection completed", map[string]string{"info": "completed"})
				}
			}()
		}
	}
}
