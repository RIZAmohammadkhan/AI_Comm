package server

import (
	"encoding/base64"
	"fmt"
	"log"
	"net/http"
	"strings"
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
	readBuffer    []byte     // Reusable read buffer
	mu            sync.Mutex // Protects connection state
}

// Server manages WebSocket connections and message routing
type Server struct {
	database    *db.Database
	connections sync.Map // map[string]*Connection - concurrent-safe map
	register    chan *Connection
	unregister  chan *Connection
	broadcast   chan []byte
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
		database:   database,
		register:   make(chan *Connection),
		unregister: make(chan *Connection),
		broadcast:  make(chan []byte),
		globalRate: rate.NewLimiter(rate.Limit(100), 200), // 100 req/sec, burst 200
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
			s.connections.Store(conn.username, conn)
			logging.Info("User connected", map[string]string{"username": conn.username})

		case conn := <-s.unregister:
			if _, ok := s.connections.LoadAndDelete(conn.username); ok {
				close(conn.send)
				logging.Info("User disconnected", map[string]string{"username": conn.username})
			}

		case message := <-s.broadcast:
			s.connections.Range(func(key, value interface{}) bool {
				conn := value.(*Connection)
				select {
				case conn.send <- message:
				default:
					s.connections.Delete(key)
					close(conn.send)
				}
				return true
			})
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
	if err := c.ws.SetReadDeadline(time.Now().Add(60 * time.Second)); err != nil {
		log.Printf("Failed to set read deadline: %v", err)
	}
	c.ws.SetPongHandler(func(string) error {
		if err := c.ws.SetReadDeadline(time.Now().Add(60 * time.Second)); err != nil {
			log.Printf("Failed to set read deadline in pong handler: %v", err)
		}
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
			if err := c.ws.SetWriteDeadline(time.Now().Add(10 * time.Second)); err != nil {
				// Connection might already be closed, just return silently
				return
			}
			if !ok {
				// Channel closed, try to send close message but ignore errors
				_ = c.ws.WriteMessage(websocket.CloseMessage, []byte{})
				return
			}

			if err := c.ws.WriteMessage(websocket.TextMessage, message); err != nil {
				return
			}

		case <-ticker.C:
			if err := c.ws.SetWriteDeadline(time.Now().Add(10 * time.Second)); err != nil {
				log.Printf("Failed to set write deadline for ping: %v", err)
				return
			}
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
		logging.ErrorWithError("Failed to generate user token for registration", err, map[string]string{"username": req.Username})
		c.sendError(500, "Failed to generate user token")
		return
	}

	salt, err := crypto.GenerateSalt()
	if err != nil {
		logging.ErrorWithError("Failed to generate salt for registration", err, map[string]string{"username": req.Username})
		c.sendError(500, "Failed to generate salt")
		return
	}

	user := &db.User{
		Username: req.Username,
		Token:    token,
		Salt:     salt,
	}

	if err := c.server.database.CreateUser(user); err != nil {
		// Check if it's a duplicate user error (expected behavior)
		if strings.Contains(err.Error(), "already exists") {
			logging.Warn("User registration rejected - username already exists", map[string]string{"username": req.Username})
		} else {
			logging.ErrorWithError("Failed to create user in database", err, map[string]string{"username": req.Username})
		}
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
	c.mu.Lock()
	isAuthenticated := c.authenticated
	username := c.username
	c.mu.Unlock()

	if !isAuthenticated {
		c.sendError(401, "Not authenticated")
		return
	}

	var req protocol.SecureMessage
	if err := msg.ParseData(&req); err != nil {
		c.sendError(400, "Invalid send data")
		return
	}

	// Find target connection
	value, exists := c.server.connections.Load(req.To)
	if !exists {
		// Store message for offline delivery
		offlineMsg := &db.OfflineMessage{
			MessageID: uuid.New().String(),
			From:      username,
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
		if err := c.server.database.UpdateLastSeen(username); err != nil {
			log.Printf("Failed to update last seen for %s: %v", username, err)
		}
		return
	}

	targetConn := value.(*Connection)

	// Create message delivery with session info
	delivery := protocol.OfflineMessage{
		From:      username,
		Message:   req.Message,
		SessionID: req.SessionID,
		Timestamp: time.Now().Unix(),
		MessageID: uuid.New().String(),
	}

	targetConn.sendMessage(protocol.MsgTypeMessage, delivery)
	c.sendMessage(protocol.MsgTypeAck, map[string]string{"status": "delivered"})

	// Update last seen
	if err := c.server.database.UpdateLastSeen(username); err != nil {
		log.Printf("Failed to update last seen for %s: %v", username, err)
	}
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
		if err := c.server.database.DeleteAuthChallenge(req.Username); err != nil {
			log.Printf("Failed to delete expired auth challenge for %s: %v", req.Username, err)
		}
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
	c.mu.Lock()
	c.username = req.Username
	c.authenticated = true
	c.mu.Unlock()

	c.server.register <- c

	// Clean up challenge
	if err := c.server.database.DeleteAuthChallenge(req.Username); err != nil {
		log.Printf("Failed to delete auth challenge for %s: %v", req.Username, err)
	}

	// Send offline messages if any
	c.deliverOfflineMessages()

	c.sendMessage(protocol.MsgTypeAck, map[string]string{"status": "authenticated"})
}

// handleKeyExchange processes Diffie-Hellman key exchange for PFS
func (c *Connection) handleKeyExchange(msg *protocol.Message) {
	c.mu.Lock()
	isAuthenticated := c.authenticated
	username := c.username
	c.mu.Unlock()

	if !isAuthenticated {
		c.sendError(401, "Not authenticated")
		return
	}

	var req protocol.KeyExchangeRequest
	if err := msg.ParseData(&req); err != nil {
		c.sendError(400, "Invalid key exchange data")
		return
	}

	// Find target connection
	value, exists := c.server.connections.Load(req.To)
	if !exists {
		c.sendError(404, "User not found or offline")
		return
	}

	targetConn := value.(*Connection)

	// Forward key exchange request
	keyRequest := protocol.KeyExchangeRequest{
		To:        req.To,
		PublicKey: req.PublicKey,
		SessionID: req.SessionID,
	}

	// Store session info
	session := &db.Session{
		SessionID:    req.SessionID,
		Participants: []string{username, req.To},
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
	c.mu.Lock()
	username := c.username
	c.mu.Unlock()

	messages, err := c.server.database.GetOfflineMessages(username)
	if err != nil {
		logging.Error("Failed to get offline messages", map[string]string{
			"username": username,
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
		if err := c.server.database.MarkMessageDelivered(username, msg.MessageID); err != nil {
			logging.Error("Failed to mark message as delivered", map[string]string{
				"username":   username,
				"message_id": msg.MessageID,
				"error":      err.Error(),
			})
		}
	}

	if len(messages) > 0 {
		logging.Info("Delivered offline messages", map[string]string{
			"username": username,
			"count":    fmt.Sprintf("%d", len(messages)),
		})
	}
}

// handleListen acknowledges that the client is ready to receive messages
func (c *Connection) handleListen(msg *protocol.Message) {
	c.mu.Lock()
	isAuthenticated := c.authenticated
	username := c.username
	c.mu.Unlock()

	if !isAuthenticated {
		c.sendError(401, "Not authenticated")
		return
	}

	c.sendMessage(protocol.MsgTypeAck, map[string]string{"status": "listening"})
	if err := c.server.database.UpdateLastSeen(username); err != nil {
		log.Printf("Failed to update last seen for %s: %v", username, err)
	}
}

// handleListUsers returns list of online users
func (c *Connection) handleListUsers(msg *protocol.Message) {
	c.mu.Lock()
	isAuthenticated := c.authenticated
	username := c.username
	c.mu.Unlock()

	if !isAuthenticated {
		c.sendError(401, "Not authenticated")
		return
	}

	var users []string
	c.server.connections.Range(func(key, value interface{}) bool {
		connUsername := key.(string)
		if connUsername != username { // Don't include self
			users = append(users, connUsername)
		}
		return true
	})

	response := protocol.UserListResponse{Users: users}
	c.sendMessage(protocol.MsgTypeUserList, response)
}

// handleHeartbeat processes heartbeat messages
func (c *Connection) handleHeartbeat(msg *protocol.Message) {
	c.mu.Lock()
	isAuthenticated := c.authenticated
	username := c.username
	c.mu.Unlock()

	if isAuthenticated && username != "" {
		if err := c.server.database.UpdateLastSeen(username); err != nil {
			log.Printf("Failed to update last seen for %s: %v", username, err)
		}
	}
	c.sendMessage(protocol.MsgTypeAck, map[string]string{"status": "ok"})
}

// sendMessage sends a message to the client with protection against concurrent writes
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
