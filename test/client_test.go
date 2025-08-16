package test

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"aimessage/internal/client"
	"aimessage/internal/crypto"
	"aimessage/internal/protocol"

	"github.com/gorilla/websocket"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// MockWebSocketServer provides a test WebSocket server
type MockWebSocketServer struct {
	server   *httptest.Server
	upgrader websocket.Upgrader
	messages chan []byte
	conn     *websocket.Conn
	mu       sync.Mutex
}

func NewMockWebSocketServer() *MockWebSocketServer {
	mock := &MockWebSocketServer{
		upgrader: websocket.Upgrader{
			CheckOrigin: func(r *http.Request) bool { return true },
		},
		messages: make(chan []byte, 100),
	}

	mock.server = httptest.NewServer(http.HandlerFunc(mock.handleWebSocket))
	return mock
}

func (m *MockWebSocketServer) handleWebSocket(w http.ResponseWriter, r *http.Request) {
	conn, err := m.upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}

	m.mu.Lock()
	m.conn = conn
	m.mu.Unlock()

	defer conn.Close()

	for {
		_, message, err := conn.ReadMessage()
		if err != nil {
			break
		}
		m.messages <- message
	}
}

func (m *MockWebSocketServer) SendMessage(msgType protocol.MessageType, data interface{}) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.conn == nil {
		return assert.AnError
	}

	msg := protocol.NewMessage(msgType, data)
	msgBytes, err := msg.Marshal()
	if err != nil {
		return err
	}

	return m.conn.WriteMessage(websocket.TextMessage, msgBytes)
}

func (m *MockWebSocketServer) GetURL() string {
	return "ws" + strings.TrimPrefix(m.server.URL, "http")
}

func (m *MockWebSocketServer) Close() {
	m.server.Close()
}

func (m *MockWebSocketServer) WaitForMessage(timeout time.Duration) ([]byte, error) {
	select {
	case msg := <-m.messages:
		return msg, nil
	case <-time.After(timeout):
		return nil, assert.AnError
	}
}

func TestNewClient(t *testing.T) {
	serverURL := "ws://localhost:8080/ws"
	c := client.NewClient(serverURL)

	assert.NotNil(t, c)
	// Test that the client was created without error
	assert.IsType(t, &client.Client{}, c)
}

func TestClientConnect(t *testing.T) {
	mock := NewMockWebSocketServer()
	defer mock.Close()

	c := client.NewClient(mock.GetURL())

	err := c.Connect()
	assert.NoError(t, err)

	err = c.Disconnect()
	assert.NoError(t, err)
}

func TestClientConnectInvalidURL(t *testing.T) {
	c := client.NewClient("invalid-url")

	err := c.Connect()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to connect to server")
}

func TestClientRegister(t *testing.T) {
	mock := NewMockWebSocketServer()
	defer mock.Close()

	c := client.NewClient(mock.GetURL())

	// Start a goroutine to handle server responses
	go func() {
		// Wait for registration message
		msgBytes, err := mock.WaitForMessage(time.Second)
		if err != nil {
			return
		}

		var msg protocol.Message
		if err := json.Unmarshal(msgBytes, &msg); err != nil {
			return
		}

		if msg.Type == protocol.MsgTypeRegister {
			// Send successful registration response
			salt, _ := crypto.GenerateSalt()
			saltB64 := base64.StdEncoding.EncodeToString(salt)
			token, _ := crypto.GenerateUserToken()

			resp := protocol.RegisterResponse{
				Username: "testuser",
				Token:    token,
				Salt:     saltB64,
			}
			mock.SendMessage(protocol.MsgTypeRegistered, resp)
		}
	}()

	err := c.Register("testuser")
	assert.NoError(t, err)

	// Verify config file was created in default location
	homeDir, _ := os.UserHomeDir()
	configPath := filepath.Join(homeDir, ".aimessage", "user.json")
	defer os.Remove(configPath) // Clean up
	assert.FileExists(t, configPath)
}

func TestClientRegisterUsernameTooShort(t *testing.T) {
	mock := NewMockWebSocketServer()
	defer mock.Close()

	c := client.NewClient(mock.GetURL())

	// Start a goroutine to handle server responses
	go func() {
		msgBytes, err := mock.WaitForMessage(time.Second)
		if err != nil {
			return
		}

		var msg protocol.Message
		if err := json.Unmarshal(msgBytes, &msg); err != nil {
			return
		}

		// Send error response for invalid username
		errorResp := protocol.ErrorResponse{
			Code:    400,
			Message: "Username must be 3-32 characters",
		}
		mock.SendMessage(protocol.MsgTypeError, errorResp)
	}()

	err := c.Register("ab") // Too short
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Username must be 3-32 characters")
}

func TestClientSendMessage(t *testing.T) {
	mock := NewMockWebSocketServer()
	defer mock.Close()

	// Set up authenticated client
	c := setupAuthenticatedClient(t, mock)

	// Handle authentication and message sending flow
	go func() {
		// Authentication flow first
		handleAuthFlow(mock)

		// Handle key exchange initiation - simulate timeout by not responding
		msgBytes, _ := mock.WaitForMessage(2 * time.Second)
		var msg protocol.Message
		json.Unmarshal(msgBytes, &msg)

		if msg.Type == protocol.MsgTypeKeyExchange {
			// Don't respond to key exchange - let it timeout and fallback
		}

		// Wait for fallback message send (with longer timeout to account for key exchange timeout)
		msgBytes, _ = mock.WaitForMessage(32 * time.Second) // Key exchange timeout is 30s
		json.Unmarshal(msgBytes, &msg)

		if msg.Type == protocol.MsgTypeSend {
			// Send acknowledgment
			mock.SendMessage(protocol.MsgTypeAck, map[string]string{"status": "delivered"})
		}
	}()

	// This should succeed using fallback encryption after key exchange times out
	err := c.SendMessage("recipient", "Hello, World!")
	assert.NoError(t, err)
}

func TestClientListUsers(t *testing.T) {
	mock := NewMockWebSocketServer()
	defer mock.Close()

	c := setupAuthenticatedClient(t, mock)

	// Handle list users flow
	go func() {
		// Authentication flow first
		handleAuthFlow(mock)

		// Wait for list users request
		msgBytes, _ := mock.WaitForMessage(2 * time.Second)
		var msg protocol.Message
		json.Unmarshal(msgBytes, &msg)

		if msg.Type == protocol.MsgTypeListUsers {
			// Send user list response
			userList := protocol.UserListResponse{
				Users: []string{"user1", "user2", "user3"},
			}
			mock.SendMessage(protocol.MsgTypeUserList, userList)
		}
	}()

	err := c.ListUsers()
	assert.NoError(t, err)
}

func TestClientStopListening(t *testing.T) {
	mock := NewMockWebSocketServer()
	defer mock.Close()

	c := client.NewClient(mock.GetURL())

	// Test that stopping listening works
	c.StopListening()

	// Should be able to call multiple times without panic
	c.StopListening()
}

func TestClientClose(t *testing.T) {
	mock := NewMockWebSocketServer()
	defer mock.Close()

	c := client.NewClient(mock.GetURL())
	err := c.Connect()
	require.NoError(t, err)

	// Test close
	c.Close()

	// Should be able to call multiple times without panic
	c.Close()
}

func TestClientSendMessageWithoutAuth(t *testing.T) {
	mock := NewMockWebSocketServer()
	defer mock.Close()

	tempDir := t.TempDir()
	c := client.NewClientWithConfigDir(mock.GetURL(), tempDir)

	err := c.SendMessage("recipient", "Hello, World!")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not registered or config missing")
}

func TestClientListUsersWithoutAuth(t *testing.T) {
	mock := NewMockWebSocketServer()
	defer mock.Close()

	tempDir := t.TempDir()
	c := client.NewClientWithConfigDir(mock.GetURL(), tempDir)

	err := c.ListUsers()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not registered or config missing")
}

func TestClientListenWithoutAuth(t *testing.T) {
	mock := NewMockWebSocketServer()
	defer mock.Close()

	tempDir := t.TempDir()
	c := client.NewClientWithConfigDir(mock.GetURL(), tempDir)

	err := c.Listen()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not registered or config missing")
}

// Helper functions for test setup

func setupAuthenticatedClient(t *testing.T, mock *MockWebSocketServer) *client.Client {
	tempDir := t.TempDir()
	c := client.NewClientWithConfigDir(mock.GetURL(), tempDir)

	// First register the user
	go func() {
		msgBytes, _ := mock.WaitForMessage(time.Second)
		var msg protocol.Message
		json.Unmarshal(msgBytes, &msg)

		if msg.Type == protocol.MsgTypeRegister {
			salt, _ := crypto.GenerateSalt()
			saltB64 := base64.StdEncoding.EncodeToString(salt)
			token, _ := crypto.GenerateUserToken()

			resp := protocol.RegisterResponse{
				Username: "testuser",
				Token:    token,
				Salt:     saltB64,
			}
			mock.SendMessage(protocol.MsgTypeRegistered, resp)
		}
	}()

	err := c.Register("testuser")
	require.NoError(t, err)

	return c
}

func handleAuthFlow(mock *MockWebSocketServer) {
	// Auth request
	msgBytes, _ := mock.WaitForMessage(time.Second)
	var msg protocol.Message
	json.Unmarshal(msgBytes, &msg)

	if msg.Type == protocol.MsgTypeAuthenticate {
		// Send challenge
		challenge := protocol.ChallengeRequest{
			Challenge: "test-challenge",
			Timestamp: time.Now().Unix(),
		}
		mock.SendMessage(protocol.MsgTypeChallenge, challenge)

		// Wait for challenge response
		msgBytes, _ = mock.WaitForMessage(time.Second)
		json.Unmarshal(msgBytes, &msg)

		if msg.Type == protocol.MsgTypeAuthenticate {
			// Send success ack
			mock.SendMessage(protocol.MsgTypeAck, map[string]string{"status": "authenticated"})
		}
	}
}

// Benchmark tests

func BenchmarkClientConnect(b *testing.B) {
	mock := NewMockWebSocketServer()
	defer mock.Close()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		c := client.NewClient(mock.GetURL())
		c.Connect()
		c.Disconnect()
	}
}

func BenchmarkClientRegister(b *testing.B) {
	mock := NewMockWebSocketServer()
	defer mock.Close()

	// Handle server responses
	go func() {
		for {
			msgBytes, err := mock.WaitForMessage(time.Second)
			if err != nil {
				continue
			}

			var msg protocol.Message
			if err := json.Unmarshal(msgBytes, &msg); err != nil {
				continue
			}

			if msg.Type == protocol.MsgTypeRegister {
				salt, _ := crypto.GenerateSalt()
				saltB64 := base64.StdEncoding.EncodeToString(salt)
				token, _ := crypto.GenerateUserToken()

				resp := protocol.RegisterResponse{
					Username: "benchuser",
					Token:    token,
					Salt:     saltB64,
				}
				mock.SendMessage(protocol.MsgTypeRegistered, resp)
			}
		}
	}()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		c := client.NewClient(mock.GetURL())
		c.Register("benchuser")
		// Clean up config file
		homeDir, _ := os.UserHomeDir()
		configPath := filepath.Join(homeDir, ".aimessage", "user.json")
		os.Remove(configPath)
	}
}

// Test concurrent operations
func TestClientConcurrency(t *testing.T) {
	mock := NewMockWebSocketServer()
	defer mock.Close()

	numClients := 10
	var wg sync.WaitGroup

	// Handle server responses for all clients
	go func() {
		for {
			msgBytes, err := mock.WaitForMessage(100 * time.Millisecond)
			if err != nil {
				continue
			}

			var msg protocol.Message
			if err := json.Unmarshal(msgBytes, &msg); err != nil {
				continue
			}

			switch msg.Type {
			case protocol.MsgTypeRegister:
				salt, _ := crypto.GenerateSalt()
				saltB64 := base64.StdEncoding.EncodeToString(salt)
				token, _ := crypto.GenerateUserToken()

				resp := protocol.RegisterResponse{
					Username: "concurrentuser",
					Token:    token,
					Salt:     saltB64,
				}
				mock.SendMessage(protocol.MsgTypeRegistered, resp)
			}
		}
	}()

	for i := 0; i < numClients; i++ {
		wg.Add(1)
		go func(clientID int) {
			defer wg.Done()

			c := client.NewClient(mock.GetURL())
			err := c.Connect()
			if err != nil {
				t.Errorf("Client %d failed to connect: %v", clientID, err)
				return
			}

			err = c.Disconnect()
			if err != nil {
				t.Errorf("Client %d failed to disconnect: %v", clientID, err)
			}
		}(i)
	}

	wg.Wait()
}
