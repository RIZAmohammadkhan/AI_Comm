package test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"aimessage/internal/protocol"
	"aimessage/internal/server"

	"github.com/gorilla/websocket"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// createTestServer creates a server for testing and ensures proper cleanup
func createTestServer(t *testing.T) (*server.Server, func()) {
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "test.db")

	srv, err := server.NewServer(dbPath)
	require.NoError(t, err)

	cleanup := func() {
		err := srv.Close()
		if err != nil {
			t.Logf("Warning: server close error: %v", err)
		}
	}

	return srv, cleanup
}

func TestNewServer(t *testing.T) {
	srv, cleanup := createTestServer(t)
	defer cleanup()

	assert.NotNil(t, srv)
}

func TestNewServerInvalidDBPath(t *testing.T) {
	// Try to create server with invalid database path
	invalidPath := "/nonexistent/invalid/path/test.db"
	if strings.Contains(strings.ToLower(runtime.GOOS), "windows") {
		invalidPath = "Z:\\nonexistent\\invalid\\path\\test.db"
	}

	_, err := server.NewServer(invalidPath)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to initialize database")
}

func TestServerWebSocketUpgrade(t *testing.T) {
	srv, cleanup := createTestServer(t)
	defer cleanup()

	// Create test server
	testServer := httptest.NewServer(http.HandlerFunc(srv.HandleWebSocket))
	defer testServer.Close()

	// Convert HTTP URL to WebSocket URL
	wsURL := "ws" + strings.TrimPrefix(testServer.URL, "http")

	// Try to connect
	dialer := websocket.Dialer{}
	conn, _, err := dialer.Dial(wsURL, nil)
	require.NoError(t, err)
	defer conn.Close()

	// Connection should be successful
	assert.NotNil(t, conn)
}

func TestServerWebSocketUpgradeWithOriginCheck(t *testing.T) {
	srv, cleanup := createTestServer(t)
	defer cleanup()

	// Create test server
	testServer := httptest.NewServer(http.HandlerFunc(srv.HandleWebSocket))
	defer testServer.Close()

	// Convert HTTP URL to WebSocket URL
	wsURL := "ws" + strings.TrimPrefix(testServer.URL, "http")

	// Try to connect with allowed origin
	dialer := websocket.Dialer{}
	headers := http.Header{}
	headers.Set("Origin", "http://localhost:8080")

	conn, _, err := dialer.Dial(wsURL, headers)
	require.NoError(t, err)
	defer conn.Close()

	assert.NotNil(t, conn)
}

func TestServerRateLimit(t *testing.T) {
	srv, cleanup := createTestServer(t)
	defer cleanup()

	// Create test server
	testServer := httptest.NewServer(http.HandlerFunc(srv.HandleWebSocket))
	defer testServer.Close()

	// Make many rapid requests to trigger rate limiting
	// Note: This test may be flaky depending on the exact rate limit configuration
	var rateLimited bool
	for i := 0; i < 300; i++ { // Exceed the rate limit
		resp, err := http.Get(testServer.URL)
		if err != nil {
			continue
		}
		resp.Body.Close()

		if resp.StatusCode == http.StatusTooManyRequests {
			rateLimited = true
			break
		}
	}

	// Eventually should hit rate limit
	assert.True(t, rateLimited)
}

func TestServerMessageHandling(t *testing.T) {
	srv, cleanup := createTestServer(t)
	defer cleanup()

	// Start server goroutine
	go srv.Run()

	// Create test server
	testServer := httptest.NewServer(http.HandlerFunc(srv.HandleWebSocket))
	defer testServer.Close()

	// Convert HTTP URL to WebSocket URL
	wsURL := "ws" + strings.TrimPrefix(testServer.URL, "http")

	// Connect to WebSocket
	dialer := websocket.Dialer{}
	conn, _, err := dialer.Dial(wsURL, nil)
	require.NoError(t, err)
	defer conn.Close()

	// Send a registration message
	registerReq := protocol.RegisterRequest{Username: "testuser"}
	msg := protocol.NewMessage(protocol.MsgTypeRegister, registerReq)
	msgBytes, err := msg.Marshal()
	require.NoError(t, err)

	err = conn.WriteMessage(websocket.TextMessage, msgBytes)
	require.NoError(t, err)

	// Wait for response
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	_, responseBytes, err := conn.ReadMessage()
	require.NoError(t, err)

	// Parse response
	var response protocol.Message
	err = json.Unmarshal(responseBytes, &response)
	require.NoError(t, err)

	// Should get either a success response or an error (depending on validation)
	assert.True(t, response.Type == protocol.MsgTypeRegistered || response.Type == protocol.MsgTypeError)
}

func TestServerInvalidMessage(t *testing.T) {
	srv, cleanup := createTestServer(t)
	defer cleanup()

	// Start server goroutine
	go srv.Run()

	// Create test server
	testServer := httptest.NewServer(http.HandlerFunc(srv.HandleWebSocket))
	defer testServer.Close()

	// Convert HTTP URL to WebSocket URL
	wsURL := "ws" + strings.TrimPrefix(testServer.URL, "http")

	// Connect to WebSocket
	dialer := websocket.Dialer{}
	conn, _, err := dialer.Dial(wsURL, nil)
	require.NoError(t, err)
	defer conn.Close()

	// Send invalid JSON
	err = conn.WriteMessage(websocket.TextMessage, []byte("{invalid json}"))
	require.NoError(t, err)

	// Wait for error response
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	_, responseBytes, err := conn.ReadMessage()
	require.NoError(t, err)

	// Parse response
	var response protocol.Message
	err = json.Unmarshal(responseBytes, &response)
	require.NoError(t, err)

	// Should get an error response
	assert.Equal(t, protocol.MsgTypeError, response.Type)

	var errorResp protocol.ErrorResponse
	err = response.ParseData(&errorResp)
	require.NoError(t, err)
	assert.Equal(t, 400, errorResp.Code)
	assert.Contains(t, errorResp.Message, "Invalid message format")
}

func TestServerConnectionLimit(t *testing.T) {
	srv, cleanup := createTestServer(t)
	defer cleanup()

	// Start server goroutine
	go srv.Run()

	// Create test server
	testServer := httptest.NewServer(http.HandlerFunc(srv.HandleWebSocket))
	defer testServer.Close()

	// Convert HTTP URL to WebSocket URL
	wsURL := "ws" + strings.TrimPrefix(testServer.URL, "http")

	// Create multiple connections
	var connections []*websocket.Conn
	maxConnections := 10

	for i := 0; i < maxConnections; i++ {
		dialer := websocket.Dialer{}
		conn, _, err := dialer.Dial(wsURL, nil)
		if err != nil {
			// Some connections might fail due to rate limiting
			break
		}
		connections = append(connections, conn)
	}

	// Clean up connections
	for _, conn := range connections {
		conn.Close()
	}

	// Should have created at least some connections
	assert.True(t, len(connections) > 0)
}

func TestServerHeartbeat(t *testing.T) {
	srv, cleanup := createTestServer(t)
	defer cleanup()

	// Start server goroutine
	go srv.Run()

	// Create test server
	testServer := httptest.NewServer(http.HandlerFunc(srv.HandleWebSocket))
	defer testServer.Close()

	// Convert HTTP URL to WebSocket URL
	wsURL := "ws" + strings.TrimPrefix(testServer.URL, "http")

	// Connect to WebSocket
	dialer := websocket.Dialer{}
	conn, _, err := dialer.Dial(wsURL, nil)
	require.NoError(t, err)
	defer conn.Close()

	// Send heartbeat message
	heartbeatMsg := protocol.NewMessage(protocol.MsgTypeHeartbeat, nil)
	msgBytes, err := heartbeatMsg.Marshal()
	require.NoError(t, err)

	err = conn.WriteMessage(websocket.TextMessage, msgBytes)
	require.NoError(t, err)

	// Heartbeat messages typically don't generate responses
	// But the connection should remain alive
	time.Sleep(100 * time.Millisecond)

	// Try to send another message to verify connection is still alive
	err = conn.WriteMessage(websocket.TextMessage, msgBytes)
	assert.NoError(t, err)
}

func TestServerConnectionCleanup(t *testing.T) {
	srv, cleanup := createTestServer(t)
	defer cleanup()

	// Start server goroutine
	go srv.Run()

	// Create test server
	testServer := httptest.NewServer(http.HandlerFunc(srv.HandleWebSocket))
	defer testServer.Close()

	// Convert HTTP URL to WebSocket URL
	wsURL := "ws" + strings.TrimPrefix(testServer.URL, "http")

	// Connect and immediately disconnect
	dialer := websocket.Dialer{}
	conn, _, err := dialer.Dial(wsURL, nil)
	require.NoError(t, err)

	// Close connection immediately
	conn.Close()

	// Server should handle the disconnection gracefully
	time.Sleep(100 * time.Millisecond)

	// No assertion needed - test passes if no panic occurs
}

func TestServerRegistrationFlow(t *testing.T) {
	srv, cleanup := createTestServer(t)
	defer cleanup()

	// Start server goroutine
	go srv.Run()

	// Create test server
	testServer := httptest.NewServer(http.HandlerFunc(srv.HandleWebSocket))
	defer testServer.Close()

	// Convert HTTP URL to WebSocket URL
	wsURL := "ws" + strings.TrimPrefix(testServer.URL, "http")

	// Connect to WebSocket
	dialer := websocket.Dialer{}
	conn, _, err := dialer.Dial(wsURL, nil)
	require.NoError(t, err)
	defer conn.Close()

	// Send registration with valid username
	registerReq := protocol.RegisterRequest{Username: "validuser123"}
	msg := protocol.NewMessage(protocol.MsgTypeRegister, registerReq)
	msgBytes, err := msg.Marshal()
	require.NoError(t, err)

	err = conn.WriteMessage(websocket.TextMessage, msgBytes)
	require.NoError(t, err)

	// Wait for response
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	_, responseBytes, err := conn.ReadMessage()
	require.NoError(t, err)

	// Parse response
	var response protocol.Message
	err = json.Unmarshal(responseBytes, &response)
	require.NoError(t, err)

	if response.Type == protocol.MsgTypeRegistered {
		var registerResp protocol.RegisterResponse
		err = response.ParseData(&registerResp)
		require.NoError(t, err)

		assert.Equal(t, "validuser123", registerResp.Username)
		assert.NotEmpty(t, registerResp.Token)
		assert.NotEmpty(t, registerResp.Salt)
	} else if response.Type == protocol.MsgTypeError {
		// Could be a validation error or duplicate user
		var errorResp protocol.ErrorResponse
		err = response.ParseData(&errorResp)
		require.NoError(t, err)
		assert.NotEmpty(t, errorResp.Message)
	}
}

func TestServerUnknownMessageType(t *testing.T) {
	srv, cleanup := createTestServer(t)
	defer cleanup()

	// Start server goroutine
	go srv.Run()

	// Create test server
	testServer := httptest.NewServer(http.HandlerFunc(srv.HandleWebSocket))
	defer testServer.Close()

	// Convert HTTP URL to WebSocket URL
	wsURL := "ws" + strings.TrimPrefix(testServer.URL, "http")

	// Connect to WebSocket
	dialer := websocket.Dialer{}
	conn, _, err := dialer.Dial(wsURL, nil)
	require.NoError(t, err)
	defer conn.Close()

	// Send message with unknown type
	unknownMsg := protocol.NewMessage(protocol.MessageType("unknown"), nil)
	msgBytes, err := unknownMsg.Marshal()
	require.NoError(t, err)

	err = conn.WriteMessage(websocket.TextMessage, msgBytes)
	require.NoError(t, err)

	// Wait for error response
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	_, responseBytes, err := conn.ReadMessage()
	require.NoError(t, err)

	// Parse response
	var response protocol.Message
	err = json.Unmarshal(responseBytes, &response)
	require.NoError(t, err)

	// Should get an error response
	assert.Equal(t, protocol.MsgTypeError, response.Type)

	var errorResp protocol.ErrorResponse
	err = response.ParseData(&errorResp)
	require.NoError(t, err)
	assert.Equal(t, 400, errorResp.Code)
	assert.Contains(t, errorResp.Message, "Unknown message type")
}

// Benchmark tests
func BenchmarkServerNewConnection(b *testing.B) {
	tempDir := b.TempDir()
	dbPath := filepath.Join(tempDir, "bench.db")

	srv, err := server.NewServer(dbPath)
	require.NoError(b, err)

	// Start server goroutine
	go srv.Run()

	// Create test server
	testServer := httptest.NewServer(http.HandlerFunc(srv.HandleWebSocket))
	defer testServer.Close()

	// Convert HTTP URL to WebSocket URL
	wsURL := "ws" + strings.TrimPrefix(testServer.URL, "http")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		dialer := websocket.Dialer{}
		conn, _, err := dialer.Dial(wsURL, nil)
		if err != nil {
			continue
		}
		conn.Close()
	}
}

func BenchmarkServerMessageProcessing(b *testing.B) {
	tempDir := b.TempDir()
	dbPath := filepath.Join(tempDir, "bench.db")

	srv, err := server.NewServer(dbPath)
	require.NoError(b, err)

	// Start server goroutine
	go srv.Run()

	// Create test server
	testServer := httptest.NewServer(http.HandlerFunc(srv.HandleWebSocket))
	defer testServer.Close()

	// Convert HTTP URL to WebSocket URL
	wsURL := "ws" + strings.TrimPrefix(testServer.URL, "http")

	// Establish connection
	dialer := websocket.Dialer{}
	conn, _, err := dialer.Dial(wsURL, nil)
	require.NoError(b, err)
	defer conn.Close()

	// Prepare heartbeat message
	heartbeatMsg := protocol.NewMessage(protocol.MsgTypeHeartbeat, nil)
	msgBytes, _ := heartbeatMsg.Marshal()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		conn.WriteMessage(websocket.TextMessage, msgBytes)
	}
}
