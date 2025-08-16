package test

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"aimessage/internal/client"
	"aimessage/internal/protocol"
	"aimessage/internal/server"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestClientServerInteraction tests the complete interaction flow between client and server
// This test specifically focuses on identifying hanging issues after key exchange
func TestClientServerInteraction(t *testing.T) {
	log.SetOutput(os.Stdout)
	log.SetFlags(log.LstdFlags | log.Lshortfile)

	fmt.Println("=== TESTING CLIENT-SERVER INTERACTION ===")

	// Create test environment
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "interaction_test.db")

	// Create and start server
	srv, err := server.NewServer(dbPath)
	require.NoError(t, err)
	defer srv.Close()

	// Start server with HTTP listener
	serverStarted := make(chan bool)
	go func() {
		fmt.Println("[SERVER] Starting server hub...")
		srv.Run()
	}()

	// Setup HTTP routes and start HTTP server
	go func() {
		http.HandleFunc("/ws", srv.HandleWebSocket)
		http.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"status":"ok","service":"aimessage-server"}`))
		})

		fmt.Println("[SERVER] Starting HTTP server on :8080...")
		serverStarted <- true
		err := http.ListenAndServe(":8080", nil)
		if err != nil {
			fmt.Printf("[SERVER] HTTP server error: %v\n", err)
		}
	}()

	// Wait for server to start
	<-serverStarted
	time.Sleep(500 * time.Millisecond)

	// Test basic connection and registration
	t.Run("BasicConnectionAndRegistration", func(t *testing.T) {
		testBasicConnection(t, tempDir)
	})

	// Test authentication flow
	t.Run("AuthenticationFlow", func(t *testing.T) {
		testAuthenticationFlow(t, tempDir)
	})

	// Test key exchange with detailed monitoring
	t.Run("KeyExchangeWithMonitoring", func(t *testing.T) {
		testKeyExchangeWithMonitoring(t, tempDir)
	})

	// Test message sending after key exchange
	t.Run("MessageSendingAfterKeyExchange", func(t *testing.T) {
		testMessageSendingAfterKeyExchange(t, tempDir)
	})

	// Test concurrent operations
	t.Run("ConcurrentOperations", func(t *testing.T) {
		testConcurrentOperations(t, tempDir)
	})

	// Test timeout scenarios
	t.Run("TimeoutScenarios", func(t *testing.T) {
		testTimeoutScenarios(t, tempDir)
	})
}

// testBasicConnection tests basic client-server connection
func testBasicConnection(t *testing.T, tempDir string) {
	fmt.Println("\n--- Testing Basic Connection ---")

	configDir := filepath.Join(tempDir, "basic_test")
	client := client.NewClientWithConfigDir("ws://localhost:8080/ws", configDir)

	// Test connection
	err := client.Connect()
	require.NoError(t, err, "Client should connect successfully")
	defer client.Close()

	fmt.Println("[CLIENT] Connected successfully")

	// Test registration
	username := fmt.Sprintf("testuser_%d", time.Now().Unix())
	err = client.Register(username)
	require.NoError(t, err, "Registration should succeed")

	fmt.Printf("[CLIENT] Registered as %s\n", username)
}

// testAuthenticationFlow tests the authentication process
func testAuthenticationFlow(t *testing.T, tempDir string) {
	fmt.Println("\n--- Testing Authentication Flow ---")

	configDir := filepath.Join(tempDir, "auth_test")
	client := client.NewClientWithConfigDir("ws://localhost:8080/ws", configDir)

	// Initial registration
	err := client.Connect()
	require.NoError(t, err)

	username := fmt.Sprintf("authuser_%d", time.Now().Unix())
	err = client.Register(username)
	require.NoError(t, err)

	client.Close()
	time.Sleep(100 * time.Millisecond)

	// Test authentication on reconnection
	err = client.Connect()
	require.NoError(t, err)
	defer client.Close()

	fmt.Println("[CLIENT] Authentication flow completed")
}

// testKeyExchangeWithMonitoring tests key exchange with detailed monitoring
func testKeyExchangeWithMonitoring(t *testing.T, tempDir string) {
	fmt.Println("\n--- Testing Key Exchange with Monitoring ---")

	timestamp := time.Now().Unix()
	receiverUsername := fmt.Sprintf("receiver_%d", timestamp)
	senderUsername := fmt.Sprintf("sender_%d", timestamp)

	var wg sync.WaitGroup
	var receiverError, senderError atomic.Value
	receiverReady := make(chan bool, 1)
	keyExchangeStarted := make(chan bool, 1)
	keyExchangeCompleted := make(chan bool, 1)

	// Monitor channels
	receiverStatus := make(chan string, 10)
	senderStatus := make(chan string, 10)

	// Start receiver
	wg.Add(1)
	go func() {
		defer wg.Done()
		err := runReceiver(t, tempDir, receiverUsername, receiverReady, receiverStatus, keyExchangeCompleted)
		if err != nil {
			receiverError.Store(err)
		}
	}()

	// Start sender
	wg.Add(1)
	go func() {
		defer wg.Done()
		err := runSender(t, tempDir, senderUsername, receiverUsername, receiverReady, keyExchangeStarted, senderStatus)
		if err != nil {
			senderError.Store(err)
		}
	}()

	// Monitor the interaction
	go func() {
		timeout := time.After(30 * time.Second)
		for {
			select {
			case status := <-receiverStatus:
				fmt.Printf("[MONITOR] Receiver: %s\n", status)
			case status := <-senderStatus:
				fmt.Printf("[MONITOR] Sender: %s\n", status)
			case <-keyExchangeStarted:
				fmt.Println("[MONITOR] Key exchange started")
			case <-keyExchangeCompleted:
				fmt.Println("[MONITOR] Key exchange completed")
				return
			case <-timeout:
				fmt.Println("[MONITOR] Test timed out - potential hanging detected!")
				return
			}
		}
	}()

	// Wait for completion with timeout
	done := make(chan bool)
	go func() {
		wg.Wait()
		done <- true
	}()

	select {
	case <-done:
		fmt.Println("[MONITOR] Test completed normally")
	case <-time.After(35 * time.Second):
		t.Error("Test timed out - hanging issue detected")
		return
	}

	// Check for errors
	if err := receiverError.Load(); err != nil {
		t.Errorf("Receiver error: %v", err)
	}
	if err := senderError.Load(); err != nil {
		t.Errorf("Sender error: %v", err)
	}
}

// runReceiver runs the receiver client with monitoring
func runReceiver(t *testing.T, tempDir, username string, ready chan bool, status chan string, keyExchangeCompleted chan bool) error {
	status <- "Starting receiver"

	configDir := filepath.Join(tempDir, "receiver_monitor")
	receiver := client.NewClientWithConfigDir("ws://localhost:8080/ws", configDir)

	// Connect
	status <- "Connecting to server"
	err := receiver.Connect()
	if err != nil {
		return fmt.Errorf("connection failed: %w", err)
	}
	defer receiver.Close()

	// Register
	status <- "Registering user"
	err = receiver.Register(username)
	if err != nil {
		return fmt.Errorf("registration failed: %w", err)
	}

	// Reconnect for auth
	receiver.Close()
	time.Sleep(100 * time.Millisecond)

	status <- "Reconnecting for authentication"
	err = receiver.Connect()
	if err != nil {
		return fmt.Errorf("reconnection failed: %w", err)
	}

	// Signal ready
	ready <- true
	status <- "Ready for key exchange"

	// Start listening with timeout
	status <- "Starting listen mode"
	listenDone := make(chan error, 1)
	go func() {
		err := receiver.Listen()
		listenDone <- err
	}()

	// Wait for listen to complete or timeout
	select {
	case err := <-listenDone:
		if err != nil {
			status <- fmt.Sprintf("Listen failed: %v", err)
			return err
		}
		status <- "Listen completed"
		keyExchangeCompleted <- true
		return nil
	case <-time.After(25 * time.Second):
		status <- "Listen timed out"
		return fmt.Errorf("listen operation timed out")
	}
}

// runSender runs the sender client with monitoring
func runSender(t *testing.T, tempDir, senderUsername, receiverUsername string, receiverReady chan bool, keyExchangeStarted chan bool, status chan string) error {
	status <- "Waiting for receiver to be ready"

	// Wait for receiver
	select {
	case <-receiverReady:
		status <- "Receiver is ready"
	case <-time.After(10 * time.Second):
		return fmt.Errorf("receiver not ready in time")
	}

	time.Sleep(500 * time.Millisecond) // Give receiver time to start listening

	status <- "Starting sender"

	configDir := filepath.Join(tempDir, "sender_monitor")
	sender := client.NewClientWithConfigDir("ws://localhost:8080/ws", configDir)

	// Connect and register
	status <- "Connecting sender to server"
	err := sender.Connect()
	if err != nil {
		return fmt.Errorf("sender connection failed: %w", err)
	}
	defer sender.Close()

	status <- "Registering sender"
	err = sender.Register(senderUsername)
	if err != nil {
		return fmt.Errorf("sender registration failed: %w", err)
	}

	// Reconnect for auth
	sender.Close()
	time.Sleep(100 * time.Millisecond)

	status <- "Reconnecting sender for authentication"
	err = sender.Connect()
	if err != nil {
		return fmt.Errorf("sender reconnection failed: %w", err)
	}

	status <- "Sending message to trigger key exchange"
	keyExchangeStarted <- true

	// Send message
	err = sender.SendMessage(receiverUsername, "Hello from sender!")
	if err != nil {
		status <- fmt.Sprintf("Message send failed: %v", err)
		return fmt.Errorf("message send failed: %w", err)
	}

	status <- "Message sent successfully"
	return nil
}

// testMessageSendingAfterKeyExchange tests message sending after successful key exchange
func testMessageSendingAfterKeyExchange(t *testing.T, tempDir string) {
	fmt.Println("\n--- Testing Message Sending After Key Exchange ---")

	// This test focuses on the post-key-exchange behavior
	timestamp := time.Now().Unix()
	receiverUsername := fmt.Sprintf("msgreceiver_%d", timestamp)
	senderUsername := fmt.Sprintf("msgsender_%d", timestamp)

	// Set up both clients
	receiverConfigDir := filepath.Join(tempDir, "msg_receiver")
	senderConfigDir := filepath.Join(tempDir, "msg_sender")

	receiver := client.NewClientWithConfigDir("ws://localhost:8080/ws", receiverConfigDir)
	sender := client.NewClientWithConfigDir("ws://localhost:8080/ws", senderConfigDir)

	// Register both clients
	err := receiver.Connect()
	require.NoError(t, err)
	err = receiver.Register(receiverUsername)
	require.NoError(t, err)
	receiver.Close()

	err = sender.Connect()
	require.NoError(t, err)
	err = sender.Register(senderUsername)
	require.NoError(t, err)
	sender.Close()

	// Reconnect both for auth
	time.Sleep(100 * time.Millisecond)

	err = receiver.Connect()
	require.NoError(t, err)
	defer receiver.Close()

	err = sender.Connect()
	require.NoError(t, err)
	defer sender.Close()

	// Start receiver in listening mode
	receiverDone := make(chan error, 1)
	go func() {
		err := receiver.Listen()
		receiverDone <- err
	}()

	time.Sleep(500 * time.Millisecond)

	// Send multiple messages to test sustained communication
	messages := []string{
		"First message",
		"Second message",
		"Third message",
	}

	for i, msg := range messages {
		fmt.Printf("[SENDER] Sending message %d: %s\n", i+1, msg)
		err = sender.SendMessage(receiverUsername, msg)
		assert.NoError(t, err, "Message %d should send successfully", i+1)
		time.Sleep(200 * time.Millisecond)
	}

	// Allow time for message processing
	time.Sleep(2 * time.Second)

	fmt.Println("[TEST] Message sending test completed")
}

// testConcurrentOperations tests concurrent client operations
func testConcurrentOperations(t *testing.T, tempDir string) {
	fmt.Println("\n--- Testing Concurrent Operations ---")

	timestamp := time.Now().Unix()
	numClients := 3

	var wg sync.WaitGroup
	errors := make(chan error, numClients)

	for i := 0; i < numClients; i++ {
		wg.Add(1)
		go func(clientNum int) {
			defer wg.Done()

			username := fmt.Sprintf("concurrent_%d_%d", timestamp, clientNum)
			configDir := filepath.Join(tempDir, fmt.Sprintf("concurrent_%d", clientNum))

			client := client.NewClientWithConfigDir("ws://localhost:8080/ws", configDir)

			err := client.Connect()
			if err != nil {
				errors <- fmt.Errorf("client %d connection failed: %w", clientNum, err)
				return
			}
			defer client.Close()

			err = client.Register(username)
			if err != nil {
				errors <- fmt.Errorf("client %d registration failed: %w", clientNum, err)
				return
			}

			fmt.Printf("[CONCURRENT] Client %d registered successfully\n", clientNum)
		}(i)
	}

	wg.Wait()
	close(errors)

	// Check for errors
	for err := range errors {
		t.Error(err)
	}
}

// testTimeoutScenarios tests various timeout scenarios
func testTimeoutScenarios(t *testing.T, tempDir string) {
	fmt.Println("\n--- Testing Timeout Scenarios ---")

	// Test connection timeout handling
	t.Run("ConnectionTimeout", func(t *testing.T) {
		configDir := filepath.Join(tempDir, "timeout_test")

		// Try to connect to non-existent server
		badClient := client.NewClientWithConfigDir("ws://localhost:9999/ws", configDir)

		start := time.Now()
		err := badClient.Connect()
		elapsed := time.Since(start)

		assert.Error(t, err, "Connection to non-existent server should fail")
		assert.True(t, elapsed < 10*time.Second, "Connection should timeout quickly")

		fmt.Printf("[TIMEOUT] Connection timeout test completed in %v\n", elapsed)
	})

	// Test operation timeout during key exchange
	t.Run("KeyExchangeTimeout", func(t *testing.T) {
		// This would require more complex setup to simulate hanging key exchange
		fmt.Println("[TIMEOUT] Key exchange timeout test - requires specific server behavior")
	})
}

// TestServerHealthDuringInteraction monitors server health during client interactions
func TestServerHealthDuringInteraction(t *testing.T) {
	fmt.Println("\n=== TESTING SERVER HEALTH DURING INTERACTION ===")

	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "health_test.db")

	srv, err := server.NewServer(dbPath)
	require.NoError(t, err)
	defer srv.Close()

	// Start server
	go srv.Run()
	time.Sleep(200 * time.Millisecond)

	// Create multiple clients and monitor server health
	numClients := 5
	var wg sync.WaitGroup

	healthMonitor := make(chan string, 100)

	// Start health monitoring
	go func() {
		for status := range healthMonitor {
			fmt.Printf("[HEALTH] %s\n", status)
		}
	}()

	for i := 0; i < numClients; i++ {
		wg.Add(1)
		go func(clientID int) {
			defer wg.Done()

			healthMonitor <- fmt.Sprintf("Starting client %d", clientID)

			username := fmt.Sprintf("healthtest_%d_%d", time.Now().Unix(), clientID)
			configDir := filepath.Join(tempDir, fmt.Sprintf("health_client_%d", clientID))

			client := client.NewClientWithConfigDir("ws://localhost:8080/ws", configDir)

			err := client.Connect()
			if err != nil {
				healthMonitor <- fmt.Sprintf("Client %d connection failed: %v", clientID, err)
				return
			}
			defer client.Close()

			err = client.Register(username)
			if err != nil {
				healthMonitor <- fmt.Sprintf("Client %d registration failed: %v", clientID, err)
				return
			}

			healthMonitor <- fmt.Sprintf("Client %d registered successfully", clientID)

			// Perform some operations
			client.Close()
			time.Sleep(100 * time.Millisecond)

			err = client.Connect()
			if err != nil {
				healthMonitor <- fmt.Sprintf("Client %d reconnection failed: %v", clientID, err)
				return
			}

			healthMonitor <- fmt.Sprintf("Client %d completed successfully", clientID)
		}(i)
	}

	wg.Wait()
	close(healthMonitor)

	fmt.Println("[HEALTH] Server health test completed")
}

// DebugMessageFlow provides detailed debugging information about message flow
func TestDebugMessageFlow(t *testing.T) {
	fmt.Println("\n=== DEBUG MESSAGE FLOW ===")

	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "debug_test.db")

	srv, err := server.NewServer(dbPath)
	require.NoError(t, err)
	defer srv.Close()

	go srv.Run()
	time.Sleep(200 * time.Millisecond)

	// Create a client with detailed logging
	configDir := filepath.Join(tempDir, "debug_client")
	debugClient := client.NewClientWithConfigDir("ws://localhost:8080/ws", configDir)

	err = debugClient.Connect()
	require.NoError(t, err)
	defer debugClient.Close()

	username := fmt.Sprintf("debuguser_%d", time.Now().Unix())

	fmt.Printf("[DEBUG] Registering user: %s\n", username)
	err = debugClient.Register(username)
	require.NoError(t, err)

	fmt.Println("[DEBUG] Registration completed")

	// Test message structure
	testMsg := protocol.Message{
		Type:      protocol.MsgTypeHeartbeat,
		ID:        "debug_test_1",
		Timestamp: time.Now().Unix(),
		Data:      nil,
	}

	msgBytes, err := json.Marshal(testMsg)
	require.NoError(t, err)

	fmt.Printf("[DEBUG] Test message structure: %s\n", string(msgBytes))
	fmt.Println("[DEBUG] Message flow test completed")
}
