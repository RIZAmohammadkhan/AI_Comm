package test

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"aimessage/internal/client"
	"aimessage/internal/server"

	"github.com/stretchr/testify/require"
)

// TestKeyExchangeHangDiagnosis specifically diagnoses the key exchange hanging issue
func TestKeyExchangeHangDiagnosis(t *testing.T) {
	log.SetOutput(os.Stdout)
	log.SetFlags(log.LstdFlags | log.Lshortfile)

	fmt.Println("=== DIAGNOSING KEY EXCHANGE HANG ===")

	// Create test environment
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "hang_diagnosis.db")

	// Create and start server
	srv, err := server.NewServer(dbPath)
	require.NoError(t, err)
	defer srv.Close()

	go srv.Run()

	// Setup HTTP routes and start HTTP server
	go func() {
		http.HandleFunc("/ws", srv.HandleWebSocket)
		err := http.ListenAndServe(":8080", nil)
		if err != nil {
			fmt.Printf("[SERVER] HTTP server error: %v\n", err)
		}
	}()

	time.Sleep(500 * time.Millisecond)

	// Test 1: Manual Key Exchange Flow
	t.Run("ManualKeyExchangeFlow", func(t *testing.T) {
		testManualKeyExchange(t, tempDir)
	})

	// Test 2: Concurrent Key Exchange
	t.Run("ConcurrentKeyExchange", func(t *testing.T) {
		testConcurrentKeyExchange(t, tempDir)
	})

	// Test 3: Debug Message Routing
	t.Run("DebugMessageRouting", func(t *testing.T) {
		testDebugMessageRouting(t, tempDir)
	})
}

// testManualKeyExchange performs step-by-step key exchange with detailed logging
func testManualKeyExchange(t *testing.T, tempDir string) {
	fmt.Println("\n--- Manual Key Exchange Test ---")

	timestamp := time.Now().Unix()
	receiverUsername := fmt.Sprintf("diagreceiver_%d", timestamp)
	senderUsername := fmt.Sprintf("diagsender_%d", timestamp)

	// Setup receiver
	receiverConfigDir := filepath.Join(tempDir, "manual_receiver")
	receiver := client.NewClientWithConfigDir("ws://localhost:8080/ws", receiverConfigDir)

	fmt.Println("[RECEIVER] Setting up receiver...")
	err := receiver.Connect()
	require.NoError(t, err)
	err = receiver.Register(receiverUsername)
	require.NoError(t, err)
	receiver.Close()

	time.Sleep(100 * time.Millisecond)

	// Setup sender
	senderConfigDir := filepath.Join(tempDir, "manual_sender")
	sender := client.NewClientWithConfigDir("ws://localhost:8080/ws", senderConfigDir)

	fmt.Println("[SENDER] Setting up sender...")
	err = sender.Connect()
	require.NoError(t, err)
	err = sender.Register(senderUsername)
	require.NoError(t, err)
	sender.Close()

	time.Sleep(100 * time.Millisecond)

	// Start receiver listening
	fmt.Println("[RECEIVER] Starting receiver in listen mode...")
	err = receiver.Connect()
	require.NoError(t, err)
	defer receiver.Close()

	receiverDone := make(chan error, 1)
	receiverStarted := make(chan bool, 1)

	go func() {
		// Signal that receiver is about to start listening
		receiverStarted <- true
		err := receiver.Listen()
		receiverDone <- err
	}()

	// Wait for receiver to start
	<-receiverStarted
	time.Sleep(1 * time.Second) // Give receiver time to fully initialize

	// Start sender
	fmt.Println("[SENDER] Starting sender...")
	err = sender.Connect()
	require.NoError(t, err)
	defer sender.Close()

	// Send message with timeout monitoring
	fmt.Println("[SENDER] Sending message...")
	sendDone := make(chan error, 1)
	go func() {
		err := sender.SendMessage(receiverUsername, "Test message for key exchange")
		sendDone <- err
	}()

	// Monitor the operation
	select {
	case err := <-sendDone:
		if err != nil {
			fmt.Printf("[SENDER] Send failed: %v\n", err)
		} else {
			fmt.Println("[SENDER] Message sent successfully")
		}
	case <-time.After(35 * time.Second):
		fmt.Println("[TIMEOUT] Send operation timed out - hanging detected!")
		t.Error("Send operation timed out")
		return
	}

	// Wait a bit more for receiver to process
	time.Sleep(2 * time.Second)

	fmt.Println("[TEST] Manual key exchange test completed")
}

// testConcurrentKeyExchange tests multiple concurrent key exchanges
func testConcurrentKeyExchange(t *testing.T, tempDir string) {
	fmt.Println("\n--- Concurrent Key Exchange Test ---")

	timestamp := time.Now().Unix()
	numPairs := 2 // Start with 2 pairs to see if concurrent exchanges cause issues

	var wg sync.WaitGroup
	errors := make(chan error, numPairs*2)

	for i := 0; i < numPairs; i++ {
		wg.Add(2) // One sender, one receiver per pair

		go func(pairID int) {
			defer wg.Done()

			receiverUsername := fmt.Sprintf("concrecv_%d_%d", timestamp, pairID)
			receiverConfigDir := filepath.Join(tempDir, fmt.Sprintf("conc_receiver_%d", pairID))
			receiver := client.NewClientWithConfigDir("ws://localhost:8080/ws", receiverConfigDir)

			// Setup receiver
			err := receiver.Connect()
			if err != nil {
				errors <- fmt.Errorf("receiver %d connect failed: %w", pairID, err)
				return
			}
			defer receiver.Close()

			err = receiver.Register(receiverUsername)
			if err != nil {
				errors <- fmt.Errorf("receiver %d register failed: %w", pairID, err)
				return
			}

			receiver.Close()
			time.Sleep(100 * time.Millisecond)
			err = receiver.Connect()
			if err != nil {
				errors <- fmt.Errorf("receiver %d reconnect failed: %w", pairID, err)
				return
			}

			// Start listening
			go func() {
				err := receiver.Listen()
				if err != nil {
					errors <- fmt.Errorf("receiver %d listen failed: %w", pairID, err)
				}
			}()

			fmt.Printf("[CONCURRENT] Receiver %d ready\n", pairID)
		}(i)

		go func(pairID int) {
			defer wg.Done()

			time.Sleep(2 * time.Second) // Give receiver time to start

			senderUsername := fmt.Sprintf("concsend_%d_%d", timestamp, pairID)
			senderConfigDir := filepath.Join(tempDir, fmt.Sprintf("conc_sender_%d", pairID))
			sender := client.NewClientWithConfigDir("ws://localhost:8080/ws", senderConfigDir)

			// Setup sender
			err := sender.Connect()
			if err != nil {
				errors <- fmt.Errorf("sender %d connect failed: %w", pairID, err)
				return
			}
			defer sender.Close()

			err = sender.Register(senderUsername)
			if err != nil {
				errors <- fmt.Errorf("sender %d register failed: %w", pairID, err)
				return
			}

			sender.Close()
			time.Sleep(100 * time.Millisecond)
			err = sender.Connect()
			if err != nil {
				errors <- fmt.Errorf("sender %d reconnect failed: %w", pairID, err)
				return
			}

			// Send message
			receiverUsername := fmt.Sprintf("concrecv_%d_%d", timestamp, pairID)
			err = sender.SendMessage(receiverUsername, fmt.Sprintf("Message from sender %d", pairID))
			if err != nil {
				errors <- fmt.Errorf("sender %d send failed: %w", pairID, err)
				return
			}

			fmt.Printf("[CONCURRENT] Sender %d completed\n", pairID)
		}(i)
	}

	// Wait for completion with timeout
	done := make(chan bool)
	go func() {
		wg.Wait()
		done <- true
	}()

	select {
	case <-done:
		fmt.Println("[CONCURRENT] All pairs completed")
	case <-time.After(45 * time.Second):
		t.Error("Concurrent test timed out")
		return
	}

	// Check for errors
	close(errors)
	for err := range errors {
		t.Error(err)
	}
}

// testDebugMessageRouting tests message routing with debug output
func testDebugMessageRouting(t *testing.T, tempDir string) {
	fmt.Println("\n--- Debug Message Routing Test ---")

	timestamp := time.Now().Unix()
	receiverUsername := fmt.Sprintf("debugrecv_%d", timestamp)
	senderUsername := fmt.Sprintf("debugsend_%d", timestamp)

	// Create both clients
	receiverConfigDir := filepath.Join(tempDir, "debug_receiver")
	senderConfigDir := filepath.Join(tempDir, "debug_sender")

	receiver := client.NewClientWithConfigDir("ws://localhost:8080/ws", receiverConfigDir)
	sender := client.NewClientWithConfigDir("ws://localhost:8080/ws", senderConfigDir)

	// Register both
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

	time.Sleep(200 * time.Millisecond)

	// Reconnect both
	err = receiver.Connect()
	require.NoError(t, err)
	defer receiver.Close()

	err = sender.Connect()
	require.NoError(t, err)
	defer sender.Close()

	// Start receiver with detailed monitoring
	go func() {
		// Custom message handler to capture what receiver gets
		for {
			// This is a simplified version - in real implementation we'd need to hook into the message handling
			time.Sleep(100 * time.Millisecond)
		}
	}()

	// Start receiver listening
	receiverDone := make(chan error, 1)
	go func() {
		err := receiver.Listen()
		receiverDone <- err
	}()

	time.Sleep(1 * time.Second)

	// Send a test message
	fmt.Println("[DEBUG] Sending test message...")
	err = sender.SendMessage(receiverUsername, "Debug test message")
	if err != nil {
		t.Errorf("Debug send failed: %v", err)
	} else {
		fmt.Println("[DEBUG] Test message sent")
	}

	// Wait for message processing
	time.Sleep(3 * time.Second)

	fmt.Println("[DEBUG] Message routing test completed")
}

// TestSimplifiedKeyExchange tests a very basic key exchange to isolate the issue
func TestSimplifiedKeyExchange(t *testing.T) {
	fmt.Println("\n=== SIMPLIFIED KEY EXCHANGE TEST ===")

	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "simple_test.db")

	srv, err := server.NewServer(dbPath)
	require.NoError(t, err)
	defer srv.Close()

	go srv.Run()

	go func() {
		http.HandleFunc("/ws", srv.HandleWebSocket)
		http.ListenAndServe(":8080", nil)
	}()

	time.Sleep(500 * time.Millisecond)

	// Create clients with minimal configuration
	receiver := client.NewClient("ws://localhost:8080/ws")
	sender := client.NewClient("ws://localhost:8080/ws")

	// Register users
	fmt.Println("[SIMPLE] Registering users...")
	err = receiver.Connect()
	require.NoError(t, err)
	err = receiver.Register("simple_receiver")
	require.NoError(t, err)
	receiver.Close()

	err = sender.Connect()
	require.NoError(t, err)
	err = sender.Register("simple_sender")
	require.NoError(t, err)
	sender.Close()

	time.Sleep(200 * time.Millisecond)

	// Test the actual key exchange
	fmt.Println("[SIMPLE] Starting key exchange test...")

	err = receiver.Connect()
	require.NoError(t, err)
	defer receiver.Close()

	// Start receiver in background
	go func() {
		receiver.Listen()
	}()

	time.Sleep(1 * time.Second)

	// Start sender
	err = sender.Connect()
	require.NoError(t, err)
	defer sender.Close()

	// Monitor send operation closely
	fmt.Println("[SIMPLE] Sending message...")
	start := time.Now()

	err = sender.SendMessage("simple_receiver", "Simple test message")
	elapsed := time.Since(start)

	if err != nil {
		fmt.Printf("[SIMPLE] Send failed after %v: %v\n", elapsed, err)
		t.Errorf("Simple send failed: %v", err)
	} else {
		fmt.Printf("[SIMPLE] Send completed successfully in %v\n", elapsed)
	}

	time.Sleep(2 * time.Second)
	fmt.Println("[SIMPLE] Test completed")
}
