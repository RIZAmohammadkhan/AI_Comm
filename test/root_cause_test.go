package test

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"aimessage/internal/client"
	"aimessage/internal/server"

	"github.com/stretchr/testify/require"
)

// TestKeyExchangeRootCause demonstrates the root cause of the hanging issue
func TestKeyExchangeRootCause(t *testing.T) {
	log.SetOutput(os.Stdout)
	log.SetFlags(log.LstdFlags | log.Lshortfile)

	fmt.Println("=== TESTING KEY EXCHANGE ROOT CAUSE ===")

	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "root_cause_test.db")

	srv, err := server.NewServer(dbPath)
	require.NoError(t, err)
	defer srv.Close()

	go srv.Run()

	go func() {
		http.HandleFunc("/ws", srv.HandleWebSocket)
		http.ListenAndServe(":8080", nil)
	}()

	time.Sleep(500 * time.Millisecond)

	// Create clients
	receiver := client.NewClientWithConfigDir("ws://localhost:8080/ws", filepath.Join(tempDir, "receiver"))
	sender := client.NewClientWithConfigDir("ws://localhost:8080/ws", filepath.Join(tempDir, "sender"))

	// Register both
	err = receiver.Connect()
	require.NoError(t, err)
	err = receiver.Register("test_receiver")
	require.NoError(t, err)
	receiver.Close()

	err = sender.Connect()
	require.NoError(t, err)
	err = sender.Register("test_sender")
	require.NoError(t, err)
	sender.Close()

	time.Sleep(200 * time.Millisecond)

	fmt.Println("\n=== TEST 1: Receiver in Listen mode (should work) ===")

	// Test 1: Receiver in Listen mode - this should work
	err = receiver.Connect()
	require.NoError(t, err)

	go func() {
		fmt.Println("[RECEIVER] Starting listen mode...")
		receiver.Listen()
	}()

	time.Sleep(1 * time.Second)

	err = sender.Connect()
	require.NoError(t, err)

	fmt.Println("[SENDER] Sending message with receiver in listen mode...")
	start := time.Now()
	err = sender.SendMessage("test_receiver", "Test message 1")
	elapsed := time.Since(start)

	if err != nil {
		fmt.Printf("[RESULT] FAILED after %v: %v\n", elapsed, err)
	} else {
		fmt.Printf("[RESULT] SUCCESS in %v\n", elapsed)
	}

	sender.Close()
	receiver.Close()

	fmt.Println("\n=== TEST 2: Receiver NOT in Listen mode (should hang) ===")

	// Test 2: Receiver NOT in Listen mode - this should demonstrate the hang
	time.Sleep(500 * time.Millisecond)

	err = receiver.Connect()
	require.NoError(t, err)
	// Note: receiver is connected but NOT calling Listen()

	time.Sleep(500 * time.Millisecond)

	err = sender.Connect()
	require.NoError(t, err)

	fmt.Println("[SENDER] Sending message with receiver NOT in listen mode...")
	start = time.Now()

	// This should timeout because receiver is not reading messages
	done := make(chan error, 1)
	go func() {
		err := sender.SendMessage("test_receiver", "Test message 2")
		done <- err
	}()

	select {
	case err := <-done:
		elapsed := time.Since(start)
		if err != nil {
			fmt.Printf("[RESULT] FAILED after %v: %v\n", elapsed, err)
			fmt.Println("[ANALYSIS] This confirms the issue - receiver must be in Listen mode!")
		} else {
			fmt.Printf("[RESULT] Unexpected success in %v\n", elapsed)
		}
	case <-time.After(35 * time.Second):
		elapsed := time.Since(start)
		fmt.Printf("[RESULT] TIMEOUT after %v\n", elapsed)
		fmt.Println("[ANALYSIS] This confirms the hanging issue - sender hangs waiting for key exchange response!")
		t.Error("Operation timed out as expected - this demonstrates the root cause")
	}

	sender.Close()
	receiver.Close()

	fmt.Println("\n=== CONCLUSION ===")
	fmt.Println("Root Cause: Senders cannot receive key exchange responses because they don't have")
	fmt.Println("an active message reading loop. Only clients in Listen() mode can receive responses.")
	fmt.Println("Solution: SendMessage() needs to temporarily read messages while waiting for key exchange.")
}

// TestProposedFix tests a conceptual fix for the key exchange issue
func TestProposedFix(t *testing.T) {
	fmt.Println("\n=== PROPOSED FIX CONCEPT ===")
	fmt.Println("The fix should modify getOrCreateSession() to:")
	fmt.Println("1. Start a temporary message reading loop")
	fmt.Println("2. Continue reading until key exchange response is received")
	fmt.Println("3. Handle the MsgTypeKeyResponse to signal the waiting channel")
	fmt.Println("4. Stop the temporary loop once key exchange is complete")
	fmt.Println("")
	fmt.Println("This would allow SendMessage() to work without requiring the sender")
	fmt.Println("to be in Listen() mode.")
}
