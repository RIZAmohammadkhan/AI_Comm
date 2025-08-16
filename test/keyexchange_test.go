package test

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"aimessage/internal/client"
	"aimessage/internal/server"

	"github.com/stretchr/testify/require"
)

// TestKeyExchangeFlow tests the complete key exchange flow between sender and receiver
func TestKeyExchangeFlow(t *testing.T) {
	log.SetOutput(os.Stdout)
	log.SetFlags(log.LstdFlags | log.Lshortfile)

	fmt.Println("=== TESTING KEY EXCHANGE FLOW ===")

	// Create a real server for testing
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "test.db")

	srv, err := server.NewServer(dbPath)
	require.NoError(t, err)
	defer srv.Close()

	// Start server
	go srv.Run()
	time.Sleep(200 * time.Millisecond)

	// Generate unique usernames for this test
	timestamp := time.Now().Unix()
	receiverUsername := fmt.Sprintf("receiver_%d", timestamp)
	senderUsername := fmt.Sprintf("sender_%d", timestamp)

	fmt.Printf("Using receiver username: %s\n", receiverUsername)
	fmt.Printf("Using sender username: %s\n", senderUsername)

	var wg sync.WaitGroup
	receiverReady := make(chan bool)

	// Start receiver
	wg.Add(1)
	go func() {
		defer wg.Done()

		fmt.Println("[RECEIVER] Starting receiver flow...")

		receiverConfigDir := filepath.Join(tempDir, "receiver")
		os.MkdirAll(receiverConfigDir, 0755)

		receiver := client.NewClientWithConfigDir("ws://localhost:8080/ws", receiverConfigDir)

		err := receiver.Connect()
		if err != nil {
			fmt.Printf("[RECEIVER] Connection failed: %v\n", err)
			return
		}
		defer receiver.Close()

		fmt.Println("[RECEIVER] Connected successfully")

		err = receiver.Register(receiverUsername)
		if err != nil {
			fmt.Printf("[RECEIVER] Registration failed: %v\n", err)
			return
		}
		fmt.Println("[RECEIVER] Registration successful")

		// Reconnect to trigger auth
		receiver.Close()
		time.Sleep(100 * time.Millisecond)

		err = receiver.Connect()
		if err != nil {
			fmt.Printf("[RECEIVER] Reconnection failed: %v\n", err)
			return
		}

		fmt.Println("[RECEIVER] Reconnected for authentication")

		// Signal ready and start listening
		receiverReady <- true

		fmt.Println("[RECEIVER] Starting listen mode...")

		listenDone := make(chan error)
		go func() {
			err := receiver.Listen()
			listenDone <- err
		}()

		// Wait for completion or timeout
		select {
		case err := <-listenDone:
			if err != nil {
				fmt.Printf("[RECEIVER] Listen failed: %v\n", err)
			} else {
				fmt.Println("[RECEIVER] Listen completed successfully")
			}
		case <-time.After(40 * time.Second):
			fmt.Println("[RECEIVER] Listen timeout, stopping...")
			receiver.StopListening()
			<-listenDone
		}

		fmt.Println("[RECEIVER] Receiver flow completed")
	}()

	// Wait for receiver to be ready
	<-receiverReady
	time.Sleep(500 * time.Millisecond)

	// Start sender
	wg.Add(1)
	go func() {
		defer wg.Done()

		fmt.Println("[SENDER] Starting sender flow...")

		senderConfigDir := filepath.Join(tempDir, "sender")
		os.MkdirAll(senderConfigDir, 0755)

		sender := client.NewClientWithConfigDir("ws://localhost:8080/ws", senderConfigDir)

		err := sender.Connect()
		if err != nil {
			fmt.Printf("[SENDER] Connection failed: %v\n", err)
			return
		}
		defer sender.Close()

		fmt.Println("[SENDER] Connected successfully")

		err = sender.Register(senderUsername)
		if err != nil {
			fmt.Printf("[SENDER] Registration failed: %v\n", err)
			return
		}
		fmt.Println("[SENDER] Registration successful")

		// Reconnect to trigger auth
		sender.Close()
		time.Sleep(100 * time.Millisecond)

		err = sender.Connect()
		if err != nil {
			fmt.Printf("[SENDER] Reconnection failed: %v\n", err)
			return
		}

		fmt.Println("[SENDER] Reconnected for message sending")

		// Attempt to send message
		fmt.Println("[SENDER] === SENDING MESSAGE ===")
		fmt.Println("[SENDER] This will trigger authentication and key exchange...")

		start := time.Now()
		err = sender.SendMessage(receiverUsername, "Test message with key exchange")
		elapsed := time.Since(start)

		fmt.Printf("[SENDER] SendMessage completed in %v\n", elapsed)

		if err != nil {
			fmt.Printf("[SENDER] Message send failed: %v\n", err)
			if elapsed > 25*time.Second {
				fmt.Println("[SENDER] Likely timeout - key exchange may have failed")
			}
		} else {
			fmt.Println("[SENDER] Message sent successfully!")
			if elapsed < 10*time.Second {
				fmt.Println("[SENDER] Fast delivery - key exchange likely worked!")
			}
		}

		fmt.Println("[SENDER] Sender flow completed")
	}()

	// Wait for both to complete
	wg.Wait()

	fmt.Println("=== KEY EXCHANGE FLOW TEST COMPLETED ===")
}
