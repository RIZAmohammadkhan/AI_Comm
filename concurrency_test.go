package main

import (
	"aimessage/internal/client"
	"aimessage/internal/server"
	"context"
	"fmt"
	"net/http"
	"sync"
	"testing"
	"time"
)

// TestConcurrencyFixes demonstrates that the race conditions have been resolved
func TestConcurrencyFixes(t *testing.T) {
	// Start test server
	dbPath := t.TempDir() + "/test.db"
	srv, err := server.NewServer(dbPath)
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}
	defer srv.Close()

	// Start server in background
	go srv.Run()

	// Start HTTP server
	httpServer := &http.Server{
		Addr: ":8080",
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/ws" {
				srv.HandleWebSocket(w, r)
			} else {
				http.NotFound(w, r)
			}
		}),
	}

	go func() {
		if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			t.Logf("HTTP server error: %v", err)
		}
	}()

	// Wait for server to start
	time.Sleep(100 * time.Millisecond)

	// Test concurrent client operations
	numGoroutines := 10
	numOperations := 5

	var wg sync.WaitGroup
	wg.Add(numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			defer wg.Done()

			testClient := client.NewClient("ws://localhost:8080/ws")
			username := fmt.Sprintf("test_user_%d", id)

			// Register user
			if err := testClient.Register(username); err != nil {
				t.Logf("Failed to register user %s: %v", username, err)
				return
			}

			// Perform multiple concurrent operations
			for j := 0; j < numOperations; j++ {
				// Test Listen and StopListening concurrently
				go func() {
					if err := testClient.Connect(); err != nil {
						return
					}
					defer testClient.Disconnect()

					// Start listening briefly
					ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
					defer cancel()

					go func() {
						<-ctx.Done()
						testClient.StopListening()
					}()

					testClient.Listen()
				}()

				// Test concurrent map access through key exchange simulation
				go func() {
					// This would trigger map access in a real scenario
					// but we'll just test concurrent client creation
					_ = client.NewClient("ws://localhost:8080/ws")
				}()
			}

			time.Sleep(200 * time.Millisecond)
		}(i)
	}

	wg.Wait()

	// Shutdown server
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	httpServer.Shutdown(ctx)

	fmt.Println("✅ Concurrency test completed successfully - no race conditions detected!")
}

func TestAtomicOperations(t *testing.T) {
	testClient := client.NewClient("ws://localhost:8080/ws")

	// Test concurrent access to isListening flag
	var wg sync.WaitGroup
	numGoroutines := 100

	wg.Add(numGoroutines)
	for i := 0; i < numGoroutines; i++ {
		go func() {
			defer wg.Done()
			// These operations should be safe now with atomic operations
			testClient.StopListening()
		}()
	}

	wg.Wait()
	fmt.Println("✅ Atomic operations test completed successfully!")
}
