package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"

	"aimessage/internal/server"
)

func getEnvString(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func getEnvInt(key string, defaultValue int) int {
	if value := os.Getenv(key); value != "" {
		if intValue, err := strconv.Atoi(value); err == nil {
			return intValue
		}
	}
	return defaultValue
}

func main() {
	var (
		port   = flag.Int("port", getEnvInt("PORT", 8080), "Server port")
		dbPath = flag.String("db", getEnvString("DB_PATH", "./data"), "Database path")
	)
	flag.Parse()

	// Create server
	srv, err := server.NewServer(*dbPath)
	if err != nil {
		log.Fatalf("Failed to create server: %v", err)
	}

	// Start server hub
	go srv.Run()

	// Setup HTTP routes
	http.HandleFunc("/ws", srv.HandleWebSocket)
	http.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		if _, err := w.Write([]byte(`{"status":"ok","service":"aimessage-server"}`)); err != nil {
			log.Printf("Failed to write health response: %v", err)
		}
	})

	// Setup graceful shutdown
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-c
		log.Println("Shutting down server...")
		srv.Close()
		os.Exit(0)
	}()

	addr := fmt.Sprintf(":%d", *port)
	log.Printf("AI Message Server starting on %s", addr)
	log.Printf("WebSocket endpoint: ws://localhost%s/ws", addr)
	log.Printf("Health check: http://localhost%s/health", addr)

	if err := http.ListenAndServe(addr, nil); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}
