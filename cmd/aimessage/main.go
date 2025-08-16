package main

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"aimessage/internal/client"

	"github.com/spf13/cobra"
)

var (
	serverURL string
	username  string
	to        string
	message   string
)

var rootCmd = &cobra.Command{
	Use:   "aimessage",
	Short: "End-to-end encrypted messaging for AI agents",
	Long: `AI Message is a high-performance terminal-based messaging tool 
that enables AI agents to communicate securely with end-to-end encryption.`,
}

var registerCmd = &cobra.Command{
	Use:   "register",
	Short: "Register a new AI agent",
	Long:  "Register a new AI agent with a unique username and receive encryption credentials",
	RunE: func(cmd *cobra.Command, args []string) error {
		if username == "" {
			return fmt.Errorf("username is required")
		}
		if serverURL == "" {
			return fmt.Errorf("server URL is required")
		}

		client := client.NewClient(serverURL)
		return client.Register(username)
	},
}

var sendCmd = &cobra.Command{
	Use:   "send",
	Short: "Send an encrypted message",
	Long:  "Send an end-to-end encrypted message to another AI agent",
	RunE: func(cmd *cobra.Command, args []string) error {
		if to == "" {
			return fmt.Errorf("recipient username is required")
		}
		if message == "" {
			return fmt.Errorf("message is required")
		}
		if serverURL == "" {
			return fmt.Errorf("server URL is required")
		}

		client := client.NewClient(serverURL)
		return client.SendMessage(to, message)
	},
}

var listenCmd = &cobra.Command{
	Use:   "listen",
	Short: "Listen for incoming messages",
	Long:  "Start listening for incoming encrypted messages from other AI agents",
	RunE: func(cmd *cobra.Command, args []string) error {
		if serverURL == "" {
			return fmt.Errorf("server URL is required")
		}

		client := client.NewClient(serverURL)

		// Setup graceful shutdown
		c := make(chan os.Signal, 1)
		signal.Notify(c, os.Interrupt, syscall.SIGTERM)

		go func() {
			<-c
			fmt.Println("\nStopping listener...")
			client.StopListening()
		}()

		return client.Listen()
	},
}

var usersCmd = &cobra.Command{
	Use:   "users",
	Short: "List online users",
	Long:  "Get a list of currently online AI agents",
	RunE: func(cmd *cobra.Command, args []string) error {
		if serverURL == "" {
			return fmt.Errorf("server URL is required")
		}

		client := client.NewClient(serverURL)
		return client.ListUsers()
	},
}

func init() {
	// Global flags
	rootCmd.PersistentFlags().StringVarP(&serverURL, "server", "s", "", "Server WebSocket URL (e.g., ws://localhost:8080/ws)")

	// Register command flags
	registerCmd.Flags().StringVarP(&username, "username", "u", "", "Username for the AI agent")
	registerCmd.MarkFlagRequired("username")

	// Send command flags
	sendCmd.Flags().StringVarP(&to, "to", "t", "", "Recipient username")
	sendCmd.Flags().StringVarP(&message, "message", "m", "", "Message to send")
	sendCmd.MarkFlagRequired("to")
	sendCmd.MarkFlagRequired("message")

	// Add commands to root
	rootCmd.AddCommand(registerCmd)
	rootCmd.AddCommand(sendCmd)
	rootCmd.AddCommand(listenCmd)
	rootCmd.AddCommand(usersCmd)
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}
