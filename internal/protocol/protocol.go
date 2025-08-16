package protocol

import (
	"encoding/json"
	"time"

	"github.com/mitchellh/mapstructure"
)

// MessageType defines the type of message
type MessageType string

const (
	// Client to server messages
	MsgTypeRegister     MessageType = "register"
	MsgTypeSend         MessageType = "send"
	MsgTypeListen       MessageType = "listen"
	MsgTypeListUsers    MessageType = "list_users"
	MsgTypeHeartbeat    MessageType = "heartbeat"
	MsgTypeAuthenticate MessageType = "authenticate"
	MsgTypeKeyExchange  MessageType = "key_exchange"

	// Server to client messages
	MsgTypeRegistered  MessageType = "registered"
	MsgTypeMessage     MessageType = "message"
	MsgTypeUserList    MessageType = "user_list"
	MsgTypeError       MessageType = "error"
	MsgTypeAck         MessageType = "ack"
	MsgTypeChallenge   MessageType = "challenge"
	MsgTypeKeyRequest  MessageType = "key_request"
	MsgTypeKeyResponse MessageType = "key_response"
	MsgTypeOfflineMsg  MessageType = "offline_message"
)

// Message represents the base message structure
type Message struct {
	Type      MessageType `json:"type"`
	ID        string      `json:"id,omitempty"`
	Timestamp int64       `json:"timestamp"`
	Data      interface{} `json:"data,omitempty"`
}

// RegisterRequest is sent when a user wants to register
type RegisterRequest struct {
	Username string `json:"username" mapstructure:"username"`
}

// RegisterResponse is sent when registration is successful
type RegisterResponse struct {
	Token    string `json:"token" mapstructure:"token"`
	Salt     string `json:"salt" mapstructure:"salt"` // Base64 encoded salt
	Username string `json:"username" mapstructure:"username"`
}

// SendRequest is sent when a user wants to send a message
type SendRequest struct {
	To      string `json:"to" mapstructure:"to"`
	Message string `json:"message" mapstructure:"message"` // Already encrypted by client
}

// MessageDelivery is sent to deliver a message to a recipient
type MessageDelivery struct {
	From      string `json:"from" mapstructure:"from"`
	Message   string `json:"message" mapstructure:"message"` // Encrypted message
	Timestamp int64  `json:"timestamp" mapstructure:"timestamp"`
}

// UserListResponse contains the list of online users
type UserListResponse struct {
	Users []string `json:"users" mapstructure:"users"`
}

// ErrorResponse is sent when an error occurs
type ErrorResponse struct {
	Code    int    `json:"code" mapstructure:"code"`
	Message string `json:"message" mapstructure:"message"`
}

// NewMessage creates a new message with timestamp
func NewMessage(msgType MessageType, data interface{}) *Message {
	return &Message{
		Type:      msgType,
		Timestamp: time.Now().Unix(),
		Data:      data,
	}
}

// Marshal converts a message to JSON bytes
func (m *Message) Marshal() ([]byte, error) {
	return json.Marshal(m)
}

// Unmarshal parses JSON bytes into a message
func UnmarshalMessage(data []byte) (*Message, error) {
	var msg Message
	err := json.Unmarshal(data, &msg)
	return &msg, err
}

// ParseData parses the message data into a specific type
func (m *Message) ParseData(target interface{}) error {
	if m.Data == nil {
		return nil
	}

	// Directly decode from the map into the target struct
	// This avoids the inefficient marshal/unmarshal cycle
	return mapstructure.Decode(m.Data, target)
}

// AuthenticationRequest is sent to authenticate with token
type AuthenticationRequest struct {
	Username  string `json:"username" mapstructure:"username"`
	Token     string `json:"token" mapstructure:"token"`
	Challenge string `json:"challenge,omitempty" mapstructure:"challenge"` // Response to server challenge
}

// ChallengeRequest is sent by server for authentication
type ChallengeRequest struct {
	Challenge string `json:"challenge" mapstructure:"challenge"`
	Timestamp int64  `json:"timestamp" mapstructure:"timestamp"`
}

// KeyExchangeRequest initiates DH key exchange for a conversation
type KeyExchangeRequest struct {
	To        string `json:"to" mapstructure:"to"`
	PublicKey string `json:"public_key" mapstructure:"public_key"` // Base64 encoded DH public key
	SessionID string `json:"session_id" mapstructure:"session_id"`
}

// KeyExchangeResponse responds to DH key exchange
type KeyExchangeResponse struct {
	From      string `json:"from" mapstructure:"from"`
	PublicKey string `json:"public_key" mapstructure:"public_key"` // Base64 encoded DH public key
	SessionID string `json:"session_id" mapstructure:"session_id"`
}

// SecureMessage represents an encrypted message with session info
type SecureMessage struct {
	To        string `json:"to" mapstructure:"to"`
	Message   string `json:"message" mapstructure:"message"`       // Encrypted with session key
	SessionID string `json:"session_id" mapstructure:"session_id"` // Session identifier for PFS
}

// OfflineMessage represents a stored message for offline delivery
type OfflineMessage struct {
	From      string `json:"from" mapstructure:"from"`
	Message   string `json:"message" mapstructure:"message"`
	SessionID string `json:"session_id,omitempty" mapstructure:"session_id"`
	Timestamp int64  `json:"timestamp" mapstructure:"timestamp"`
	MessageID string `json:"message_id" mapstructure:"message_id"`
}
