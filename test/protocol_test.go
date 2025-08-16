package test

import (
	"encoding/json"
	"testing"
	"time"

	"aimessage/internal/protocol"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMessageTypes(t *testing.T) {
	// Test all message type constants exist
	assert.Equal(t, protocol.MessageType("register"), protocol.MsgTypeRegister)
	assert.Equal(t, protocol.MessageType("send"), protocol.MsgTypeSend)
	assert.Equal(t, protocol.MessageType("listen"), protocol.MsgTypeListen)
	assert.Equal(t, protocol.MessageType("list_users"), protocol.MsgTypeListUsers)
	assert.Equal(t, protocol.MessageType("heartbeat"), protocol.MsgTypeHeartbeat)
	assert.Equal(t, protocol.MessageType("authenticate"), protocol.MsgTypeAuthenticate)
	assert.Equal(t, protocol.MessageType("key_exchange"), protocol.MsgTypeKeyExchange)

	// Server to client messages
	assert.Equal(t, protocol.MessageType("registered"), protocol.MsgTypeRegistered)
	assert.Equal(t, protocol.MessageType("message"), protocol.MsgTypeMessage)
	assert.Equal(t, protocol.MessageType("user_list"), protocol.MsgTypeUserList)
	assert.Equal(t, protocol.MessageType("error"), protocol.MsgTypeError)
	assert.Equal(t, protocol.MessageType("ack"), protocol.MsgTypeAck)
	assert.Equal(t, protocol.MessageType("challenge"), protocol.MsgTypeChallenge)
	assert.Equal(t, protocol.MessageType("key_request"), protocol.MsgTypeKeyRequest)
	assert.Equal(t, protocol.MessageType("key_response"), protocol.MsgTypeKeyResponse)
	assert.Equal(t, protocol.MessageType("offline_message"), protocol.MsgTypeOfflineMsg)
}

func TestNewMessage(t *testing.T) {
	data := map[string]string{"key": "value"}
	msg := protocol.NewMessage(protocol.MsgTypeRegister, data)

	assert.NotNil(t, msg)
	assert.Equal(t, protocol.MsgTypeRegister, msg.Type)
	assert.Equal(t, data, msg.Data)
	assert.NotZero(t, msg.Timestamp)
	assert.True(t, msg.Timestamp <= time.Now().Unix())
}

func TestNewMessageWithNilData(t *testing.T) {
	msg := protocol.NewMessage(protocol.MsgTypeHeartbeat, nil)

	assert.NotNil(t, msg)
	assert.Equal(t, protocol.MsgTypeHeartbeat, msg.Type)
	assert.Nil(t, msg.Data)
	assert.NotZero(t, msg.Timestamp)
}

func TestMessageMarshal(t *testing.T) {
	data := protocol.RegisterRequest{Username: "testuser"}
	msg := protocol.NewMessage(protocol.MsgTypeRegister, data)
	msg.ID = "test-id-123"

	marshaled, err := msg.Marshal()
	require.NoError(t, err)
	assert.NotEmpty(t, marshaled)

	// Should be valid JSON
	var jsonData map[string]interface{}
	err = json.Unmarshal(marshaled, &jsonData)
	require.NoError(t, err)

	assert.Equal(t, "register", jsonData["type"])
	assert.Equal(t, "test-id-123", jsonData["id"])
	assert.NotNil(t, jsonData["timestamp"])
	assert.NotNil(t, jsonData["data"])
}

func TestUnmarshalMessage(t *testing.T) {
	originalData := protocol.RegisterRequest{Username: "testuser"}
	originalMsg := protocol.NewMessage(protocol.MsgTypeRegister, originalData)
	originalMsg.ID = "test-id-123"

	marshaled, err := originalMsg.Marshal()
	require.NoError(t, err)

	// Unmarshal the message
	unmarshaledMsg, err := protocol.UnmarshalMessage(marshaled)
	require.NoError(t, err)
	assert.NotNil(t, unmarshaledMsg)

	assert.Equal(t, originalMsg.Type, unmarshaledMsg.Type)
	assert.Equal(t, originalMsg.ID, unmarshaledMsg.ID)
	assert.Equal(t, originalMsg.Timestamp, unmarshaledMsg.Timestamp)
	assert.NotNil(t, unmarshaledMsg.Data)
}

func TestUnmarshalInvalidJSON(t *testing.T) {
	invalidJSON := []byte("{invalid json}")

	_, err := protocol.UnmarshalMessage(invalidJSON)
	assert.Error(t, err)
}

func TestParseData(t *testing.T) {
	// Create a message with RegisterRequest data
	originalData := protocol.RegisterRequest{Username: "testuser"}
	msg := protocol.NewMessage(protocol.MsgTypeRegister, originalData)

	// Parse data into RegisterRequest struct
	var parsedData protocol.RegisterRequest
	err := msg.ParseData(&parsedData)
	require.NoError(t, err)

	assert.Equal(t, originalData.Username, parsedData.Username)
}

func TestParseDataWithNilData(t *testing.T) {
	msg := protocol.NewMessage(protocol.MsgTypeHeartbeat, nil)

	var parsedData protocol.RegisterRequest
	err := msg.ParseData(&parsedData)
	require.NoError(t, err)

	// Should not error with nil data
	assert.Empty(t, parsedData.Username)
}

func TestParseDataInvalidStructure(t *testing.T) {
	// Create message with wrong data type
	msg := protocol.NewMessage(protocol.MsgTypeRegister, "invalid data type")

	var parsedData protocol.RegisterRequest
	err := msg.ParseData(&parsedData)
	assert.Error(t, err)
}

func TestRegisterRequest(t *testing.T) {
	req := protocol.RegisterRequest{Username: "testuser"}

	assert.Equal(t, "testuser", req.Username)

	// Test JSON marshaling
	data, err := json.Marshal(req)
	require.NoError(t, err)

	var unmarshaled protocol.RegisterRequest
	err = json.Unmarshal(data, &unmarshaled)
	require.NoError(t, err)
	assert.Equal(t, req.Username, unmarshaled.Username)
}

func TestRegisterResponse(t *testing.T) {
	resp := protocol.RegisterResponse{
		Token:    "test-token",
		Salt:     "test-salt-base64",
		Username: "testuser",
	}

	assert.Equal(t, "test-token", resp.Token)
	assert.Equal(t, "test-salt-base64", resp.Salt)
	assert.Equal(t, "testuser", resp.Username)

	// Test JSON marshaling
	data, err := json.Marshal(resp)
	require.NoError(t, err)

	var unmarshaled protocol.RegisterResponse
	err = json.Unmarshal(data, &unmarshaled)
	require.NoError(t, err)
	assert.Equal(t, resp.Token, unmarshaled.Token)
	assert.Equal(t, resp.Salt, unmarshaled.Salt)
	assert.Equal(t, resp.Username, unmarshaled.Username)
}

func TestSendRequest(t *testing.T) {
	req := protocol.SendRequest{
		To:      "recipient",
		Message: "encrypted-message-content",
	}

	assert.Equal(t, "recipient", req.To)
	assert.Equal(t, "encrypted-message-content", req.Message)
}

func TestMessageDelivery(t *testing.T) {
	delivery := protocol.MessageDelivery{
		From:      "sender",
		Message:   "encrypted-message-content",
		Timestamp: time.Now().Unix(),
	}

	assert.Equal(t, "sender", delivery.From)
	assert.Equal(t, "encrypted-message-content", delivery.Message)
	assert.NotZero(t, delivery.Timestamp)
}

func TestUserListResponse(t *testing.T) {
	users := []string{"user1", "user2", "user3"}
	resp := protocol.UserListResponse{Users: users}

	assert.Equal(t, users, resp.Users)
	assert.Len(t, resp.Users, 3)
}

func TestErrorResponse(t *testing.T) {
	errorResp := protocol.ErrorResponse{
		Code:    404,
		Message: "User not found",
	}

	assert.Equal(t, 404, errorResp.Code)
	assert.Equal(t, "User not found", errorResp.Message)
}

func TestAuthenticationRequest(t *testing.T) {
	authReq := protocol.AuthenticationRequest{
		Username:  "testuser",
		Token:     "test-token",
		Challenge: "encrypted-challenge-response",
	}

	assert.Equal(t, "testuser", authReq.Username)
	assert.Equal(t, "test-token", authReq.Token)
	assert.Equal(t, "encrypted-challenge-response", authReq.Challenge)
}

func TestChallengeRequest(t *testing.T) {
	challengeReq := protocol.ChallengeRequest{
		Challenge: "random-challenge-string",
		Timestamp: time.Now().Unix(),
	}

	assert.Equal(t, "random-challenge-string", challengeReq.Challenge)
	assert.NotZero(t, challengeReq.Timestamp)
}

func TestKeyExchangeRequest(t *testing.T) {
	keyReq := protocol.KeyExchangeRequest{
		To:        "recipient",
		PublicKey: "base64-encoded-public-key",
		SessionID: "session-123",
	}

	assert.Equal(t, "recipient", keyReq.To)
	assert.Equal(t, "base64-encoded-public-key", keyReq.PublicKey)
	assert.Equal(t, "session-123", keyReq.SessionID)
}

func TestKeyExchangeResponse(t *testing.T) {
	keyResp := protocol.KeyExchangeResponse{
		From:      "sender",
		PublicKey: "base64-encoded-public-key",
		SessionID: "session-123",
	}

	assert.Equal(t, "sender", keyResp.From)
	assert.Equal(t, "base64-encoded-public-key", keyResp.PublicKey)
	assert.Equal(t, "session-123", keyResp.SessionID)
}

func TestSecureMessage(t *testing.T) {
	secureMsg := protocol.SecureMessage{
		To:        "recipient",
		Message:   "encrypted-with-session-key",
		SessionID: "session-123",
	}

	assert.Equal(t, "recipient", secureMsg.To)
	assert.Equal(t, "encrypted-with-session-key", secureMsg.Message)
	assert.Equal(t, "session-123", secureMsg.SessionID)
}

func TestOfflineMessage(t *testing.T) {
	offlineMsg := protocol.OfflineMessage{
		From:      "sender",
		Message:   "encrypted-offline-message",
		SessionID: "session-123",
		Timestamp: time.Now().Unix(),
		MessageID: "msg-456",
	}

	assert.Equal(t, "sender", offlineMsg.From)
	assert.Equal(t, "encrypted-offline-message", offlineMsg.Message)
	assert.Equal(t, "session-123", offlineMsg.SessionID)
	assert.NotZero(t, offlineMsg.Timestamp)
	assert.Equal(t, "msg-456", offlineMsg.MessageID)
}

func TestCompleteMessageFlow(t *testing.T) {
	// Test a complete message flow: register -> authenticate -> send

	// 1. Registration
	registerReq := protocol.RegisterRequest{Username: "testuser"}
	registerMsg := protocol.NewMessage(protocol.MsgTypeRegister, registerReq)
	registerMsg.ID = "reg-123"

	// Marshal and unmarshal
	data, err := registerMsg.Marshal()
	require.NoError(t, err)

	unmarshaledRegister, err := protocol.UnmarshalMessage(data)
	require.NoError(t, err)

	var parsedRegister protocol.RegisterRequest
	err = unmarshaledRegister.ParseData(&parsedRegister)
	require.NoError(t, err)
	assert.Equal(t, "testuser", parsedRegister.Username)

	// 2. Registration Response
	registerResp := protocol.RegisterResponse{
		Token:    "generated-token",
		Salt:     "generated-salt",
		Username: "testuser",
	}
	respMsg := protocol.NewMessage(protocol.MsgTypeRegistered, registerResp)

	// 3. Authentication
	authReq := protocol.AuthenticationRequest{
		Username: "testuser",
		Token:    "generated-token",
	}
	authMsg := protocol.NewMessage(protocol.MsgTypeAuthenticate, authReq)

	// 4. Send Message
	sendReq := protocol.SendRequest{
		To:      "recipient",
		Message: "encrypted-message",
	}
	sendMsg := protocol.NewMessage(protocol.MsgTypeSend, sendReq)

	// All messages should be valid
	assert.Equal(t, protocol.MsgTypeRegister, unmarshaledRegister.Type)
	assert.Equal(t, protocol.MsgTypeRegistered, respMsg.Type)
	assert.Equal(t, protocol.MsgTypeAuthenticate, authMsg.Type)
	assert.Equal(t, protocol.MsgTypeSend, sendMsg.Type)
}

func TestMessageWithMapStructure(t *testing.T) {
	// Test that mapstructure tags work correctly
	data := map[string]interface{}{
		"username": "mapstructure-user",
	}

	msg := protocol.NewMessage(protocol.MsgTypeRegister, data)

	var parsed protocol.RegisterRequest
	err := msg.ParseData(&parsed)
	require.NoError(t, err)

	assert.Equal(t, "mapstructure-user", parsed.Username)
}

// Benchmark tests
func BenchmarkNewMessage(b *testing.B) {
	data := protocol.RegisterRequest{Username: "benchuser"}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		protocol.NewMessage(protocol.MsgTypeRegister, data)
	}
}

func BenchmarkMessageMarshal(b *testing.B) {
	data := protocol.RegisterRequest{Username: "benchuser"}
	msg := protocol.NewMessage(protocol.MsgTypeRegister, data)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		msg.Marshal()
	}
}

func BenchmarkUnmarshalMessage(b *testing.B) {
	data := protocol.RegisterRequest{Username: "benchuser"}
	msg := protocol.NewMessage(protocol.MsgTypeRegister, data)
	marshaled, _ := msg.Marshal()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		protocol.UnmarshalMessage(marshaled)
	}
}

func BenchmarkParseData(b *testing.B) {
	data := protocol.RegisterRequest{Username: "benchuser"}
	msg := protocol.NewMessage(protocol.MsgTypeRegister, data)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var parsed protocol.RegisterRequest
		msg.ParseData(&parsed)
	}
}
