package protocol

import (
	"testing"
	"time"
)

func TestParseDataWithMapstructure(t *testing.T) {
	// Test the improved ParseData method using mapstructure

	// Test with RegisterRequest
	originalData := RegisterRequest{
		Username: "testuser123",
	}

	msg := NewMessage(MsgTypeRegister, originalData)

	// Simulate network transmission
	jsonData, err := msg.Marshal()
	if err != nil {
		t.Fatalf("Failed to marshal message: %v", err)
	}

	receivedMsg, err := UnmarshalMessage(jsonData)
	if err != nil {
		t.Fatalf("Failed to unmarshal message: %v", err)
	}

	// Parse using improved method
	var parsedData RegisterRequest
	err = receivedMsg.ParseData(&parsedData)
	if err != nil {
		t.Fatalf("Failed to parse data: %v", err)
	}

	// Verify
	if parsedData.Username != originalData.Username {
		t.Fatalf("Username mismatch: expected %s, got %s", originalData.Username, parsedData.Username)
	}

	t.Logf("✅ RegisterRequest parsing successful")
}

func TestParseDataWithSecureMessage(t *testing.T) {
	// Test parsing SecureMessage (for PFS)

	originalData := SecureMessage{
		To:        "recipient",
		Message:   "encrypted_message_content",
		SessionID: "session-12345",
	}

	msg := NewMessage(MsgTypeSend, originalData)

	// Simulate network transmission
	jsonData, err := msg.Marshal()
	if err != nil {
		t.Fatalf("Failed to marshal message: %v", err)
	}

	receivedMsg, err := UnmarshalMessage(jsonData)
	if err != nil {
		t.Fatalf("Failed to unmarshal message: %v", err)
	}

	// Parse using improved method
	var parsedData SecureMessage
	err = receivedMsg.ParseData(&parsedData)
	if err != nil {
		t.Fatalf("Failed to parse data: %v", err)
	}

	// Verify all fields
	if parsedData.To != originalData.To {
		t.Fatalf("To field mismatch: expected %s, got %s", originalData.To, parsedData.To)
	}
	if parsedData.Message != originalData.Message {
		t.Fatalf("Message field mismatch: expected %s, got %s", originalData.Message, parsedData.Message)
	}
	if parsedData.SessionID != originalData.SessionID {
		t.Fatalf("SessionID field mismatch: expected %s, got %s", originalData.SessionID, parsedData.SessionID)
	}

	t.Logf("✅ SecureMessage parsing successful")
}

func TestParseDataWithKeyExchange(t *testing.T) {
	// Test parsing key exchange messages

	keyReq := KeyExchangeRequest{
		To:        "recipient",
		PublicKey: "base64_encoded_public_key",
		SessionID: "session-456",
	}

	msg := NewMessage(MsgTypeKeyExchange, keyReq)

	// Simulate network transmission
	jsonData, err := msg.Marshal()
	if err != nil {
		t.Fatalf("Failed to marshal message: %v", err)
	}

	receivedMsg, err := UnmarshalMessage(jsonData)
	if err != nil {
		t.Fatalf("Failed to unmarshal message: %v", err)
	}

	// Parse using improved method
	var parsedReq KeyExchangeRequest
	err = receivedMsg.ParseData(&parsedReq)
	if err != nil {
		t.Fatalf("Failed to parse key exchange request: %v", err)
	}

	// Verify
	if parsedReq.To != keyReq.To {
		t.Fatalf("To field mismatch: expected %s, got %s", keyReq.To, parsedReq.To)
	}
	if parsedReq.PublicKey != keyReq.PublicKey {
		t.Fatalf("PublicKey field mismatch: expected %s, got %s", keyReq.PublicKey, parsedReq.PublicKey)
	}
	if parsedReq.SessionID != keyReq.SessionID {
		t.Fatalf("SessionID field mismatch: expected %s, got %s", keyReq.SessionID, parsedReq.SessionID)
	}

	t.Logf("✅ KeyExchangeRequest parsing successful")
}

func TestParseDataPerformance(t *testing.T) {
	// Compare parsing performance

	testData := SecureMessage{
		To:        "performance_test_user",
		Message:   "this_is_a_test_message_for_performance_comparison",
		SessionID: "perf-session-789",
	}

	msg := NewMessage(MsgTypeSend, testData)
	jsonData, _ := msg.Marshal()

	// Run multiple iterations to get average
	iterations := 1000
	start := time.Now()

	for i := 0; i < iterations; i++ {
		receivedMsg, _ := UnmarshalMessage(jsonData)
		var parsedData SecureMessage
		_ = receivedMsg.ParseData(&parsedData)
	}

	elapsed := time.Since(start)
	avgTime := elapsed / time.Duration(iterations)

	t.Logf("✅ Performance test: %d iterations in %v (avg: %v per parse)",
		iterations, elapsed, avgTime)
}
