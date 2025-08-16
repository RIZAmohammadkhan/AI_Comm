package main

import (
	"aimessage/internal/protocol"
	"fmt"
	"log"
	"time"
)

func testProtocolParsing() {
	// Test the improved ParseData method with mapstructure

	// Create a sample message with register request data
	registerData := protocol.RegisterRequest{
		Username: "testuser",
	}

	msg := protocol.NewMessage(protocol.MsgTypeRegister, registerData)

	// Marshal it to simulate receiving over network
	data, err := msg.Marshal()
	if err != nil {
		log.Fatal("Failed to marshal:", err)
	}

	// Unmarshal it back
	receivedMsg, err := protocol.UnmarshalMessage(data)
	if err != nil {
		log.Fatal("Failed to unmarshal:", err)
	}

	// Test the improved ParseData method
	var parsedData protocol.RegisterRequest
	start := time.Now()
	err = receivedMsg.ParseData(&parsedData)
	elapsed := time.Since(start)

	if err != nil {
		log.Fatal("Failed to parse data:", err)
	}

	fmt.Printf("Successfully parsed data using mapstructure: %+v\n", parsedData)
	fmt.Printf("Parse time: %v\n", elapsed)

	// Test with SecureMessage to verify PFS-related fields
	secureMsg := protocol.SecureMessage{
		To:        "recipient",
		Message:   "encrypted_content",
		SessionID: "session123",
	}

	msg2 := protocol.NewMessage(protocol.MsgTypeSend, secureMsg)
	data2, _ := msg2.Marshal()
	receivedMsg2, _ := protocol.UnmarshalMessage(data2)

	var parsedSecure protocol.SecureMessage
	err = receivedMsg2.ParseData(&parsedSecure)
	if err != nil {
		log.Fatal("Failed to parse secure message:", err)
	}

	fmt.Printf("Successfully parsed secure message: %+v\n", parsedSecure)

	fmt.Println("✅ Protocol parsing improvements working correctly!")
}

func main() {
	testProtocolParsing()
}
