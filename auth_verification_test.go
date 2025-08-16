package main

import (
	"encoding/base64"
	"testing"

	"aimessage/internal/crypto"
	"aimessage/internal/protocol"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestAuthenticationFixed verifies that the authentication bug is fixed
func TestAuthenticationFixed(t *testing.T) {
	suite := SetupTestSuite(t)

	conn, err := suite.ConnectWebSocket()
	require.NoError(t, err)
	defer conn.Close()

	// Step 1: Register a new user
	registerMsg := protocol.NewMessage(protocol.MsgTypeRegister, protocol.RegisterRequest{
		Username: "auth_test_user",
	})

	response, err := suite.SendMessage(conn, registerMsg)
	require.NoError(t, err)
	assert.Equal(t, protocol.MsgTypeRegistered, response.Type)

	var registerResp protocol.RegisterResponse
	err = response.ParseData(&registerResp)
	require.NoError(t, err)
	assert.Equal(t, "auth_test_user", registerResp.Username)
	assert.NotEmpty(t, registerResp.Token)
	assert.NotEmpty(t, registerResp.Salt)

	// Step 2: Create user crypto instance for authentication
	saltBytes, err := base64.StdEncoding.DecodeString(registerResp.Salt)
	require.NoError(t, err)
	userCrypto := crypto.NewUserCrypto(registerResp.Token, saltBytes)

	// Step 3: Start authentication - request challenge
	authMsg := protocol.NewMessage(protocol.MsgTypeAuthenticate, protocol.AuthenticationRequest{
		Username: "auth_test_user",
		Token:    "",
	})

	challengeResponse, err := suite.SendMessage(conn, authMsg)
	require.NoError(t, err)
	assert.Equal(t, protocol.MsgTypeChallenge, challengeResponse.Type)

	var challengeReq protocol.ChallengeRequest
	err = challengeResponse.ParseData(&challengeReq)
	require.NoError(t, err)
	assert.NotEmpty(t, challengeReq.Challenge)
	t.Logf("Received challenge: %s", challengeReq.Challenge)

	// Step 4: Encrypt the challenge and send back
	encryptedChallenge, err := userCrypto.Encrypt(challengeReq.Challenge)
	require.NoError(t, err)
	t.Logf("Encrypted challenge: %s", encryptedChallenge)

	authResponseMsg := protocol.NewMessage(protocol.MsgTypeAuthenticate, protocol.AuthenticationRequest{
		Username:  "auth_test_user",
		Challenge: encryptedChallenge,
	})

	authResult, err := suite.SendMessage(conn, authResponseMsg)
	require.NoError(t, err)

	// Step 5: Verify authentication succeeded
	t.Logf("Authentication result type: %v", authResult.Type)

	if authResult.Type == protocol.MsgTypeError {
		var errorResp protocol.ErrorResponse
		err = authResult.ParseData(&errorResp)
		require.NoError(t, err)
		t.Fatalf("Authentication failed: %d - %s", errorResp.Code, errorResp.Message)
	}

	// Authentication should succeed with MsgTypeAck
	assert.Equal(t, protocol.MsgTypeAck, authResult.Type)

	var ackResp map[string]string
	err = authResult.ParseData(&ackResp)
	require.NoError(t, err)
	assert.Equal(t, "authenticated", ackResp["status"])

	t.Log("✅ Authentication bug is FIXED! Authentication completed successfully.")
}

// TestAuthenticationWithWrongChallenge tests that invalid challenges are rejected
func TestAuthenticationWithWrongChallenge(t *testing.T) {
	suite := SetupTestSuite(t)

	conn, err := suite.ConnectWebSocket()
	require.NoError(t, err)
	defer conn.Close()

	// Step 1: Register a new user
	registerMsg := protocol.NewMessage(protocol.MsgTypeRegister, protocol.RegisterRequest{
		Username: "auth_wrong_test",
	})

	response, err := suite.SendMessage(conn, registerMsg)
	require.NoError(t, err)

	var registerResp protocol.RegisterResponse
	err = response.ParseData(&registerResp)
	require.NoError(t, err)

	// Step 2: Request challenge
	authMsg := protocol.NewMessage(protocol.MsgTypeAuthenticate, protocol.AuthenticationRequest{
		Username: "auth_wrong_test",
		Token:    "",
	})

	challengeResponse, err := suite.SendMessage(conn, authMsg)
	require.NoError(t, err)
	assert.Equal(t, protocol.MsgTypeChallenge, challengeResponse.Type)

	// Step 3: Send wrong challenge response
	authResponseMsg := protocol.NewMessage(protocol.MsgTypeAuthenticate, protocol.AuthenticationRequest{
		Username:  "auth_wrong_test",
		Challenge: "wrong_encrypted_challenge",
	})

	authResult, err := suite.SendMessage(conn, authResponseMsg)
	require.NoError(t, err)

	// Should fail with error
	assert.Equal(t, protocol.MsgTypeError, authResult.Type)

	var errorResp protocol.ErrorResponse
	err = authResult.ParseData(&errorResp)
	require.NoError(t, err)
	assert.Equal(t, 401, errorResp.Code)
	assert.Equal(t, "Invalid challenge response", errorResp.Message)

	t.Log("✅ Invalid challenge correctly rejected")
}
