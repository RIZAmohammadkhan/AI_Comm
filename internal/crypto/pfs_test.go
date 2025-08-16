package crypto

import (
	"testing"
)

func TestDiffieHellmanKeyExchange(t *testing.T) {
	// Test complete DH key exchange flow

	// Alice generates her key pair
	aliceKeyPair, err := GenerateDHKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate Alice's key pair: %v", err)
	}

	// Bob generates his key pair
	bobKeyPair, err := GenerateDHKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate Bob's key pair: %v", err)
	}

	// Alice computes shared secret using Bob's public key
	aliceSharedSecret, err := ComputeSharedSecret(aliceKeyPair.PrivateKey, bobKeyPair.PublicKey)
	if err != nil {
		t.Fatalf("Alice failed to compute shared secret: %v", err)
	}

	// Bob computes shared secret using Alice's public key
	bobSharedSecret, err := ComputeSharedSecret(bobKeyPair.PrivateKey, aliceKeyPair.PublicKey)
	if err != nil {
		t.Fatalf("Bob failed to compute shared secret: %v", err)
	}

	// Both should have the same shared secret
	if len(aliceSharedSecret) != len(bobSharedSecret) {
		t.Fatalf("Shared secret lengths don't match: Alice=%d, Bob=%d",
			len(aliceSharedSecret), len(bobSharedSecret))
	}

	for i := range aliceSharedSecret {
		if aliceSharedSecret[i] != bobSharedSecret[i] {
			t.Fatalf("Shared secrets don't match at index %d", i)
		}
	}

	t.Logf("✅ DH key exchange successful, shared secret length: %d bytes", len(aliceSharedSecret))
}

func TestSessionKeysDerivation(t *testing.T) {
	// Test session key derivation for PFS

	// Generate some test data
	sharedSecret := []byte("test_shared_secret_32_bytes_long")
	sessionID := "test-session-123"
	salt, err := GenerateSalt()
	if err != nil {
		t.Fatalf("Failed to generate salt: %v", err)
	}

	// Derive session keys
	sessionKeys, err := DeriveSessionKeys(sharedSecret, sessionID, salt)
	if err != nil {
		t.Fatalf("Failed to derive session keys: %v", err)
	}

	// Verify session keys structure
	if sessionKeys.SessionID != sessionID {
		t.Fatalf("Session ID mismatch: expected %s, got %s", sessionID, sessionKeys.SessionID)
	}

	if len(sessionKeys.EncryptKey) != 32 { // AES-256
		t.Fatalf("Invalid encrypt key length: expected 32, got %d", len(sessionKeys.EncryptKey))
	}

	if len(sessionKeys.SharedSecret) != len(sharedSecret) {
		t.Fatalf("Shared secret length mismatch")
	}

	t.Logf("✅ Session keys derived successfully")
}

func TestSessionCrypto(t *testing.T) {
	// Test session-based encryption/decryption

	// Create test session keys
	sharedSecret := []byte("test_shared_secret_32_bytes_long")
	sessionID := "test-session-456"
	salt, err := GenerateSalt()
	if err != nil {
		t.Fatalf("Failed to generate salt: %v", err)
	}

	sessionKeys, err := DeriveSessionKeys(sharedSecret, sessionID, salt)
	if err != nil {
		t.Fatalf("Failed to derive session keys: %v", err)
	}

	// Create session crypto instance
	sessionCrypto := NewSessionCrypto(sessionKeys)

	// Test message
	testMessage := "This is a secret message with Perfect Forward Secrecy!"

	// Encrypt
	encrypted, err := sessionCrypto.Encrypt(testMessage)
	if err != nil {
		t.Fatalf("Failed to encrypt: %v", err)
	}

	// Decrypt
	decrypted, err := sessionCrypto.Decrypt(encrypted)
	if err != nil {
		t.Fatalf("Failed to decrypt: %v", err)
	}

	// Verify
	if decrypted != testMessage {
		t.Fatalf("Message mismatch: expected '%s', got '%s'", testMessage, decrypted)
	}

	t.Logf("✅ Session crypto test passed")
}

func TestCompletePFSFlow(t *testing.T) {
	// Test complete Perfect Forward Secrecy flow

	// Step 1: Both parties generate key pairs
	clientKeyPair, err := GenerateDHKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate client key pair: %v", err)
	}

	serverKeyPair, err := GenerateDHKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate server key pair: %v", err)
	}

	// Step 2: Exchange public keys and compute shared secrets
	clientSharedSecret, err := ComputeSharedSecret(clientKeyPair.PrivateKey, serverKeyPair.PublicKey)
	if err != nil {
		t.Fatalf("Client failed to compute shared secret: %v", err)
	}

	serverSharedSecret, err := ComputeSharedSecret(serverKeyPair.PrivateKey, clientKeyPair.PublicKey)
	if err != nil {
		t.Fatalf("Server failed to compute shared secret: %v", err)
	}

	// Step 3: Both derive session keys with same parameters
	sessionID := "pfs-test-session"
	salt, err := GenerateSalt()
	if err != nil {
		t.Fatalf("Failed to generate salt: %v", err)
	}

	clientSessionKeys, err := DeriveSessionKeys(clientSharedSecret, sessionID, salt)
	if err != nil {
		t.Fatalf("Client failed to derive session keys: %v", err)
	}

	serverSessionKeys, err := DeriveSessionKeys(serverSharedSecret, sessionID, salt)
	if err != nil {
		t.Fatalf("Server failed to derive session keys: %v", err)
	}

	// Step 4: Create session crypto instances
	clientCrypto := NewSessionCrypto(clientSessionKeys)
	serverCrypto := NewSessionCrypto(serverSessionKeys)

	// Step 5: Test bidirectional communication
	clientMessage := "Hello from client with PFS!"
	serverMessage := "Hello from server with PFS!"

	// Client encrypts message
	clientEncrypted, err := clientCrypto.Encrypt(clientMessage)
	if err != nil {
		t.Fatalf("Client encryption failed: %v", err)
	}

	// Server decrypts client's message
	clientDecrypted, err := serverCrypto.Decrypt(clientEncrypted)
	if err != nil {
		t.Fatalf("Server decryption failed: %v", err)
	}

	if clientDecrypted != clientMessage {
		t.Fatalf("Client message mismatch: expected '%s', got '%s'", clientMessage, clientDecrypted)
	}

	// Server encrypts response
	serverEncrypted, err := serverCrypto.Encrypt(serverMessage)
	if err != nil {
		t.Fatalf("Server encryption failed: %v", err)
	}

	// Client decrypts server's response
	serverDecrypted, err := clientCrypto.Decrypt(serverEncrypted)
	if err != nil {
		t.Fatalf("Client decryption failed: %v", err)
	}

	if serverDecrypted != serverMessage {
		t.Fatalf("Server message mismatch: expected '%s', got '%s'", serverMessage, serverDecrypted)
	}

	t.Logf("✅ Complete PFS flow test passed!")
	t.Logf("   Client->Server: '%s'", clientDecrypted)
	t.Logf("   Server->Client: '%s'", serverDecrypted)
}
