package test

import (
	"encoding/base64"
	"testing"

	"aimessage/internal/crypto"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGenerateSalt(t *testing.T) {
	salt1, err := crypto.GenerateSalt()
	require.NoError(t, err)
	assert.Len(t, salt1, 16) // saltLength is 16

	salt2, err := crypto.GenerateSalt()
	require.NoError(t, err)
	assert.Len(t, salt2, 16)

	// Should generate different salts
	assert.NotEqual(t, salt1, salt2)
}

func TestGenerateUserToken(t *testing.T) {
	token1, err := crypto.GenerateUserToken()
	require.NoError(t, err)
	assert.NotEmpty(t, token1)

	token2, err := crypto.GenerateUserToken()
	require.NoError(t, err)
	assert.NotEmpty(t, token2)

	// Should generate different tokens
	assert.NotEqual(t, token1, token2)

	// Should be valid base64
	_, err = base64.URLEncoding.DecodeString(token1)
	assert.NoError(t, err)
}

func TestNewUserCrypto(t *testing.T) {
	salt, err := crypto.GenerateSalt()
	require.NoError(t, err)

	token, err := crypto.GenerateUserToken()
	require.NoError(t, err)

	userCrypto := crypto.NewUserCrypto(token, salt)
	assert.NotNil(t, userCrypto)
}

func TestUserCryptoEncryptDecrypt(t *testing.T) {
	salt, err := crypto.GenerateSalt()
	require.NoError(t, err)

	token, err := crypto.GenerateUserToken()
	require.NoError(t, err)

	userCrypto := crypto.NewUserCrypto(token, salt)

	plaintext := "Hello, World! This is a test message."

	// Test encryption
	encrypted, err := userCrypto.Encrypt(plaintext)
	require.NoError(t, err)
	assert.NotEmpty(t, encrypted)
	assert.NotEqual(t, plaintext, encrypted)

	// Should be valid base64
	_, err = base64.StdEncoding.DecodeString(encrypted)
	assert.NoError(t, err)

	// Test decryption
	decrypted, err := userCrypto.Decrypt(encrypted)
	require.NoError(t, err)
	assert.Equal(t, plaintext, decrypted)
}

func TestUserCryptoEncryptDecryptEmpty(t *testing.T) {
	salt, err := crypto.GenerateSalt()
	require.NoError(t, err)

	token, err := crypto.GenerateUserToken()
	require.NoError(t, err)

	userCrypto := crypto.NewUserCrypto(token, salt)

	// Test empty string
	encrypted, err := userCrypto.Encrypt("")
	require.NoError(t, err)
	assert.NotEmpty(t, encrypted) // Should still have nonce

	decrypted, err := userCrypto.Decrypt(encrypted)
	require.NoError(t, err)
	assert.Equal(t, "", decrypted)
}

func TestUserCryptoDecryptInvalidData(t *testing.T) {
	salt, err := crypto.GenerateSalt()
	require.NoError(t, err)

	token, err := crypto.GenerateUserToken()
	require.NoError(t, err)

	userCrypto := crypto.NewUserCrypto(token, salt)

	// Test invalid base64
	_, err = userCrypto.Decrypt("invalid-base64!")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to decode base64")

	// Test short data
	shortData := base64.StdEncoding.EncodeToString([]byte("short"))
	_, err = userCrypto.Decrypt(shortData)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "encrypted data too short")

	// Test corrupted data
	validData, _ := userCrypto.Encrypt("test")
	decoded, _ := base64.StdEncoding.DecodeString(validData)
	// Corrupt the data
	decoded[0] = decoded[0] ^ 0xFF
	corruptedData := base64.StdEncoding.EncodeToString(decoded)
	_, err = userCrypto.Decrypt(corruptedData)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to decrypt")
}

func TestGenerateDHKeyPair(t *testing.T) {
	keyPair1, err := crypto.GenerateDHKeyPair()
	require.NoError(t, err)
	assert.NotNil(t, keyPair1)
	assert.NotEmpty(t, keyPair1.PrivateKey)
	assert.NotEmpty(t, keyPair1.PublicKey)

	keyPair2, err := crypto.GenerateDHKeyPair()
	require.NoError(t, err)
	assert.NotNil(t, keyPair2)

	// Should generate different key pairs
	assert.NotEqual(t, keyPair1.PrivateKey, keyPair2.PrivateKey)
	assert.NotEqual(t, keyPair1.PublicKey, keyPair2.PublicKey)
}

func TestComputeSharedSecret(t *testing.T) {
	// Generate two key pairs
	keyPair1, err := crypto.GenerateDHKeyPair()
	require.NoError(t, err)

	keyPair2, err := crypto.GenerateDHKeyPair()
	require.NoError(t, err)

	// Compute shared secrets from both sides
	secret1, err := crypto.ComputeSharedSecret(keyPair1.PrivateKey, keyPair2.PublicKey)
	require.NoError(t, err)
	assert.NotEmpty(t, secret1)

	secret2, err := crypto.ComputeSharedSecret(keyPair2.PrivateKey, keyPair1.PublicKey)
	require.NoError(t, err)
	assert.NotEmpty(t, secret2)

	// Shared secrets should be the same
	assert.Equal(t, secret1, secret2)
}

func TestComputeSharedSecretInvalidKeys(t *testing.T) {
	keyPair, err := crypto.GenerateDHKeyPair()
	require.NoError(t, err)

	// Test invalid private key
	_, err = crypto.ComputeSharedSecret([]byte("invalid"), keyPair.PublicKey)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid private key")

	// Test invalid public key
	_, err = crypto.ComputeSharedSecret(keyPair.PrivateKey, []byte("invalid"))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid public key")
}

func TestDeriveSessionKeys(t *testing.T) {
	// Generate shared secret
	keyPair1, err := crypto.GenerateDHKeyPair()
	require.NoError(t, err)

	keyPair2, err := crypto.GenerateDHKeyPair()
	require.NoError(t, err)

	sharedSecret, err := crypto.ComputeSharedSecret(keyPair1.PrivateKey, keyPair2.PublicKey)
	require.NoError(t, err)

	sessionID := "test-session-123"
	salt, err := crypto.GenerateSalt()
	require.NoError(t, err)

	// Derive session keys
	sessionKeys, err := crypto.DeriveSessionKeys(sharedSecret, sessionID, salt)
	require.NoError(t, err)
	assert.NotNil(t, sessionKeys)
	assert.Equal(t, sharedSecret, sessionKeys.SharedSecret)
	assert.Equal(t, sessionID, sessionKeys.SessionID)
	assert.NotEmpty(t, sessionKeys.EncryptKey)
	assert.Len(t, sessionKeys.EncryptKey, 32) // AES-256 key length

	// Same inputs should produce same keys
	sessionKeys2, err := crypto.DeriveSessionKeys(sharedSecret, sessionID, salt)
	require.NoError(t, err)
	assert.Equal(t, sessionKeys.EncryptKey, sessionKeys2.EncryptKey)

	// Different session ID should produce different keys
	sessionKeys3, err := crypto.DeriveSessionKeys(sharedSecret, "different-session", salt)
	require.NoError(t, err)
	assert.NotEqual(t, sessionKeys.EncryptKey, sessionKeys3.EncryptKey)
}

func TestNewSessionCrypto(t *testing.T) {
	// Create session keys
	keyPair1, err := crypto.GenerateDHKeyPair()
	require.NoError(t, err)

	keyPair2, err := crypto.GenerateDHKeyPair()
	require.NoError(t, err)

	sharedSecret, err := crypto.ComputeSharedSecret(keyPair1.PrivateKey, keyPair2.PublicKey)
	require.NoError(t, err)

	sessionID := "test-session"
	salt, err := crypto.GenerateSalt()
	require.NoError(t, err)

	sessionKeys, err := crypto.DeriveSessionKeys(sharedSecret, sessionID, salt)
	require.NoError(t, err)

	// Create session crypto
	sessionCrypto := crypto.NewSessionCrypto(sessionKeys)
	assert.NotNil(t, sessionCrypto)
}

func TestSessionCryptoEncryptDecrypt(t *testing.T) {
	// Set up session crypto
	keyPair1, err := crypto.GenerateDHKeyPair()
	require.NoError(t, err)

	keyPair2, err := crypto.GenerateDHKeyPair()
	require.NoError(t, err)

	sharedSecret, err := crypto.ComputeSharedSecret(keyPair1.PrivateKey, keyPair2.PublicKey)
	require.NoError(t, err)

	sessionID := "test-session"
	salt, err := crypto.GenerateSalt()
	require.NoError(t, err)

	sessionKeys, err := crypto.DeriveSessionKeys(sharedSecret, sessionID, salt)
	require.NoError(t, err)

	sessionCrypto := crypto.NewSessionCrypto(sessionKeys)

	plaintext := "Session encrypted message with PFS!"

	// Test encryption
	encrypted, err := sessionCrypto.Encrypt(plaintext)
	require.NoError(t, err)
	assert.NotEmpty(t, encrypted)
	assert.NotEqual(t, plaintext, encrypted)

	// Should be valid base64
	_, err = base64.StdEncoding.DecodeString(encrypted)
	assert.NoError(t, err)

	// Test decryption
	decrypted, err := sessionCrypto.Decrypt(encrypted)
	require.NoError(t, err)
	assert.Equal(t, plaintext, decrypted)
}

func TestSessionCryptoDecryptInvalidData(t *testing.T) {
	// Set up session crypto
	keyPair1, err := crypto.GenerateDHKeyPair()
	require.NoError(t, err)

	keyPair2, err := crypto.GenerateDHKeyPair()
	require.NoError(t, err)

	sharedSecret, err := crypto.ComputeSharedSecret(keyPair1.PrivateKey, keyPair2.PublicKey)
	require.NoError(t, err)

	sessionID := "test-session"
	salt, err := crypto.GenerateSalt()
	require.NoError(t, err)

	sessionKeys, err := crypto.DeriveSessionKeys(sharedSecret, sessionID, salt)
	require.NoError(t, err)

	sessionCrypto := crypto.NewSessionCrypto(sessionKeys)

	// Test invalid base64
	_, err = sessionCrypto.Decrypt("invalid-base64!")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to decode base64")

	// Test short data
	shortData := base64.StdEncoding.EncodeToString([]byte("short"))
	_, err = sessionCrypto.Decrypt(shortData)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "encrypted data too short")
}

func TestCrossCompatibilityUserAndSession(t *testing.T) {
	// Create user crypto
	salt, err := crypto.GenerateSalt()
	require.NoError(t, err)

	token, err := crypto.GenerateUserToken()
	require.NoError(t, err)

	userCrypto := crypto.NewUserCrypto(token, salt)

	// Create session crypto
	keyPair1, err := crypto.GenerateDHKeyPair()
	require.NoError(t, err)

	keyPair2, err := crypto.GenerateDHKeyPair()
	require.NoError(t, err)

	sharedSecret, err := crypto.ComputeSharedSecret(keyPair1.PrivateKey, keyPair2.PublicKey)
	require.NoError(t, err)

	sessionID := "test-session"
	sessionSalt, err := crypto.GenerateSalt()
	require.NoError(t, err)

	sessionKeys, err := crypto.DeriveSessionKeys(sharedSecret, sessionID, sessionSalt)
	require.NoError(t, err)

	sessionCrypto := crypto.NewSessionCrypto(sessionKeys)

	plaintext := "Test message for both encryption types"

	// Encrypt with user crypto
	userEncrypted, err := userCrypto.Encrypt(plaintext)
	require.NoError(t, err)

	// Encrypt with session crypto
	sessionEncrypted, err := sessionCrypto.Encrypt(plaintext)
	require.NoError(t, err)

	// They should produce different ciphertexts
	assert.NotEqual(t, userEncrypted, sessionEncrypted)

	// Each should decrypt with its own method
	userDecrypted, err := userCrypto.Decrypt(userEncrypted)
	require.NoError(t, err)
	assert.Equal(t, plaintext, userDecrypted)

	sessionDecrypted, err := sessionCrypto.Decrypt(sessionEncrypted)
	require.NoError(t, err)
	assert.Equal(t, plaintext, sessionDecrypted)

	// Cross-decryption should fail
	_, err = userCrypto.Decrypt(sessionEncrypted)
	assert.Error(t, err)

	_, err = sessionCrypto.Decrypt(userEncrypted)
	assert.Error(t, err)
}

// Benchmark tests
func BenchmarkGenerateSalt(b *testing.B) {
	for i := 0; i < b.N; i++ {
		crypto.GenerateSalt()
	}
}

func BenchmarkGenerateUserToken(b *testing.B) {
	for i := 0; i < b.N; i++ {
		crypto.GenerateUserToken()
	}
}

func BenchmarkGenerateDHKeyPair(b *testing.B) {
	for i := 0; i < b.N; i++ {
		crypto.GenerateDHKeyPair()
	}
}

func BenchmarkUserCryptoEncrypt(b *testing.B) {
	salt, _ := crypto.GenerateSalt()
	token, _ := crypto.GenerateUserToken()
	userCrypto := crypto.NewUserCrypto(token, salt)
	plaintext := "This is a benchmark message for encryption testing."

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		userCrypto.Encrypt(plaintext)
	}
}

func BenchmarkUserCryptoDecrypt(b *testing.B) {
	salt, _ := crypto.GenerateSalt()
	token, _ := crypto.GenerateUserToken()
	userCrypto := crypto.NewUserCrypto(token, salt)
	plaintext := "This is a benchmark message for decryption testing."
	encrypted, _ := userCrypto.Encrypt(plaintext)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		userCrypto.Decrypt(encrypted)
	}
}

func BenchmarkSessionCryptoEncrypt(b *testing.B) {
	keyPair1, _ := crypto.GenerateDHKeyPair()
	keyPair2, _ := crypto.GenerateDHKeyPair()
	sharedSecret, _ := crypto.ComputeSharedSecret(keyPair1.PrivateKey, keyPair2.PublicKey)
	salt, _ := crypto.GenerateSalt()
	sessionKeys, _ := crypto.DeriveSessionKeys(sharedSecret, "test-session", salt)
	sessionCrypto := crypto.NewSessionCrypto(sessionKeys)
	plaintext := "This is a benchmark message for session encryption testing."

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		sessionCrypto.Encrypt(plaintext)
	}
}

func BenchmarkSessionCryptoDecrypt(b *testing.B) {
	keyPair1, _ := crypto.GenerateDHKeyPair()
	keyPair2, _ := crypto.GenerateDHKeyPair()
	sharedSecret, _ := crypto.ComputeSharedSecret(keyPair1.PrivateKey, keyPair2.PublicKey)
	salt, _ := crypto.GenerateSalt()
	sessionKeys, _ := crypto.DeriveSessionKeys(sharedSecret, "test-session", salt)
	sessionCrypto := crypto.NewSessionCrypto(sessionKeys)
	plaintext := "This is a benchmark message for session decryption testing."
	encrypted, _ := sessionCrypto.Encrypt(plaintext)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		sessionCrypto.Decrypt(encrypted)
	}
}

func BenchmarkComputeSharedSecret(b *testing.B) {
	keyPair1, _ := crypto.GenerateDHKeyPair()
	keyPair2, _ := crypto.GenerateDHKeyPair()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		crypto.ComputeSharedSecret(keyPair1.PrivateKey, keyPair2.PublicKey)
	}
}

func BenchmarkDeriveSessionKeys(b *testing.B) {
	keyPair1, _ := crypto.GenerateDHKeyPair()
	keyPair2, _ := crypto.GenerateDHKeyPair()
	sharedSecret, _ := crypto.ComputeSharedSecret(keyPair1.PrivateKey, keyPair2.PublicKey)
	salt, _ := crypto.GenerateSalt()
	sessionID := "benchmark-session"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		crypto.DeriveSessionKeys(sharedSecret, sessionID, salt)
	}
}
