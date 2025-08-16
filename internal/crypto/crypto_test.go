package crypto

import (
	"testing"
)

func TestGenerateSalt(t *testing.T) {
	salt1, err := GenerateSalt()
	if err != nil {
		t.Fatalf("GenerateSalt failed: %v", err)
	}

	salt2, err := GenerateSalt()
	if err != nil {
		t.Fatalf("GenerateSalt failed: %v", err)
	}

	if len(salt1) != saltLength {
		t.Errorf("Expected salt length %d, got %d", saltLength, len(salt1))
	}

	// Salts should be different
	if string(salt1) == string(salt2) {
		t.Error("Generated salts should be unique")
	}
}

func TestGenerateUserToken(t *testing.T) {
	token1, err := GenerateUserToken()
	if err != nil {
		t.Fatalf("GenerateUserToken failed: %v", err)
	}

	token2, err := GenerateUserToken()
	if err != nil {
		t.Fatalf("GenerateUserToken failed: %v", err)
	}

	if len(token1) == 0 {
		t.Error("Token should not be empty")
	}

	// Tokens should be different
	if token1 == token2 {
		t.Error("Generated tokens should be unique")
	}
}

func TestEncryptDecrypt(t *testing.T) {
	token := "test-token-12345"
	salt, err := GenerateSalt()
	if err != nil {
		t.Fatalf("GenerateSalt failed: %v", err)
	}

	crypto := NewUserCrypto(token, salt)

	plaintext := "Hello, AI Message!"

	// Encrypt
	encrypted, err := crypto.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}

	if encrypted == plaintext {
		t.Error("Encrypted text should be different from plaintext")
	}

	// Decrypt
	decrypted, err := crypto.Decrypt(encrypted)
	if err != nil {
		t.Fatalf("Decryption failed: %v", err)
	}

	if decrypted != plaintext {
		t.Errorf("Expected %q, got %q", plaintext, decrypted)
	}
}

func TestDecryptInvalidData(t *testing.T) {
	token := "test-token-12345"
	salt, _ := GenerateSalt()
	crypto := NewUserCrypto(token, salt)

	// Test invalid base64
	_, err := crypto.Decrypt("invalid-base64!")
	if err == nil {
		t.Error("Expected error for invalid base64")
	}

	// Test too short data
	_, err = crypto.Decrypt("YWJj") // "abc" in base64
	if err == nil {
		t.Error("Expected error for too short data")
	}
}
