package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"

	"golang.org/x/crypto/pbkdf2"
)

const (
	// Encryption parameters
	keyLength   = 32     // AES-256
	nonceLength = 12     // GCM nonce length
	saltLength  = 16     // Salt length for PBKDF2
	iterations  = 100000 // PBKDF2 iterations
)

// DHKeyPair represents a Diffie-Hellman key pair
type DHKeyPair struct {
	PrivateKey []byte `json:"private_key"`
	PublicKey  []byte `json:"public_key"`
}

// SessionKeys holds ephemeral keys for a conversation
type SessionKeys struct {
	SharedSecret []byte `json:"shared_secret"`
	EncryptKey   []byte `json:"encrypt_key"`
	SessionID    string `json:"session_id"`
}

// UserCrypto handles encryption/decryption for a specific user
type UserCrypto struct {
	key []byte
}

// NewUserCrypto creates a new crypto instance for a user with their token
func NewUserCrypto(userToken string, salt []byte) *UserCrypto {
	key := pbkdf2.Key([]byte(userToken), salt, iterations, keyLength, sha256.New)
	return &UserCrypto{key: key}
}

// GenerateSalt creates a random salt for a new user
func GenerateSalt() ([]byte, error) {
	salt := make([]byte, saltLength)
	_, err := rand.Read(salt)
	return salt, err
}

// GenerateDHKeyPair generates a new Diffie-Hellman key pair using P-256 curve
func GenerateDHKeyPair() (*DHKeyPair, error) {
	curve := elliptic.P256()
	privateKey, err := rand.Int(rand.Reader, curve.Params().N)
	if err != nil {
		return nil, fmt.Errorf("failed to generate private key: %w", err)
	}

	// Generate public key
	x, y := curve.ScalarBaseMult(privateKey.Bytes())
	publicKey := elliptic.Marshal(curve, x, y)

	return &DHKeyPair{
		PrivateKey: privateKey.Bytes(),
		PublicKey:  publicKey,
	}, nil
}

// ComputeSharedSecret computes the shared secret from our private key and their public key
func ComputeSharedSecret(ourPrivateKey []byte, theirPublicKey []byte) ([]byte, error) {
	curve := elliptic.P256()

	// Unmarshal their public key
	x, y := elliptic.Unmarshal(curve, theirPublicKey)
	if x == nil {
		return nil, errors.New("invalid public key")
	}

	// Convert our private key to big.Int
	privateKey := new(big.Int).SetBytes(ourPrivateKey)

	// Compute shared secret
	sharedX, _ := curve.ScalarMult(x, y, privateKey.Bytes())

	// Use SHA256 to derive a fixed-length key from the shared secret
	hash := sha256.Sum256(sharedX.Bytes())
	return hash[:], nil
}

// DeriveSessionKeys derives encryption keys from shared secret and session info
func DeriveSessionKeys(sharedSecret []byte, sessionID string, salt []byte) (*SessionKeys, error) {
	// Combine shared secret with session ID and salt for key derivation
	keyMaterial := append(sharedSecret, []byte(sessionID)...)
	keyMaterial = append(keyMaterial, salt...)

	// Derive encryption key using PBKDF2
	encryptKey := pbkdf2.Key(keyMaterial, salt, iterations, keyLength, sha256.New)

	return &SessionKeys{
		SharedSecret: sharedSecret,
		EncryptKey:   encryptKey,
		SessionID:    sessionID,
	}, nil
}

// SessionCrypto handles encryption/decryption with ephemeral session keys
type SessionCrypto struct {
	encryptKey []byte
}

// NewSessionCrypto creates a new session crypto instance
func NewSessionCrypto(sessionKeys *SessionKeys) *SessionCrypto {
	return &SessionCrypto{
		encryptKey: sessionKeys.EncryptKey,
	}
}

// Encrypt encrypts a message using the session key
func (sc *SessionCrypto) Encrypt(plaintext string) (string, error) {
	if len(sc.encryptKey) == 0 {
		return "", errors.New("session encryption key not initialized")
	}

	block, err := aes.NewCipher(sc.encryptKey)
	if err != nil {
		return "", fmt.Errorf("failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("failed to create GCM: %w", err)
	}

	nonce := make([]byte, nonceLength)
	_, err = rand.Read(nonce)
	if err != nil {
		return "", fmt.Errorf("failed to generate nonce: %w", err)
	}

	ciphertext := gcm.Seal(nonce, nonce, []byte(plaintext), nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// Decrypt decrypts a message using the session key
func (sc *SessionCrypto) Decrypt(encryptedData string) (string, error) {
	if len(sc.encryptKey) == 0 {
		return "", errors.New("session encryption key not initialized")
	}

	data, err := base64.StdEncoding.DecodeString(encryptedData)
	if err != nil {
		return "", fmt.Errorf("failed to decode base64: %w", err)
	}

	if len(data) < nonceLength {
		return "", errors.New("encrypted data too short")
	}

	block, err := aes.NewCipher(sc.encryptKey)
	if err != nil {
		return "", fmt.Errorf("failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("failed to create GCM: %w", err)
	}

	nonce := data[:nonceLength]
	ciphertext := data[nonceLength:]

	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", fmt.Errorf("failed to decrypt: %w", err)
	}

	return string(plaintext), nil
}

// GenerateUserToken creates a secure random token for a new user
func GenerateUserToken() (string, error) {
	tokenBytes := make([]byte, 32)
	_, err := rand.Read(tokenBytes)
	if err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(tokenBytes), nil
}

// Encrypt encrypts a message using AES-GCM
func (uc *UserCrypto) Encrypt(plaintext string) (string, error) {
	if len(uc.key) == 0 {
		return "", errors.New("encryption key not initialized")
	}

	block, err := aes.NewCipher(uc.key)
	if err != nil {
		return "", fmt.Errorf("failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("failed to create GCM: %w", err)
	}

	nonce := make([]byte, nonceLength)
	_, err = rand.Read(nonce)
	if err != nil {
		return "", fmt.Errorf("failed to generate nonce: %w", err)
	}

	ciphertext := gcm.Seal(nonce, nonce, []byte(plaintext), nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// Decrypt decrypts a message using AES-GCM
func (uc *UserCrypto) Decrypt(encryptedData string) (string, error) {
	if len(uc.key) == 0 {
		return "", errors.New("encryption key not initialized")
	}

	data, err := base64.StdEncoding.DecodeString(encryptedData)
	if err != nil {
		return "", fmt.Errorf("failed to decode base64: %w", err)
	}

	if len(data) < nonceLength {
		return "", errors.New("encrypted data too short")
	}

	block, err := aes.NewCipher(uc.key)
	if err != nil {
		return "", fmt.Errorf("failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("failed to create GCM: %w", err)
	}

	nonce := data[:nonceLength]
	ciphertext := data[nonceLength:]

	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", fmt.Errorf("failed to decrypt: %w", err)
	}

	return string(plaintext), nil
}
