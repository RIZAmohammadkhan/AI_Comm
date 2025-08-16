package test

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"aimessage/internal/db"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewDatabase(t *testing.T) {
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "test.db")

	database, err := db.NewDatabase(dbPath)
	require.NoError(t, err)
	assert.NotNil(t, database)

	defer database.Close()

	// Verify database directory was created
	assert.DirExists(t, dbPath)
}

func TestNewDatabaseInvalidPath(t *testing.T) {
	// Try to create database in a non-existent parent directory with restricted permissions
	invalidPath := "/nonexistent/invalid/path/test.db"
	if os.Getenv("OS") == "Windows_NT" {
		invalidPath = "Z:\\nonexistent\\invalid\\path\\test.db"
	}

	_, err := db.NewDatabase(invalidPath)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to open database")
}

func TestCreateUser(t *testing.T) {
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "test.db")

	database, err := db.NewDatabase(dbPath)
	require.NoError(t, err)
	defer database.Close()

	salt := []byte("test-salt-12345678")
	user := &db.User{
		Username: "testuser",
		Token:    "test-token-12345",
		Salt:     salt,
	}

	err = database.CreateUser(user)
	assert.NoError(t, err)

	// Verify timestamps were set
	assert.False(t, user.CreatedAt.IsZero())
	assert.False(t, user.LastSeen.IsZero())
}

func TestCreateUserDuplicate(t *testing.T) {
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "test.db")

	database, err := db.NewDatabase(dbPath)
	require.NoError(t, err)
	defer database.Close()

	salt := []byte("test-salt-12345678")
	user := &db.User{
		Username: "testuser",
		Token:    "test-token-12345",
		Salt:     salt,
	}

	err = database.CreateUser(user)
	require.NoError(t, err)

	// Try to create the same user again
	err = database.CreateUser(user)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "already exists")
}

func TestGetUser(t *testing.T) {
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "test.db")

	database, err := db.NewDatabase(dbPath)
	require.NoError(t, err)
	defer database.Close()

	salt := []byte("test-salt-12345678")
	originalUser := &db.User{
		Username: "testuser",
		Token:    "test-token-12345",
		Salt:     salt,
	}

	err = database.CreateUser(originalUser)
	require.NoError(t, err)

	// Retrieve the user
	retrievedUser, err := database.GetUser("testuser")
	require.NoError(t, err)
	assert.NotNil(t, retrievedUser)
	assert.Equal(t, originalUser.Username, retrievedUser.Username)
	assert.Equal(t, originalUser.Token, retrievedUser.Token)
	assert.Equal(t, originalUser.Salt, retrievedUser.Salt)
	assert.False(t, retrievedUser.CreatedAt.IsZero())
	assert.False(t, retrievedUser.LastSeen.IsZero())
}

func TestGetUserNotFound(t *testing.T) {
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "test.db")

	database, err := db.NewDatabase(dbPath)
	require.NoError(t, err)
	defer database.Close()

	_, err = database.GetUser("nonexistent")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

func TestUpdateLastSeen(t *testing.T) {
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "test.db")

	database, err := db.NewDatabase(dbPath)
	require.NoError(t, err)
	defer database.Close()

	salt := []byte("test-salt-12345678")
	user := &db.User{
		Username: "testuser",
		Token:    "test-token-12345",
		Salt:     salt,
	}

	err = database.CreateUser(user)
	require.NoError(t, err)

	originalLastSeen := user.LastSeen

	// Wait a bit to ensure time difference
	time.Sleep(10 * time.Millisecond)

	err = database.UpdateLastSeen("testuser")
	assert.NoError(t, err)

	// Verify last seen was updated
	updatedUser, err := database.GetUser("testuser")
	require.NoError(t, err)
	assert.True(t, updatedUser.LastSeen.After(originalLastSeen))
}

func TestUpdateLastSeenNonExistent(t *testing.T) {
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "test.db")

	database, err := db.NewDatabase(dbPath)
	require.NoError(t, err)
	defer database.Close()

	err = database.UpdateLastSeen("nonexistent")
	assert.Error(t, err)
}

func TestListUsers(t *testing.T) {
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "test.db")

	database, err := db.NewDatabase(dbPath)
	require.NoError(t, err)
	defer database.Close()

	// Create multiple users
	users := []*db.User{
		{Username: "user1", Token: "token1", Salt: []byte("salt1-1234567890")},
		{Username: "user2", Token: "token2", Salt: []byte("salt2-1234567890")},
		{Username: "user3", Token: "token3", Salt: []byte("salt3-1234567890")},
	}

	for _, user := range users {
		err = database.CreateUser(user)
		require.NoError(t, err)
	}

	// List all users
	allUsers, err := database.ListUsers()
	require.NoError(t, err)
	assert.Len(t, allUsers, 3)

	// Verify all usernames are present
	usernames := make(map[string]bool)
	for _, user := range allUsers {
		usernames[user.Username] = true
	}
	assert.True(t, usernames["user1"])
	assert.True(t, usernames["user2"])
	assert.True(t, usernames["user3"])
}

func TestGetActiveUsers(t *testing.T) {
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "test.db")

	database, err := db.NewDatabase(dbPath)
	require.NoError(t, err)
	defer database.Close()

	// Create users with different last seen times
	oldUser := &db.User{
		Username: "olduser",
		Token:    "token1",
		Salt:     []byte("salt1-1234567890"),
	}
	err = database.CreateUser(oldUser)
	require.NoError(t, err)

	recentUser := &db.User{
		Username: "recentuser",
		Token:    "token2",
		Salt:     []byte("salt2-1234567890"),
	}
	err = database.CreateUser(recentUser)
	require.NoError(t, err)

	// Update last seen for recent user
	time.Sleep(10 * time.Millisecond)
	err = database.UpdateLastSeen("recentuser")
	require.NoError(t, err)

	// Get active users within last second
	activeUsers, err := database.GetActiveUsers(1 * time.Second)
	require.NoError(t, err)

	// Should include both users since they were just created/updated
	assert.Len(t, activeUsers, 2)

	// Get active users within last millisecond (should be empty or just recent)
	veryRecentUsers, err := database.GetActiveUsers(1 * time.Millisecond)
	require.NoError(t, err)
	assert.True(t, len(veryRecentUsers) <= 2)
}

func TestStoreOfflineMessage(t *testing.T) {
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "test.db")

	database, err := db.NewDatabase(dbPath)
	require.NoError(t, err)
	defer database.Close()

	msg := &db.OfflineMessage{
		MessageID: "msg-123",
		From:      "sender",
		To:        "recipient",
		Message:   "encrypted-message-content",
		SessionID: "session-456",
		Timestamp: time.Now().Unix(),
		Delivered: false,
	}

	err = database.StoreOfflineMessage(msg)
	assert.NoError(t, err)
}

func TestGetOfflineMessages(t *testing.T) {
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "test.db")

	database, err := db.NewDatabase(dbPath)
	require.NoError(t, err)
	defer database.Close()

	// Store multiple messages for the same recipient
	messages := []*db.OfflineMessage{
		{
			MessageID: "msg-1",
			From:      "sender1",
			To:        "recipient",
			Message:   "message1",
			Timestamp: time.Now().Unix(),
			Delivered: false,
		},
		{
			MessageID: "msg-2",
			From:      "sender2",
			To:        "recipient",
			Message:   "message2",
			Timestamp: time.Now().Unix(),
			Delivered: false,
		},
		{
			MessageID: "msg-3",
			From:      "sender1",
			To:        "other",
			Message:   "message3",
			Timestamp: time.Now().Unix(),
			Delivered: false,
		},
	}

	for _, msg := range messages {
		err = database.StoreOfflineMessage(msg)
		require.NoError(t, err)
	}

	// Get messages for specific recipient
	recipientMessages, err := database.GetOfflineMessages("recipient")
	require.NoError(t, err)
	assert.Len(t, recipientMessages, 2)

	// Verify message content
	messageIDs := make(map[string]bool)
	for _, msg := range recipientMessages {
		messageIDs[msg.MessageID] = true
		assert.Equal(t, "recipient", msg.To)
		assert.False(t, msg.Delivered)
	}
	assert.True(t, messageIDs["msg-1"])
	assert.True(t, messageIDs["msg-2"])
}

func TestMarkMessageDelivered(t *testing.T) {
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "test.db")

	database, err := db.NewDatabase(dbPath)
	require.NoError(t, err)
	defer database.Close()

	msg := &db.OfflineMessage{
		MessageID: "msg-123",
		From:      "sender",
		To:        "recipient",
		Message:   "encrypted-message-content",
		Timestamp: time.Now().Unix(),
		Delivered: false,
	}

	err = database.StoreOfflineMessage(msg)
	require.NoError(t, err)

	// Mark as delivered
	err = database.MarkMessageDelivered("recipient", "msg-123")
	assert.NoError(t, err)

	// Verify it's no longer returned as undelivered
	messages, err := database.GetOfflineMessages("recipient")
	require.NoError(t, err)
	assert.Len(t, messages, 0)
}

func TestStoreAndGetSession(t *testing.T) {
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "test.db")

	database, err := db.NewDatabase(dbPath)
	require.NoError(t, err)
	defer database.Close()

	session := &db.Session{
		SessionID:    "session-123",
		Participants: []string{"user1", "user2"},
		CreatedAt:    time.Now(),
		LastUsed:     time.Now(),
		ExpiresAt:    time.Now().Add(time.Hour),
	}

	err = database.StoreSession(session)
	require.NoError(t, err)

	// Retrieve the session
	retrievedSession, err := database.GetSession("session-123")
	require.NoError(t, err)
	assert.NotNil(t, retrievedSession)
	assert.Equal(t, session.SessionID, retrievedSession.SessionID)
	assert.Equal(t, session.Participants, retrievedSession.Participants)
}

func TestGetSessionNotFound(t *testing.T) {
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "test.db")

	database, err := db.NewDatabase(dbPath)
	require.NoError(t, err)
	defer database.Close()

	_, err = database.GetSession("nonexistent")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

func TestUpdateSessionLastUsed(t *testing.T) {
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "test.db")

	database, err := db.NewDatabase(dbPath)
	require.NoError(t, err)
	defer database.Close()

	session := &db.Session{
		SessionID:    "session-123",
		Participants: []string{"user1", "user2"},
		CreatedAt:    time.Now(),
		LastUsed:     time.Now(),
		ExpiresAt:    time.Now().Add(time.Hour),
	}

	err = database.StoreSession(session)
	require.NoError(t, err)

	originalLastUsed := session.LastUsed

	// Wait a bit to ensure time difference
	time.Sleep(10 * time.Millisecond)

	err = database.UpdateSessionLastUsed("session-123")
	assert.NoError(t, err)

	// Verify last used was updated
	updatedSession, err := database.GetSession("session-123")
	require.NoError(t, err)
	assert.True(t, updatedSession.LastUsed.After(originalLastUsed))
}

func TestStoreAndGetAuthChallenge(t *testing.T) {
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "test.db")

	database, err := db.NewDatabase(dbPath)
	require.NoError(t, err)
	defer database.Close()

	challenge := &db.AuthChallenge{
		Username:  "testuser",
		Challenge: "challenge-string-123",
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(time.Minute),
	}

	err = database.StoreAuthChallenge(challenge)
	require.NoError(t, err)

	// Retrieve the challenge
	retrievedChallenge, err := database.GetAuthChallenge("testuser")
	require.NoError(t, err)
	assert.NotNil(t, retrievedChallenge)
	assert.Equal(t, challenge.Username, retrievedChallenge.Username)
	assert.Equal(t, challenge.Challenge, retrievedChallenge.Challenge)
}

func TestDeleteAuthChallenge(t *testing.T) {
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "test.db")

	database, err := db.NewDatabase(dbPath)
	require.NoError(t, err)
	defer database.Close()

	challenge := &db.AuthChallenge{
		Username:  "testuser",
		Challenge: "challenge-string-123",
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(time.Minute),
	}

	err = database.StoreAuthChallenge(challenge)
	require.NoError(t, err)

	// Delete the challenge
	err = database.DeleteAuthChallenge("testuser")
	assert.NoError(t, err)

	// Verify it's gone
	_, err = database.GetAuthChallenge("testuser")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

func TestCleanupExpiredSessions(t *testing.T) {
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "test.db")

	database, err := db.NewDatabase(dbPath)
	require.NoError(t, err)
	defer database.Close()

	now := time.Now()

	// Create expired and valid sessions
	expiredSession := &db.Session{
		SessionID:    "expired-session",
		Participants: []string{"user1", "user2"},
		CreatedAt:    now.Add(-time.Hour),
		LastUsed:     now.Add(-time.Hour),
		ExpiresAt:    now.Add(-time.Minute), // Expired
	}

	validSession := &db.Session{
		SessionID:    "valid-session",
		Participants: []string{"user3", "user4"},
		CreatedAt:    now,
		LastUsed:     now,
		ExpiresAt:    now.Add(time.Hour), // Valid
	}

	err = database.StoreSession(expiredSession)
	require.NoError(t, err)

	err = database.StoreSession(validSession)
	require.NoError(t, err)

	// Clean up expired sessions
	err = database.CleanupExpiredSessions()
	assert.NoError(t, err)

	// Verify expired session is gone
	_, err = database.GetSession("expired-session")
	assert.Error(t, err)

	// Verify valid session remains
	_, err = database.GetSession("valid-session")
	assert.NoError(t, err)
}

func TestCleanupExpiredChallenges(t *testing.T) {
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "test.db")

	database, err := db.NewDatabase(dbPath)
	require.NoError(t, err)
	defer database.Close()

	now := time.Now()

	// Create expired and valid challenges
	expiredChallenge := &db.AuthChallenge{
		Username:  "expired-user",
		Challenge: "expired-challenge",
		CreatedAt: now.Add(-time.Hour),
		ExpiresAt: now.Add(-time.Minute), // Expired
	}

	validChallenge := &db.AuthChallenge{
		Username:  "valid-user",
		Challenge: "valid-challenge",
		CreatedAt: now,
		ExpiresAt: now.Add(time.Minute), // Valid
	}

	err = database.StoreAuthChallenge(expiredChallenge)
	require.NoError(t, err)

	err = database.StoreAuthChallenge(validChallenge)
	require.NoError(t, err)

	// Clean up expired challenges
	err = database.CleanupExpiredChallenges()
	assert.NoError(t, err)

	// Verify expired challenge is gone
	_, err = database.GetAuthChallenge("expired-user")
	assert.Error(t, err)

	// Verify valid challenge remains
	_, err = database.GetAuthChallenge("valid-user")
	assert.NoError(t, err)
}

func TestRunGarbageCollection(t *testing.T) {
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "test.db")

	database, err := db.NewDatabase(dbPath)
	require.NoError(t, err)
	defer database.Close()

	// GC should not error even on empty database
	err = database.RunGarbageCollection()
	assert.NoError(t, err)
}

func TestDatabaseClose(t *testing.T) {
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "test.db")

	database, err := db.NewDatabase(dbPath)
	require.NoError(t, err)

	err = database.Close()
	assert.NoError(t, err)

	// Operations after close should fail
	user := &db.User{
		Username: "testuser",
		Token:    "token",
		Salt:     []byte("salt-1234567890"),
	}

	err = database.CreateUser(user)
	assert.Error(t, err)
}

// Benchmark tests
func BenchmarkCreateUser(b *testing.B) {
	tempDir := b.TempDir()
	dbPath := filepath.Join(tempDir, "bench.db")

	database, err := db.NewDatabase(dbPath)
	require.NoError(b, err)
	defer database.Close()

	salt := []byte("test-salt-12345678")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		user := &db.User{
			Username: "testuser" + string(rune(i)),
			Token:    "test-token-12345",
			Salt:     salt,
		}
		database.CreateUser(user)
	}
}

func BenchmarkGetUser(b *testing.B) {
	tempDir := b.TempDir()
	dbPath := filepath.Join(tempDir, "bench.db")

	database, err := db.NewDatabase(dbPath)
	require.NoError(b, err)
	defer database.Close()

	// Create a user first
	salt := []byte("test-salt-12345678")
	user := &db.User{
		Username: "benchuser",
		Token:    "test-token-12345",
		Salt:     salt,
	}
	database.CreateUser(user)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		database.GetUser("benchuser")
	}
}

func BenchmarkStoreOfflineMessage(b *testing.B) {
	tempDir := b.TempDir()
	dbPath := filepath.Join(tempDir, "bench.db")

	database, err := db.NewDatabase(dbPath)
	require.NoError(b, err)
	defer database.Close()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		msg := &db.OfflineMessage{
			MessageID: "msg-" + string(rune(i)),
			From:      "sender",
			To:        "recipient",
			Message:   "encrypted-message-content",
			Timestamp: time.Now().Unix(),
			Delivered: false,
		}
		database.StoreOfflineMessage(msg)
	}
}
