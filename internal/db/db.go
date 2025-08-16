package db

import (
	"bytes"
	"encoding/json"
	"fmt"
	"time"

	"github.com/dgraph-io/badger/v4"
)

// User represents a registered user
type User struct {
	Username  string    `json:"username"`
	Token     string    `json:"token"`
	Salt      []byte    `json:"salt"`
	CreatedAt time.Time `json:"created_at"`
	LastSeen  time.Time `json:"last_seen"`
}

// OfflineMessage represents a message stored for offline delivery
type OfflineMessage struct {
	MessageID string `json:"message_id"`
	From      string `json:"from"`
	To        string `json:"to"`
	Message   string `json:"message"` // Encrypted message
	SessionID string `json:"session_id,omitempty"`
	Timestamp int64  `json:"timestamp"`
	Delivered bool   `json:"delivered"`
}

// Session represents an active cryptographic session between users
type Session struct {
	SessionID    string    `json:"session_id"`
	Participants []string  `json:"participants"` // [user1, user2]
	CreatedAt    time.Time `json:"created_at"`
	LastUsed     time.Time `json:"last_used"`
	ExpiresAt    time.Time `json:"expires_at"`
}

// AuthChallenge represents an authentication challenge
type AuthChallenge struct {
	Username  string    `json:"username"`
	Challenge string    `json:"challenge"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
}

// Database wraps BadgerDB for user management
type Database struct {
	db         *badger.DB
	jsonBuffer []byte // Reusable buffer for JSON operations
}

// NewDatabase creates a new database instance
func NewDatabase(path string) (*Database, error) {
	opts := badger.DefaultOptions(path)
	opts.Logger = nil // Disable logging for performance

	// Memory efficiency optimizations
	opts.NumMemtables = 2            // Minimum required (reduced from default)
	opts.NumLevelZeroTables = 2      // Reduce L0 tables (reduced from default 5)
	opts.NumLevelZeroTablesStall = 3 // Reduce stall threshold (reduced from default 15)
	opts.NumCompactors = 2           // Minimum required compactors (reduced from default 4)
	opts.LevelSizeMultiplier = 8     // Reduce level size multiplier (reduced from default 10)
	opts.ValueLogFileSize = 16 << 20 // 16MB value log files (smaller than default 1GB)
	opts.MemTableSize = 8 << 20      // 8MB memtable size (smaller than default 64MB)
	opts.BlockCacheSize = 8 << 20    // 8MB block cache (smaller than default 256MB)
	opts.IndexCacheSize = 8 << 20    // 8MB index cache (smaller than default 0)
	opts.CompactL0OnClose = true     // Compact on close to reduce startup time
	opts.DetectConflicts = false     // Disable conflict detection for performance

	// Reduce disk usage and temporary files
	opts.SyncWrites = false    // Async writes for better performance
	opts.NumVersionsToKeep = 1 // Keep only 1 version to save space

	db, err := badger.Open(opts)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	return &Database{
		db:         db,
		jsonBuffer: make([]byte, 0, 1024), // Pre-allocate 1KB buffer
	}, nil
}

// Close closes the database
func (d *Database) Close() error {
	// Force garbage collection on database before closing
	return d.db.Close()
}

// RunGarbageCollection manually triggers BadgerDB garbage collection
func (d *Database) RunGarbageCollection() error {
	// Run value log garbage collection to reclaim space
	for {
		err := d.db.RunValueLogGC(0.5) // Reclaim 50% of space
		if err != nil {
			break // No more cleanup needed
		}
	}
	return nil
}

// marshalJSON efficiently marshals data using reusable buffer
func (d *Database) marshalJSON(v interface{}) ([]byte, error) {
	d.jsonBuffer = d.jsonBuffer[:0] // Reset buffer

	// Try to marshal into our buffer first
	buf := bytes.NewBuffer(d.jsonBuffer)
	encoder := json.NewEncoder(buf)
	err := encoder.Encode(v)
	if err != nil {
		return nil, err
	}

	data := buf.Bytes()
	// Remove trailing newline that Encoder adds
	if len(data) > 0 && data[len(data)-1] == '\n' {
		data = data[:len(data)-1]
	}

	// Update our buffer for reuse if it's reasonable size
	if len(data) <= 4096 {
		d.jsonBuffer = data[:0:cap(data)]
	}

	return data, nil
}

// CreateUser creates a new user in the database
func (d *Database) CreateUser(user *User) error {
	user.CreatedAt = time.Now()
	user.LastSeen = time.Now()

	return d.db.Update(func(txn *badger.Txn) error {
		// Check if user already exists
		key := []byte("user:" + user.Username)
		_, err := txn.Get(key)
		if err == nil {
			return fmt.Errorf("user %s already exists", user.Username)
		}
		if err != badger.ErrKeyNotFound {
			return fmt.Errorf("failed to check if user exists: %w", err)
		}

		// Store user data using efficient marshaling
		userData, err := d.marshalJSON(user)
		if err != nil {
			return fmt.Errorf("failed to marshal user data: %w", err)
		}

		return txn.Set(key, userData)
	})
}

// GetUser retrieves a user by username
func (d *Database) GetUser(username string) (*User, error) {
	var user User

	err := d.db.View(func(txn *badger.Txn) error {
		key := []byte("user:" + username)
		item, err := txn.Get(key)
		if err != nil {
			return fmt.Errorf("failed to get user item: %w", err)
		}

		return item.Value(func(val []byte) error {
			if err := json.Unmarshal(val, &user); err != nil {
				return fmt.Errorf("failed to unmarshal user data: %w", err)
			}
			return nil
		})
	})

	if err == badger.ErrKeyNotFound {
		return nil, fmt.Errorf("user %s not found", username)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve user %s: %w", username, err)
	}

	return &user, nil
}

// UpdateLastSeen updates the last seen timestamp for a user
func (d *Database) UpdateLastSeen(username string) error {
	return d.db.Update(func(txn *badger.Txn) error {
		key := []byte("user:" + username)
		item, err := txn.Get(key)
		if err != nil {
			return err
		}

		var user User
		err = item.Value(func(val []byte) error {
			return json.Unmarshal(val, &user)
		})
		if err != nil {
			return err
		}

		user.LastSeen = time.Now()
		userData, err := d.marshalJSON(&user)
		if err != nil {
			return err
		}

		return txn.Set(key, userData)
	})
}

// ListUsers returns all users (for debugging/admin purposes)
func (d *Database) ListUsers() ([]*User, error) {
	var users []*User

	err := d.db.View(func(txn *badger.Txn) error {
		opts := badger.DefaultIteratorOptions
		opts.PrefetchSize = 5       // Reduce prefetch size for memory efficiency
		opts.PrefetchValues = false // Don't prefetch values, load on demand
		it := txn.NewIterator(opts)
		defer it.Close()

		prefix := []byte("user:")
		for it.Seek(prefix); it.ValidForPrefix(prefix); it.Next() {
			item := it.Item()

			err := item.Value(func(val []byte) error {
				var user User
				err := json.Unmarshal(val, &user)
				if err != nil {
					return err
				}
				users = append(users, &user)
				return nil
			})
			if err != nil {
				return err
			}
		}
		return nil
	})

	return users, err
}

// GetActiveUsers returns users active within the specified duration
func (d *Database) GetActiveUsers(within time.Duration) ([]*User, error) {
	cutoff := time.Now().Add(-within)
	var activeUsers []*User

	err := d.db.View(func(txn *badger.Txn) error {
		opts := badger.DefaultIteratorOptions
		opts.PrefetchSize = 5       // Reduce prefetch size for memory efficiency
		opts.PrefetchValues = false // Don't prefetch values, load on demand
		it := txn.NewIterator(opts)
		defer it.Close()

		prefix := []byte("user:")
		for it.Seek(prefix); it.ValidForPrefix(prefix); it.Next() {
			item := it.Item()

			err := item.Value(func(val []byte) error {
				var user User
				err := json.Unmarshal(val, &user)
				if err != nil {
					return err
				}

				if user.LastSeen.After(cutoff) {
					activeUsers = append(activeUsers, &user)
				}
				return nil
			})
			if err != nil {
				return err
			}
		}
		return nil
	})

	return activeUsers, err
}

// StoreOfflineMessage stores a message for offline delivery
func (d *Database) StoreOfflineMessage(msg *OfflineMessage) error {
	return d.db.Update(func(txn *badger.Txn) error {
		key := []byte(fmt.Sprintf("offline_msg:%s:%s", msg.To, msg.MessageID))
		msgData, err := json.Marshal(msg)
		if err != nil {
			return err
		}
		return txn.Set(key, msgData)
	})
}

// GetOfflineMessages retrieves all undelivered messages for a user
func (d *Database) GetOfflineMessages(username string) ([]*OfflineMessage, error) {
	var messages []*OfflineMessage

	err := d.db.View(func(txn *badger.Txn) error {
		opts := badger.DefaultIteratorOptions
		opts.PrefetchSize = 10
		it := txn.NewIterator(opts)
		defer it.Close()

		prefix := []byte(fmt.Sprintf("offline_msg:%s:", username))
		for it.Seek(prefix); it.ValidForPrefix(prefix); it.Next() {
			item := it.Item()

			err := item.Value(func(val []byte) error {
				var msg OfflineMessage
				err := json.Unmarshal(val, &msg)
				if err != nil {
					return err
				}
				if !msg.Delivered {
					messages = append(messages, &msg)
				}
				return nil
			})
			if err != nil {
				return err
			}
		}
		return nil
	})

	return messages, err
}

// MarkMessageDelivered marks an offline message as delivered
func (d *Database) MarkMessageDelivered(username, messageID string) error {
	return d.db.Update(func(txn *badger.Txn) error {
		key := []byte(fmt.Sprintf("offline_msg:%s:%s", username, messageID))
		item, err := txn.Get(key)
		if err != nil {
			return err
		}

		var msg OfflineMessage
		err = item.Value(func(val []byte) error {
			return json.Unmarshal(val, &msg)
		})
		if err != nil {
			return err
		}

		msg.Delivered = true
		msgData, err := json.Marshal(&msg)
		if err != nil {
			return err
		}

		return txn.Set(key, msgData)
	})
}

// StoreSession stores a cryptographic session
func (d *Database) StoreSession(session *Session) error {
	return d.db.Update(func(txn *badger.Txn) error {
		key := []byte("session:" + session.SessionID)
		sessionData, err := json.Marshal(session)
		if err != nil {
			return err
		}
		return txn.Set(key, sessionData)
	})
}

// GetSession retrieves a session by ID
func (d *Database) GetSession(sessionID string) (*Session, error) {
	var session Session

	err := d.db.View(func(txn *badger.Txn) error {
		key := []byte("session:" + sessionID)
		item, err := txn.Get(key)
		if err != nil {
			return err
		}

		return item.Value(func(val []byte) error {
			return json.Unmarshal(val, &session)
		})
	})

	if err == badger.ErrKeyNotFound {
		return nil, fmt.Errorf("session %s not found", sessionID)
	}

	return &session, err
}

// UpdateSessionLastUsed updates the last used timestamp for a session
func (d *Database) UpdateSessionLastUsed(sessionID string) error {
	return d.db.Update(func(txn *badger.Txn) error {
		key := []byte("session:" + sessionID)
		item, err := txn.Get(key)
		if err != nil {
			return err
		}

		var session Session
		err = item.Value(func(val []byte) error {
			return json.Unmarshal(val, &session)
		})
		if err != nil {
			return err
		}

		session.LastUsed = time.Now()
		sessionData, err := json.Marshal(&session)
		if err != nil {
			return err
		}

		return txn.Set(key, sessionData)
	})
}

// StoreAuthChallenge stores an authentication challenge
func (d *Database) StoreAuthChallenge(challenge *AuthChallenge) error {
	return d.db.Update(func(txn *badger.Txn) error {
		key := []byte("challenge:" + challenge.Username)
		challengeData, err := json.Marshal(challenge)
		if err != nil {
			return err
		}
		return txn.Set(key, challengeData)
	})
}

// GetAuthChallenge retrieves an authentication challenge
func (d *Database) GetAuthChallenge(username string) (*AuthChallenge, error) {
	var challenge AuthChallenge

	err := d.db.View(func(txn *badger.Txn) error {
		key := []byte("challenge:" + username)
		item, err := txn.Get(key)
		if err != nil {
			return err
		}

		return item.Value(func(val []byte) error {
			return json.Unmarshal(val, &challenge)
		})
	})

	if err == badger.ErrKeyNotFound {
		return nil, fmt.Errorf("challenge for %s not found", username)
	}

	return &challenge, err
}

// DeleteAuthChallenge removes an authentication challenge
func (d *Database) DeleteAuthChallenge(username string) error {
	return d.db.Update(func(txn *badger.Txn) error {
		key := []byte("challenge:" + username)
		return txn.Delete(key)
	})
}

// CleanupExpiredSessions removes expired sessions
func (d *Database) CleanupExpiredSessions() error {
	now := time.Now()

	return d.db.Update(func(txn *badger.Txn) error {
		opts := badger.DefaultIteratorOptions
		opts.PrefetchSize = 5       // Reduce prefetch for memory efficiency
		opts.PrefetchValues = false // Don't prefetch values, load on demand
		it := txn.NewIterator(opts)
		defer it.Close()

		var keysToDelete [][]byte // Batch deletes for efficiency
		prefix := []byte("session:")
		for it.Seek(prefix); it.ValidForPrefix(prefix); it.Next() {
			item := it.Item()

			err := item.Value(func(val []byte) error {
				var session Session
				err := json.Unmarshal(val, &session)
				if err != nil {
					return err
				}

				if session.ExpiresAt.Before(now) {
					key := make([]byte, len(item.Key()))
					copy(key, item.Key())
					keysToDelete = append(keysToDelete, key)
				}
				return nil
			})
			if err != nil {
				return err
			}
		}

		// Batch delete expired sessions
		for _, key := range keysToDelete {
			if err := txn.Delete(key); err != nil {
				return err
			}
		}
		return nil
	})
}

// CleanupExpiredChallenges removes expired authentication challenges
func (d *Database) CleanupExpiredChallenges() error {
	now := time.Now()

	return d.db.Update(func(txn *badger.Txn) error {
		opts := badger.DefaultIteratorOptions
		opts.PrefetchSize = 5       // Reduce prefetch for memory efficiency
		opts.PrefetchValues = false // Don't prefetch values, load on demand
		it := txn.NewIterator(opts)
		defer it.Close()

		var keysToDelete [][]byte // Batch deletes for efficiency
		prefix := []byte("challenge:")
		for it.Seek(prefix); it.ValidForPrefix(prefix); it.Next() {
			item := it.Item()

			err := item.Value(func(val []byte) error {
				var challenge AuthChallenge
				err := json.Unmarshal(val, &challenge)
				if err != nil {
					return err
				}

				if challenge.ExpiresAt.Before(now) {
					key := make([]byte, len(item.Key()))
					copy(key, item.Key())
					keysToDelete = append(keysToDelete, key)
				}
				return nil
			})
			if err != nil {
				return err
			}
		}

		// Batch delete expired challenges
		for _, key := range keysToDelete {
			if err := txn.Delete(key); err != nil {
				return err
			}
		}
		return nil
	})
}
