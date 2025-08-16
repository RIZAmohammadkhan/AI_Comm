package main

import (
	"runtime"
	"testing"
	"time"

	"aimessage/internal/db"
	"aimessage/internal/server"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestMemoryEfficiency tests the memory optimization improvements
func TestMemoryEfficiency(t *testing.T) {
	// Use a temporary directory
	tempDir := t.TempDir()

	// Create database with optimized settings
	database, err := db.NewDatabase(tempDir)
	require.NoError(t, err)
	defer database.Close()

	// Measure initial memory
	var m1 runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&m1)

	// Create many users to test memory efficiency
	for i := 0; i < 1000; i++ {
		user := &db.User{
			Username: "test_user_" + string(rune(i)),
			Token:    "token_" + string(rune(i)),
			Salt:     []byte("salt"),
		}
		err := database.CreateUser(user)
		require.NoError(t, err)
	}

	// Create many sessions
	for i := 0; i < 500; i++ {
		session := &db.Session{
			SessionID:    "session_" + string(rune(i)),
			Participants: []string{"user1", "user2"},
			ExpiresAt:    time.Now().Add(1 * time.Hour),
		}
		err := database.StoreSession(session)
		require.NoError(t, err)
	}

	// Measure memory after operations
	var m2 runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&m2)

	// Run garbage collection
	err = database.RunGarbageCollection()
	require.NoError(t, err)

	// Measure memory after GC
	var m3 runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&m3)

	// Test that memory usage is reasonable
	var memoryIncrease, memoryAfterGC int64

	if m2.Alloc >= m1.Alloc {
		memoryIncrease = int64(m2.Alloc - m1.Alloc)
	} else {
		memoryIncrease = 0 // Memory decreased
	}

	if m3.Alloc >= m1.Alloc {
		memoryAfterGC = int64(m3.Alloc - m1.Alloc)
	} else {
		memoryAfterGC = 0 // Memory decreased after GC
	}

	t.Logf("Initial memory: %d bytes", m1.Alloc)
	t.Logf("Memory after operations: %d bytes", m2.Alloc)
	t.Logf("Memory after GC: %d bytes", m3.Alloc)
	t.Logf("Memory increase: %d bytes", memoryIncrease)
	t.Logf("Memory after GC: %d bytes", memoryAfterGC)

	// Assert that GC helped reduce memory (not always guaranteed but generally true)
	assert.LessOrEqual(t, memoryAfterGC, memoryIncrease, "Garbage collection should help reduce memory usage")

	// Test cleanup functionality
	err = database.CleanupExpiredSessions()
	assert.NoError(t, err)

	err = database.CleanupExpiredChallenges()
	assert.NoError(t, err)
}

// TestOptimizedServerMemory tests server memory efficiency
func TestOptimizedServerMemory(t *testing.T) {
	tempDir := t.TempDir()

	// Measure initial memory
	var m1 runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&m1)

	// Create server
	srv, err := server.NewServer(tempDir)
	require.NoError(t, err)
	defer srv.Close()

	// Measure memory after server creation
	var m2 runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&m2)

	memoryIncrease := m2.Alloc - m1.Alloc

	t.Logf("Memory increase from server creation: %d bytes", memoryIncrease)

	// Assert that server creation doesn't use excessive memory
	// Arbitrary threshold - adjust based on your needs
	assert.Less(t, memoryIncrease, uint64(50*1024*1024), "Server should not use more than 50MB")
}

// BenchmarkDatabaseOperations benchmarks optimized database operations
func BenchmarkDatabaseOperations(b *testing.B) {
	tempDir := b.TempDir()
	database, err := db.NewDatabase(tempDir)
	require.NoError(b, err)
	defer database.Close()

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		user := &db.User{
			Username: "bench_user_" + string(rune(i)),
			Token:    "token_" + string(rune(i)),
			Salt:     []byte("salt"),
		}

		err := database.CreateUser(user)
		if err != nil {
			b.Fatal(err)
		}

		_, err = database.GetUser(user.Username)
		if err != nil {
			b.Fatal(err)
		}
	}
}
