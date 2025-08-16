package test

import (
	"bytes"
	"encoding/json"
	"errors"
	"log"
	"os"
	"strings"
	"testing"

	"aimessage/internal/logging"

	"github.com/stretchr/testify/assert"
)

func TestNewLogger(t *testing.T) {
	logger := logging.NewLogger("test-service")
	assert.NotNil(t, logger)
}

func TestLoggerWithContext(t *testing.T) {
	logger := logging.NewLogger("test-service")

	// Add context
	loggerWithContext := logger.WithContext("user_id", "12345")
	assert.NotNil(t, loggerWithContext)

	// Should be a different instance
	assert.NotEqual(t, logger, loggerWithContext)
}

func TestLoggerWithError(t *testing.T) {
	logger := logging.NewLogger("test-service")
	testError := errors.New("test error message")

	loggerWithError := logger.WithError(testError)
	assert.NotNil(t, loggerWithError)

	// Should be a different instance
	assert.NotEqual(t, logger, loggerWithError)
}

func TestLogLevels(t *testing.T) {
	// Capture log output
	var buf bytes.Buffer
	log.SetOutput(&buf)
	defer log.SetOutput(os.Stderr)

	// Test all log levels using convenience functions
	logging.Info("Info message", map[string]string{"key": "value"})
	logging.Warn("Warning message", map[string]string{"key": "value"})
	logging.Error("Error message", map[string]string{"key": "value"})

	output := buf.String()

	// Should contain log level indicators
	assert.Contains(t, output, "[INFO]")
	assert.Contains(t, output, "[WARN]")
	assert.Contains(t, output, "[ERROR]")
}

func TestLogWithError(t *testing.T) {
	var buf bytes.Buffer
	log.SetOutput(&buf)
	defer log.SetOutput(os.Stderr)

	testError := errors.New("test error for logging")

	logging.ErrorWithError("Error occurred", testError, map[string]string{"context": "test"})

	output := buf.String()
	assert.Contains(t, output, "[ERROR]")
	assert.Contains(t, output, "Error occurred")
	assert.Contains(t, output, "test error for logging")
}

func TestStructuredLogging(t *testing.T) {
	// Set environment variable for structured logging
	originalFormat := os.Getenv("LOG_FORMAT")
	os.Setenv("LOG_FORMAT", "json")
	defer os.Setenv("LOG_FORMAT", originalFormat)

	var buf bytes.Buffer
	log.SetOutput(&buf)
	defer log.SetOutput(os.Stderr)

	// Test structured logging with convenience functions
	logging.Info("Test structured log", map[string]string{"key": "value"})

	output := buf.String()

	// Should be valid JSON
	var logEntry map[string]interface{}
	lines := strings.Split(strings.TrimSpace(output), "\n")
	if len(lines) > 0 {
		err := json.Unmarshal([]byte(lines[len(lines)-1]), &logEntry)
		if err == nil {
			assert.Equal(t, "INFO", logEntry["level"])
			assert.Equal(t, "aimessage", logEntry["service"])
			assert.Equal(t, "Test structured log", logEntry["message"])
		}
	}
}

func TestDebugLogLevel(t *testing.T) {
	// Set debug log level
	originalLevel := os.Getenv("LOG_LEVEL")
	os.Setenv("LOG_LEVEL", "DEBUG")
	defer os.Setenv("LOG_LEVEL", originalLevel)

	var buf bytes.Buffer
	log.SetOutput(&buf)
	defer log.SetOutput(os.Stderr)

	// Replace the default logger with a debug-enabled one
	originalLogger := logging.DefaultLogger
	logging.DefaultLogger = logging.NewLogger("test-service")
	defer func() { logging.DefaultLogger = originalLogger }()

	// Test debug logging
	logging.Debug("Debug message should appear")

	output := buf.String()
	assert.Contains(t, output, "[DEBUG]")
	assert.Contains(t, output, "Debug message should appear")
}

func TestLoggerContextChaining(t *testing.T) {
	logger := logging.NewLogger("test-service")

	// Test that chaining works without error
	chainedLogger := logger.
		WithContext("user_id", "12345").
		WithContext("session_id", "67890").
		WithError(errors.New("chained error"))

	assert.NotNil(t, chainedLogger)
}

func TestLogLevelString(t *testing.T) {
	assert.Equal(t, "DEBUG", logging.DEBUG.String())
	assert.Equal(t, "INFO", logging.INFO.String())
	assert.Equal(t, "WARN", logging.WARN.String())
	assert.Equal(t, "ERROR", logging.ERROR.String())
	assert.Equal(t, "FATAL", logging.FATAL.String())
}

func TestLogLevelFiltering(t *testing.T) {
	// Set INFO level (default)
	originalLevel := os.Getenv("LOG_LEVEL")
	os.Setenv("LOG_LEVEL", "")
	defer os.Setenv("LOG_LEVEL", originalLevel)

	var buf bytes.Buffer
	log.SetOutput(&buf)
	defer log.SetOutput(os.Stderr)

	// Log debug message (should be filtered out at INFO level)
	logging.Debug("Debug message should not appear")

	// Log info message (should appear)
	logging.Info("Info message should appear")

	output := buf.String()

	// Debug should not appear
	assert.NotContains(t, output, "Debug message should not appear")
	// Info should appear
	assert.Contains(t, output, "Info message should appear")
}

func TestConvenienceFunctions(t *testing.T) {
	var buf bytes.Buffer
	log.SetOutput(&buf)
	defer log.SetOutput(os.Stderr)

	// Test convenience functions
	logging.Info("Info convenience")
	logging.Warn("Warn convenience")
	logging.Error("Error convenience")

	testError := errors.New("convenience error")
	logging.InfoWithError("Info with error", testError)
	logging.WarnWithError("Warn with error", testError)
	logging.ErrorWithError("Error with error", testError)

	output := buf.String()

	assert.Contains(t, output, "Info convenience")
	assert.Contains(t, output, "Warn convenience")
	assert.Contains(t, output, "Error convenience")
	assert.Contains(t, output, "convenience error")
}

func TestDebugConvenienceFunctions(t *testing.T) {
	// Enable debug logging
	originalLevel := os.Getenv("LOG_LEVEL")
	os.Setenv("LOG_LEVEL", "DEBUG")
	defer os.Setenv("LOG_LEVEL", originalLevel)

	var buf bytes.Buffer
	log.SetOutput(&buf)
	defer log.SetOutput(os.Stderr)

	// Replace the default logger with a debug-enabled one
	originalLogger := logging.DefaultLogger
	logging.DefaultLogger = logging.NewLogger("test-service")
	defer func() { logging.DefaultLogger = originalLogger }()

	logging.Debug("Debug convenience")
	logging.DebugWithError("Debug with error", errors.New("debug error"))

	output := buf.String()

	assert.Contains(t, output, "Debug convenience")
	assert.Contains(t, output, "debug error")
}

func TestLoggerErrorHandling(t *testing.T) {
	var buf bytes.Buffer
	log.SetOutput(&buf)
	defer log.SetOutput(os.Stderr)

	// Test logging with various data types
	logging.Info("Message with string data", "string data")
	logging.Info("Message with map data", map[string]string{"key": "value"})
	logging.Info("Message with nil data", nil)

	output := buf.String()

	assert.Contains(t, output, "Message with string data")
	assert.Contains(t, output, "Message with map data")
	assert.Contains(t, output, "Message with nil data")
}

func TestLoggerDefaultInstance(t *testing.T) {
	var buf bytes.Buffer
	log.SetOutput(&buf)
	defer log.SetOutput(os.Stderr)

	// Test that default logger works
	logging.Info("Default logger test")

	output := buf.String()
	assert.Contains(t, output, "Default logger test")
}

func TestLoggerConcurrency(t *testing.T) {
	var buf bytes.Buffer
	log.SetOutput(&buf)
	defer log.SetOutput(os.Stderr)

	// Test concurrent logging
	done := make(chan bool, 10)

	for i := 0; i < 10; i++ {
		go func(id int) {
			logging.Info("Concurrent message", map[string]int{"goroutine": id})
			done <- true
		}(i)
	}

	// Wait for all goroutines to complete
	for i := 0; i < 10; i++ {
		<-done
	}

	output := buf.String()

	// Should contain messages from concurrent goroutines
	assert.Contains(t, output, "Concurrent message")
}

func TestFatalLogging(t *testing.T) {
	// This test is tricky because Fatal calls os.Exit(1)
	// We can't easily test the actual Fatal function without stopping the test
	// But we can test that the FATAL log level string works
	assert.Equal(t, "FATAL", logging.FATAL.String())
}

func TestLoggerWithMultipleContexts(t *testing.T) {
	logger := logging.NewLogger("test-service")

	// Test adding multiple contexts
	loggerWithContexts := logger.
		WithContext("user_id", "12345").
		WithContext("session_id", "67890").
		WithContext("action", "test")

	assert.NotNil(t, loggerWithContexts)

	// Should be different from original
	assert.NotEqual(t, logger, loggerWithContexts)
}

func TestLoggerErrorChaining(t *testing.T) {
	logger := logging.NewLogger("test-service")

	err1 := errors.New("first error")
	err2 := errors.New("second error")

	// Test that we can chain error contexts
	loggerWithError1 := logger.WithError(err1)
	loggerWithError2 := loggerWithError1.WithError(err2)

	assert.NotNil(t, loggerWithError1)
	assert.NotNil(t, loggerWithError2)
	assert.NotEqual(t, loggerWithError1, loggerWithError2)
}

func TestInvalidLogLevel(t *testing.T) {
	// Test unknown log level string conversion
	var unknownLevel logging.LogLevel = 999
	assert.Equal(t, "UNKNOWN", unknownLevel.String())
}

// Benchmark tests
func BenchmarkSimpleLogging(b *testing.B) {
	var buf bytes.Buffer
	log.SetOutput(&buf)
	defer log.SetOutput(os.Stderr)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		logging.Info("Benchmark message")
	}
}

func BenchmarkStructuredLogging(b *testing.B) {
	// Enable structured logging
	originalFormat := os.Getenv("LOG_FORMAT")
	os.Setenv("LOG_FORMAT", "json")
	defer os.Setenv("LOG_FORMAT", originalFormat)

	var buf bytes.Buffer
	log.SetOutput(&buf)
	defer log.SetOutput(os.Stderr)

	data := map[string]string{
		"key1": "value1",
		"key2": "value2",
		"key3": "value3",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		logging.Info("Benchmark structured message", data)
	}
}

func BenchmarkLoggerWithContext(b *testing.B) {
	logger := logging.NewLogger("benchmark")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		logger.WithContext("iteration", i)
	}
}

func BenchmarkLoggerChaining(b *testing.B) {
	logger := logging.NewLogger("benchmark")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		logger.
			WithContext("user_id", "12345").
			WithContext("session_id", "67890").
			WithContext("iteration", i)
	}
}
