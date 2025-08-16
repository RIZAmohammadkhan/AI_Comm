package logging

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"runtime"
	"time"
)

// LogLevel represents the severity of a log entry
type LogLevel int

const (
	DEBUG LogLevel = iota
	INFO
	WARN
	ERROR
	FATAL
)

func (l LogLevel) String() string {
	switch l {
	case DEBUG:
		return "DEBUG"
	case INFO:
		return "INFO"
	case WARN:
		return "WARN"
	case ERROR:
		return "ERROR"
	case FATAL:
		return "FATAL"
	default:
		return "UNKNOWN"
	}
}

type Logger struct {
	structured bool
	level      LogLevel
	service    string
	context    map[string]interface{}
}

type LogEntry struct {
	Time      time.Time              `json:"time"`
	Level     string                 `json:"level"`
	Message   string                 `json:"message"`
	Service   string                 `json:"service"`
	Data      interface{}            `json:"data,omitempty"`
	Context   map[string]interface{} `json:"context,omitempty"`
	Error     string                 `json:"error,omitempty"`
	Caller    string                 `json:"caller,omitempty"`
	RequestID string                 `json:"request_id,omitempty"`
}

var DefaultLogger = NewLogger("aimessage")

func NewLogger(service string) *Logger {
	level := INFO
	if os.Getenv("LOG_LEVEL") == "DEBUG" {
		level = DEBUG
	}

	return &Logger{
		structured: os.Getenv("LOG_FORMAT") == "json",
		level:      level,
		service:    service,
		context:    make(map[string]interface{}),
	}
}

// WithContext returns a new logger with additional context
func (l *Logger) WithContext(key string, value interface{}) *Logger {
	newLogger := &Logger{
		structured: l.structured,
		level:      l.level,
		service:    l.service,
		context:    make(map[string]interface{}),
	}

	// Copy existing context
	for k, v := range l.context {
		newLogger.context[k] = v
	}

	// Add new context
	newLogger.context[key] = value
	return newLogger
}

// WithError returns a new logger with error context
func (l *Logger) WithError(err error) *Logger {
	return l.WithContext("error", err.Error())
}

func (l *Logger) log(level LogLevel, message string, data interface{}, err error) {
	if level < l.level {
		return
	}

	// Get caller information
	_, file, line, ok := runtime.Caller(3)
	caller := ""
	if ok {
		caller = fmt.Sprintf("%s:%d", file, line)
	}

	if l.structured {
		entry := LogEntry{
			Time:    time.Now().UTC(),
			Level:   level.String(),
			Message: message,
			Service: l.service,
			Data:    data,
			Context: l.context,
			Caller:  caller,
		}

		if err != nil {
			entry.Error = err.Error()
		}

		// Extract request ID from context if available
		if ctx, ok := data.(context.Context); ok {
			if reqID := ctx.Value("request_id"); reqID != nil {
				if reqIDStr, ok := reqID.(string); ok {
					entry.RequestID = reqIDStr
				}
			}
		}

		if jsonData, marshalErr := json.Marshal(entry); marshalErr == nil {
			log.Println(string(jsonData))
		} else {
			log.Printf("[%s] %s (JSON marshal error: %v)", level.String(), message, marshalErr)
		}
	} else {
		prefix := fmt.Sprintf("[%s]", level.String())
		if err != nil {
			if data != nil {
				log.Printf("%s %s: %+v (error: %v)", prefix, message, data, err)
			} else {
				log.Printf("%s %s (error: %v)", prefix, message, err)
			}
		} else {
			if data != nil {
				log.Printf("%s %s: %+v", prefix, message, data)
			} else {
				log.Printf("%s %s", prefix, message)
			}
		}
	}
}

// Convenience functions for common log levels
func Debug(message string, data ...interface{}) {
	var d interface{}
	if len(data) > 0 {
		d = data[0]
	}
	DefaultLogger.log(DEBUG, message, d, nil)
}

func DebugWithError(message string, err error, data ...interface{}) {
	var d interface{}
	if len(data) > 0 {
		d = data[0]
	}
	DefaultLogger.log(DEBUG, message, d, err)
}

func Info(message string, data ...interface{}) {
	var d interface{}
	if len(data) > 0 {
		d = data[0]
	}
	DefaultLogger.log(INFO, message, d, nil)
}

func InfoWithError(message string, err error, data ...interface{}) {
	var d interface{}
	if len(data) > 0 {
		d = data[0]
	}
	DefaultLogger.log(INFO, message, d, err)
}

func Error(message string, data ...interface{}) {
	var d interface{}
	if len(data) > 0 {
		d = data[0]
	}
	DefaultLogger.log(ERROR, message, d, nil)
}

func ErrorWithError(message string, err error, data ...interface{}) {
	var d interface{}
	if len(data) > 0 {
		d = data[0]
	}
	DefaultLogger.log(ERROR, message, d, err)
}

func Warn(message string, data ...interface{}) {
	var d interface{}
	if len(data) > 0 {
		d = data[0]
	}
	DefaultLogger.log(WARN, message, d, nil)
}

func WarnWithError(message string, err error, data ...interface{}) {
	var d interface{}
	if len(data) > 0 {
		d = data[0]
	}
	DefaultLogger.log(WARN, message, d, err)
}

func Fatal(message string, data ...interface{}) {
	var d interface{}
	if len(data) > 0 {
		d = data[0]
	}
	DefaultLogger.log(FATAL, message, d, nil)
	os.Exit(1)
}

func FatalWithError(message string, err error, data ...interface{}) {
	var d interface{}
	if len(data) > 0 {
		d = data[0]
	}
	DefaultLogger.log(FATAL, message, d, err)
	os.Exit(1)
}
