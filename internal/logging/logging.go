package logging

import (
	"encoding/json"
	"log"
	"os"
	"time"
)

type Logger struct {
	structured bool
}

type LogEntry struct {
	Time    time.Time `json:"time"`
	Level   string    `json:"level"`
	Message string    `json:"message"`
	Service string    `json:"service"`
	Data    any       `json:"data,omitempty"`
}

var DefaultLogger = &Logger{
	structured: os.Getenv("LOG_FORMAT") == "json",
}

func (l *Logger) log(level, message string, data any) {
	if l.structured {
		entry := LogEntry{
			Time:    time.Now().UTC(),
			Level:   level,
			Message: message,
			Service: "aimessage-server",
			Data:    data,
		}
		if jsonData, err := json.Marshal(entry); err == nil {
			log.Println(string(jsonData))
		} else {
			log.Printf("[%s] %s", level, message)
		}
	} else {
		if data != nil {
			log.Printf("[%s] %s: %+v", level, message, data)
		} else {
			log.Printf("[%s] %s", level, message)
		}
	}
}

func Info(message string, data ...any) {
	var d any
	if len(data) > 0 {
		d = data[0]
	}
	DefaultLogger.log("INFO", message, d)
}

func Error(message string, data ...any) {
	var d any
	if len(data) > 0 {
		d = data[0]
	}
	DefaultLogger.log("ERROR", message, d)
}

func Warn(message string, data ...any) {
	var d any
	if len(data) > 0 {
		d = data[0]
	}
	DefaultLogger.log("WARN", message, d)
}
