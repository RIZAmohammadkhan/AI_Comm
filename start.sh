#!/bin/bash

# Production startup script for AI Message Server

set -e

# Default values
PORT=${PORT:-8080}
DB_PATH=${DB_PATH:-./data}
LOG_FORMAT=${LOG_FORMAT:-json}

# Create data directory if it doesn't exist
mkdir -p "$DB_PATH"

# Set production environment
export LOG_FORMAT="$LOG_FORMAT"
export PORT="$PORT"
export DB_PATH="$DB_PATH"

echo "Starting AI Message Server..."
echo "Port: $PORT"
echo "Database: $DB_PATH"
echo "Log format: $LOG_FORMAT"

# Start the server
exec ./bin/aimessage-server -port "$PORT" -db "$DB_PATH"
