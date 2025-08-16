#!/bin/bash

# AI Message - Build Script
echo "Building AI Message..."

# Create bin directory
mkdir -p bin

# Build server
echo "Building server..."
go build -o bin/aimessage-server ./cmd/aimessage-server
if [ $? -eq 0 ]; then
    echo "✅ Server built successfully"
else
    echo "❌ Server build failed"
    exit 1
fi

# Build client
echo "Building client..."
go build -o bin/aimessage ./cmd/aimessage
if [ $? -eq 0 ]; then
    echo "✅ Client built successfully"
else
    echo "❌ Client build failed"
    exit 1
fi

echo ""
echo "🎉 Build complete!"
echo "Server: ./bin/aimessage-server"
echo "Client: ./bin/aimessage"
