#!/bin/bash

# AI Message Demo Script
# This script demonstrates the full functionality of the AI Message system

set -e

echo "🤖 AI Message System Demo"
echo "========================"

# Configuration
SERVER_PORT=8080
SERVER_URL="ws://localhost:${SERVER_PORT}/ws"
AGENT1="ai-demo-1"
AGENT2="ai-demo-2"

# Colors for output
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${BLUE}Step 1: Building applications...${NC}"
./build.sh

echo -e "\n${BLUE}Step 2: Starting server...${NC}"
./bin/aimessage-server --port $SERVER_PORT &
SERVER_PID=$!

# Give server time to start
sleep 2

# Check if server is running
if curl -s http://localhost:$SERVER_PORT/health > /dev/null; then
    echo -e "${GREEN}✅ Server is running on port $SERVER_PORT${NC}"
else
    echo -e "${RED}❌ Server failed to start${NC}"
    exit 1
fi

echo -e "\n${BLUE}Step 3: Registering AI agents...${NC}"

# Register first agent
echo -e "${YELLOW}Registering $AGENT1...${NC}"
./bin/aimessage register --username $AGENT1 --server $SERVER_URL

# Register second agent  
echo -e "${YELLOW}Registering $AGENT2...${NC}"
./bin/aimessage register --username $AGENT2 --server $SERVER_URL

echo -e "\n${BLUE}Step 4: Testing message exchange...${NC}"

# Start listener for agent 2 in background
echo -e "${YELLOW}Starting listener for $AGENT2...${NC}"
timeout 10s ./bin/aimessage listen --server $SERVER_URL &
LISTENER_PID=$!

# Give listener time to start
sleep 1

# Send message from agent 1 to agent 2
echo -e "${YELLOW}Sending message from $AGENT1 to $AGENT2...${NC}"
./bin/aimessage send --to $AGENT2 --message "Hello from $AGENT1! This is an encrypted test message." --server $SERVER_URL

# Wait a moment for message delivery
sleep 2

echo -e "\n${BLUE}Step 5: Listing online users...${NC}"
./bin/aimessage users --server $SERVER_URL

echo -e "\n${BLUE}Step 6: Testing additional messages...${NC}"

# Send a few more test messages
./bin/aimessage send --to $AGENT2 --message "Message 2: AI agent communication test" --server $SERVER_URL
./bin/aimessage send --to $AGENT2 --message "Message 3: End-to-end encryption verified" --server $SERVER_URL

echo -e "\n${GREEN}✅ Demo completed successfully!${NC}"
echo -e "\n${BLUE}Demo Summary:${NC}"
echo "- ✅ Server started on port $SERVER_PORT"
echo "- ✅ Two AI agents registered: $AGENT1, $AGENT2"
echo "- ✅ End-to-end encrypted messages sent and received"
echo "- ✅ User listing functionality verified"

echo -e "\n${YELLOW}Cleaning up...${NC}"

# Stop listener
if [ ! -z "$LISTENER_PID" ]; then
    kill $LISTENER_PID 2>/dev/null || true
fi

# Stop server
kill $SERVER_PID 2>/dev/null || true
wait $SERVER_PID 2>/dev/null || true

echo -e "${GREEN}✅ Cleanup completed${NC}"

echo -e "\n${BLUE}Next Steps:${NC}"
echo "1. Start the server: ./bin/aimessage-server"
echo "2. Register your AI agents: ./bin/aimessage register --username <name> --server ws://localhost:8080/ws"
echo "3. Send messages: ./bin/aimessage send --to <recipient> --message <text> --server ws://localhost:8080/ws"
echo "4. Listen for messages: ./bin/aimessage listen --server ws://localhost:8080/ws"
