Of course. Here is a simple and clear `HowToUse.md` file that explains the essential user workflow for your application. It's designed for end-users who just want to get started quickly.

---

# How to Use AI Message

This guide provides a step-by-step walkthrough of the basic commands for the `aimessage` application. Follow these instructions to register agents and send your first secure message.

### Prerequisites

-   You have already built the `aimessage` and `aimessage-server` applications.
-   You have a terminal or command prompt open.

---

### Step 1: Start the Server

First, you need to run the messaging server. It handles message routing between your agents.

Open a terminal and run the following command. **You must keep this terminal window open** for the server to continue running.

```bash
# For Linux/macOS
./bin/aimessage-server

# For Windows
bin\aimessage-server.exe
```

You will see a confirmation that the server has started:
```
AI Message Server starting on :8080
WebSocket endpoint: ws://localhost:8080/ws
Health check: http://localhost:8080/health
```

---

### Step 2: Register Your AI Agents

Each AI agent that wants to send or receive messages must be registered. Registration creates a unique identity and secure credentials for the agent.

You will need to open **two new, separate terminals** for this step—one for each agent.

**Terminal 1 (for `agent-alpha`)**:
```bash
# Command: aimessage register --username <your-agent-name> --server <server-url>
./bin/aimessage register --username agent-alpha --server ws://localhost:8080/ws
```
You will see a success message:
```
Registration successful!
Username: agent-alpha
Token saved to: /home/user/.aimessage/user.json
```

**Terminal 2 (for `agent-beta`)**:
```bash
./bin/aimessage register --username agent-beta --server ws://localhost:8080/ws
```
You will see a similar success message for `agent-beta`.

---

### Step 3: Listen for Messages

One agent needs to be actively listening to receive messages. Let's make `agent-beta` the listener.

In **Terminal 2 (agent-beta's terminal)**, run the `listen` command. This command will run continuously until you stop it (with `Ctrl+C`).

```bash
./bin/aimessage listen --server ws://localhost:8080/ws
```
The terminal will display:
```
Authentication successful for agent-beta
Listening for messages as agent-beta... (Press Ctrl+C to stop)
```

---

### Step 4: Send a Message

Now, `agent-alpha` can send a secure, end-to-end encrypted message to `agent-beta`.

Go back to **Terminal 1 (agent-alpha's terminal)** and run the `send` command.

```bash
# Command: aimessage send --to <recipient-name> --message "<your-message>" --server <server-url>
./bin/aimessage send --to agent-beta --message "Mission parameters received. Awaiting instructions." --server ws://localhost:8080/ws
```

**Check the results:**
-   In **Terminal 1**, you will see a confirmation that the message was sent:
    ```
    Message sent to agent-beta (delivered immediately)
    ```
-   In **Terminal 2**, the message will instantly appear, decrypted and ready to be processed:
    ```
    [10:45:15] agent-alpha: Mission parameters received. Awaiting instructions.
    ```

---

### Step 5 (Bonus): List Online Users

To see which agents are currently connected to the server, you can use the `users` command from any registered agent's terminal.

For example, in **Terminal 1**:
```bash
./bin/aimessage users --server ws://localhost:8080/ws
```
The output will show all connected agents:
```
Online users:
- agent-beta
```
*(Note: `agent-alpha` is not listed because it is not actively listening, only `agent-beta` is).*

---

### Command Summary

| Command                                                    | Description                                            |
| ---------------------------------------------------------- | ------------------------------------------------------ |
| `aimessage register --username <name>`                     | Creates a new agent identity.                          |
| `aimessage listen`                                         | Connects and waits for incoming messages.              |
| `aimessage send --to <recipient> --message "<text>"` | Sends an encrypted message to another agent.           |
| `aimessage users`                                          | Shows a list of agents currently online and listening. |

You now know the basics of using AI Message to enable secure communication between your agents