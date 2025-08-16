# Multi-Agent Support

## Overview

AI Message now supports running multiple agents on the same system. This feature allows different AI processes, applications, or services to each have their own unique identity and secure communication channel.

## Key Changes

### 1. Agent-Specific Configuration Directories

**Before:** All agents shared a single configuration file:
- `~/.aimessage/user.json`

**After:** Each agent has its own configuration directory:
- `~/.aimessage/agents/{agent-id}/user.json`

### 2. New CLI Flag

A new global flag `--agent` (short: `-a`) has been added to all commands:

```bash
aimessage register --username worker-1 --agent worker1 --server ws://localhost:8080/ws
aimessage listen --agent worker1 --server ws://localhost:8080/ws
aimessage send --to coordinator --message "Task complete" --agent worker1 --server ws://localhost:8080/ws
```

### 3. Backward Compatibility

The system remains backward compatible:
- If no `--agent` flag is specified, the default agent ID "default" is used
- Existing configurations will continue to work with the default agent

## Usage Examples

### Running Multiple Agents

```bash
# Terminal 1: AI Coordinator
aimessage register --username ai-coordinator --agent coord --server ws://localhost:8080/ws
aimessage listen --agent coord --server ws://localhost:8080/ws

# Terminal 2: Worker Agent 1
aimessage register --username worker-001 --agent worker1 --server ws://localhost:8080/ws
aimessage listen --agent worker1 --server ws://localhost:8080/ws

# Terminal 3: Worker Agent 2
aimessage register --username worker-002 --agent worker2 --server ws://localhost:8080/ws
aimessage listen --agent worker2 --server ws://localhost:8080/ws

# Terminal 4: Send commands from coordinator
aimessage send --to worker-001 --message "Process batch A" --agent coord --server ws://localhost:8080/ws
aimessage send --to worker-002 --message "Process batch B" --agent coord --server ws://localhost:8080/ws
```

### Configuration File Locations

Each agent's configuration is stored separately:

```
~/.aimessage/
├── agents/
│   ├── coord/
│   │   └── user.json     # AI Coordinator credentials
│   ├── worker1/
│   │   └── user.json     # Worker 1 credentials
│   ├── worker2/
│   │   └── user.json     # Worker 2 credentials
│   └── default/
│       └── user.json     # Default agent (for backward compatibility)
```

## Security Benefits

1. **Credential Isolation**: Each agent has its own unique credentials and cannot access another agent's configuration
2. **Process Separation**: Multiple AI processes can run independently without credential conflicts
3. **Audit Trail**: Each agent's activity can be tracked separately

## Migration Guide

### For Existing Single-Agent Setups

No changes required! Your existing setup will continue to work exactly as before.

### For New Multi-Agent Setups

1. Choose unique agent IDs for each agent (e.g., "coordinator", "worker1", "worker2")
2. Use the `--agent` flag consistently for each agent across all commands
3. Register each agent with a unique username and agent ID

## API Changes

### New Functions

- `client.NewClientWithAgent(serverURL, agentID string) *Client` - Create a client for a specific agent
- Existing `client.NewClient(serverURL string) *Client` now uses "default" as the agent ID

### File Structure Changes

- Configuration files moved from `~/.aimessage/user.json` to `~/.aimessage/agents/{agent-id}/user.json`
- Automatic directory creation for agent-specific paths

## Best Practices

1. **Use descriptive agent IDs**: Choose meaningful names like "coordinator", "worker1", "monitor" rather than generic names
2. **Consistent agent usage**: Always use the same agent ID for the same logical agent across all operations
3. **Document your agents**: Keep track of which agent IDs are used for what purposes in your system
4. **Secure agent IDs**: While agent IDs are not secret, avoid using sensitive information in the ID itself

## Troubleshooting

### Common Issues

1. **Wrong agent specified**: Make sure you're using the correct `--agent` flag for the intended agent
2. **Missing configuration**: Each agent needs to be registered before it can send or receive messages
3. **Path permissions**: Ensure the user has write permissions to the `~/.aimessage/agents/` directory

### Debug Commands

```bash
# List all registered agents
ls ~/.aimessage/agents/

# Check a specific agent's configuration
cat ~/.aimessage/agents/worker1/user.json

# Test connectivity for a specific agent
aimessage users --agent worker1 --server ws://localhost:8080/ws
```
