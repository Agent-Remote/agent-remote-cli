# 01 Project Overview

`agent-remote-cli` is the local device client for agent-remote. It configures a device, authenticates users, manages local dependencies and network access, coordinates workspace sync, and launches or attaches to remote tool sessions.

## Repository Boundary

- `agent-remote` owns generic local device management.
- Tool-specific workflows remain separate binaries such as `fclaude`.
- The CLI consumes control-plane contracts; it does not make server scheduling or authorization decisions.
- Remote tool login state and browser profiles stay on nodes.

Command names, flags, exit behavior, configuration layout, and installer behavior are public compatibility surfaces. Changes require focused tests and documentation.
