# ZeroClaw Tools Reference

This document provides a comprehensive reference for all tools available in ZeroClaw, including their descriptions, parameters, configuration options, and external dependencies.

Last verified: **February 23, 2026**.

## Tool Registry

Tools are assembled into registries:
- **Default tools**: `shell`, `file_read`, `file_write`, `file_edit`, `glob_search`, `content_search`
- **Full tools**: All default tools plus memory, browser, cron, HTTP, delegation, and optional integrations

```bash
# List available tools
zeroclaw tools
```

---

## File Operations

### shell

Execute shell commands in the workspace directory.

| Parameter | Type | Description | Required |
|-----------|------|-------------|----------|
| `command` | string | The shell command to execute | Yes |
| `approved` | boolean | Set true to explicitly approve medium/high-risk commands in supervised mode | No |

**Description**: Execute a shell command with security sandboxing. Commands run in the workspace directory with a 60-second timeout and 1MB output limit. Environment variables are sanitized to prevent API key leakage.

**Config Options** (via `[autonomy]` in config):
```toml
[autonomy]
level = "supervised"  # read_only, supervised, full
allowed_commands = ["git", "cargo", "npm"]  # whitelist specific commands
shell_env_passthrough = ["MY_CUSTOM_VAR"]  # pass specific env vars
max_actions_per_hour = 100
```

**External Dependencies**: None (built-in)

---

### file_read

Read file contents with line numbers. Supports partial reading via offset/limit.

| Parameter | Type | Description | Required |
|-----------|------|-------------|----------|
| `path` | string | Path to the file (relative to workspace) | Yes |
| `offset` | integer | Starting line number (1-based, default: 1) | No |
| `limit` | integer | Maximum number of lines to return | No |

**Description**: Reads files within workspace boundaries. Supports PDF text extraction (when `rag-pdf` feature enabled). Binary files are read with lossy UTF-8 conversion.

**Config Options**: Uses `[autonomy]` settings for path restrictions.

**External Dependencies**: None (built-in)

---

### file_write

Write contents to a file in the workspace.

| Parameter | Type | Description | Required |
|-----------|------|-------------|----------|
| `path` | string | Path to the file | Yes |
| `content` | string | Content to write | Yes |

**Description**: Creates parent directories as needed. Refuses to write through symlinks.

**Config Options**: Uses `[autonomy]` settings.

**External Dependencies**: None (built-in)

---

### file_edit

Edit a file by replacing an exact string match with new content.

| Parameter | Type | Description | Required |
|-----------|------|-------------|----------|
| `path` | string file | Yes |
 | Path to the| `old_string` | string | Exact text to find and replace | Yes |
| `new_string` | string | Replacement text (empty to delete) | Yes |

**Description**: The `old_string` must appear exactly once in the file. Multiple matches return an error.

**Config Options**: Uses `[autonomy]` settings.

**External Dependencies**: None (built-in)

---

### glob_search

Search for files matching a glob pattern within the workspace.

| Parameter | Type | Description | Required |
|-----------|------|-------------|----------|
| `pattern` | string | Glob pattern (e.g., `**/*.rs`, `src/**/mod.rs`) | Yes |

**Description**: Returns sorted list of matching file paths. Filters symlink escapes. Max 1000 results.

**Config Options**: Uses `[autonomy]` settings.

**External Dependencies**: None (built-in)

---

### content_search

Search file contents by regex pattern within the workspace.

| Parameter | Type | Description | Required |
|-----------|------|-------------|----------|
| `pattern` | string | Regular expression pattern | Yes |
| `path` | string | Directory to search (default: `.`) | No |
| `output_mode` | string | `content`, `files_with_matches`, or `count` | No |
| `include` | string | File glob filter (e.g., `*.rs`) | No |
| `case_sensitive` | boolean | Case-sensitive matching (default: true) | No |
| `context_before` | integer | Lines before each match | No |
| `context_after` | integer | Lines after each match | No |
| `multiline` | boolean | Enable multiline matching (requires ripgrep) | No |
| `max_results` | integer | Maximum results (default: 1000) | No |

**Description**: Uses ripgrep (`rg`) when available, falls back to `grep`. Output truncated at 1MB.

**External Dependencies**: 
- **Recommended**: `ripgrep` (`rg`) for full feature support
- **Fallback**: `grep` (limited features, no multiline)

---

## Cron Scheduling Tools

### cron_add

Create a scheduled cron job (shell or agent).

| Parameter | Type | Description | Required |
|-----------|------|-------------|----------|
| `name` | string | Job name | No |
| `schedule` | object | Schedule specification | Yes |
| `job_type` | string | `shell` or `agent` | No |
| `command` | string | Shell command (for shell jobs) | No |
| `prompt` | string | Agent prompt (for agent jobs) | No |
| `session_target` | string | `isolated` or `main` | No |
| `model` | string | Model to use | No |
| `delete_after_run` | boolean | Delete job after execution (default: true for `at` schedules) | No |
| `approved` | boolean | Approve medium-risk shell commands | No |

**Schedule Format**:
```json
{"kind": "cron", "expr": "*/5 * * * *", "tz": "UTC"}
{"kind": "at", "at": "2024-01-01T12:00:00Z"}
{"kind": "every", "every_ms": 60000}
```

**Config Options**:
```toml
[cron]
enabled = true
jobs_dir = ".zeroclaw/cron"
```

**External Dependencies**: None (built-in scheduler)

---

### cron_list

List all scheduled cron jobs.

| Parameter | Type | Description | Required |
|-----------|------|-------------|----------|
| (none) | - | - | - |

**Config Options**: Requires `[cron].enabled = true`

**External Dependencies**: None (built-in)

---

### cron_remove

Remove a cron job by ID.

| Parameter | Type | Description | Required |
|-----------|------|-------------|----------|
| `job_id` | string | ID of the job to remove | Yes |

**External Dependencies**: None (built-in)

---

### cron_update

Patch an existing cron job.

| Parameter | Type | Description | Required |
|-----------|------|-------------|----------|
| `job_id` | string | ID of the job to update | Yes |
| `patch` | object | Fields to update | Yes |
| `approved` | boolean | Approve medium-risk shell commands | No |

**Patch Fields**: `schedule`, `command`, `prompt`, `enabled`, `delivery`, `model`, `delete_after_run`

**External Dependencies**: None (built-in)

---

### cron_run

Force-run a cron job immediately.

| Parameter | Type | Description | Required |
|-----------|------|-------------|----------|
| `job_id` | string | ID of the job to run | Yes |
| `approved` | boolean | Approve medium-risk shell commands | No |

**External Dependencies**: None (built-in)

---

### cron_runs

List recent run history for a cron job.

| Parameter | Type | Description | Required |
|-----------|------|-------------|----------|
| `job_id` | string | ID of the job | Yes |
| `limit` | integer | Maximum runs to return (default: 10) | No |

**External Dependencies**: None (built-in)

---

## Memory Tools

### memory_store

Store a fact, preference, or note in long-term memory.

| Parameter | Type | Description | Required |
|-----------|------|-------------|----------|
| `key` | string | Unique key for this memory | Yes |
| `content` | string | The information to remember | Yes |
| `category` | string | `core` (permanent), `daily`, `conversation`, or custom | No |

**Description**: Categories: `core` for permanent facts, `daily` for session notes, `conversation` for chat context.

**Config Options**:
```toml
[memory]
backend = "sqlite"  # sqlite, markdown, none
path = ".zeroclaw/memory.db"
```

**External Dependencies**: None (built-in backends)

---

### memory_recall

Search long-term memory for relevant facts.

| Parameter | Type | Description | Required |
|-----------|------|-------------|----------|
| `query` | string | Keywords or phrase to search | Yes |
| `limit` | integer | Max results (default: 5) | No |

**External Dependencies**: None (built-in)

---

### memory_forget

Remove a memory by key.

| Parameter | Type | Description | Required |
|-----------|------|-------------|----------|
| `key` | string | Key of the memory to forget | Yes |

**External Dependencies**: None (built-in)

---

## Git Operations

### git_operations

Perform structured Git operations.

| Parameter | Type | Description | Required |
|-----------|------|-------------|----------|
| `operation` | string | `status`, `diff`, `log`, `branch`, `commit`, `add`, `checkout`, `stash` | Yes |
| `message` | string | Commit message | No* |
| `paths` | string | File paths to stage (for `add`) | No* |
| `branch` | string | Branch name (for `checkout`) | No* |
| `files` | string | Files to diff | No* |
| `cached` | boolean | Show staged changes | No |
| `limit` | integer | Number of log entries | No |
| `action` | string | Stash action: `push`, `pop`, `list`, `drop` | No* |
| `index` | integer | Stash index (for `drop`) | No |

**Required parameters vary by operation.

**Description**: Provides parsed JSON output. Integrates with security policy for autonomy controls. Write operations (commit, add, checkout, stash, reset, revert) require higher autonomy level.

**Config Options**: Uses `[autonomy]` settings.

**External Dependencies**: `git` CLI installed and available in PATH

---

## Browser Tools

### browser_open

Open an approved HTTPS URL in Brave Browser.

| Parameter | Type | Description | Required |
|-----------|------|-------------|----------|
| `url` | string | HTTPS URL to open | Yes |

**Description**: Security: allowlist-only domains, no local/private hosts, no scraping.

**Config Options**:
```toml
[browser]
enabled = true
allowed_domains = ["example.com", "docs.example.com"]
```

**External Dependencies**: Brave Browser installed

---

### browser

Full browser automation tool with pluggable backends.

| Parameter | Type | Description | Required |
|-----------|------|-------------|----------|
| `action` | string | Browser action to perform | Yes |
| `url` | string | URL for `open` action | No* |
| `selector` | string | Element selector for click/fill actions | No* |
| `value` | string | Value for fill actions | No* |

**Actions**: `open`, `snapshot`, `click`, `fill`, `scroll`, `screenshot`, `console`

**Config Options**:
```toml
[browser]
enabled = true
allowed_domains = ["example.com"]
session_name = "default"

[browser.backend]
type = "agent_browser"  # agent_browser, rust_native, computer_use, auto

[browser.computer_use]
endpoint = "http://127.0.0.1:8787/v1/actions"
api_key = "optional-key"
timeout_ms = 15000
```

**External Dependencies**:
- **agent_browser backend**: Vercel `agent-browser` CLI
- **rust_native backend**: Chrome/Chromium with Selenium WebDriver
- **computer_use backend**: Computer use sidecar service

---

## HTTP Tools

### http_request

Make HTTP requests to external APIs.

| Parameter | Type | Description | Required |
|-----------|------|-------------|----------|
| `url` | string | HTTP or HTTPS URL | Yes |
| `method` | string | `GET`, `POST`, `PUT`, `DELETE`, `PATCH`, `HEAD`, `OPTIONS` | No |
| `headers` | object | Key-value pairs for request headers | No |
| `body` | string | Request body for POST/PUT/PATCH | No |

**Description**: Security: allowlist-only domains, no local/private hosts. Response truncated at configurable limit.

**Config Options**:
```toml
[http_request]
enabled = true
allowed_domains = ["api.example.com", "*.service.com"]
max_response_size = 1048576  # bytes
timeout_secs = 30
```

**External Dependencies**: None (built-in HTTP client)

---

### web_search_tool

Search the web for information.

| Parameter | Type | Description | Required |
|-----------|------|-------------|----------|
| `query` | string | Search query | Yes |

**Description**: Returns search results with titles, URLs, and descriptions. Supports DuckDuckGo (free) and Brave (API key required).

**Config Options**:
```toml
[web_search]
enabled = true
provider = "duckduckgo"  # or "brave"
brave_api_key = "your-brave-api-key"
max_results = 10
timeout_secs = 15
```

**External Dependencies**:
- **DuckDuckGo**: None (free, no API key)
- **Brave**: Brave Search API key required

---

## Notification Tools

### pushover

Send Pushover notifications to your device.

| Parameter | Type | Description | Required |
|-----------|------|-------------|----------|
| `message` | string | Notification message | Yes |
| `title` | string | Optional notification title | No |
| `priority` | integer | -2 (lowest) to 2 (emergency) | No |
| `sound` | string | Sound override (e.g., `pushover`, `bike`) | No |

**Config Options**:
```toml
# Requires .env file in workspace
PUSHOVER_TOKEN = "your-app-token"
PUSHOVER_USER_KEY = "your-user-key"
```

**External Dependencies**:
- Pushover account (free tier works)
- API credentials in `.env` file

---

## Integration Tools

### composio

Execute actions on 1000+ apps via Composio (Gmail, Notion, GitHub, Slack, etc.).

| Parameter | Type | Description | Required |
|-----------|------|-------------|----------|
| `action` | string | `list`, `list_accounts`, `execute`, `connect` | Yes |
| `app` | string | Toolkit slug (e.g., `gmail`, `github`) | No |
| `action_name` | string | Action/tool identifier to execute | No* |
| `tool_slug` | string | Preferred v3 tool slug | No* |
| `params` | object | Parameters to pass to the action | No |
| `entity_id` | string | Entity/user ID for multi-user setups | No |
| `auth_config_id` | string | Auth config ID for connect flow | No |
| `connected_account_id` | string | Specific connected account ID | No |

**Required**: `action_name` or `tool_slug` for `execute` action.

**Config Options**:
```toml
[composio]
# API key stored in encrypted secret store
api_key = "composio-api-key"  # or set via COMPOSIO_API_KEY env var
entity_id = "default"
```

**External Dependencies**:
- Composio account (https://composio.ai)
- API key from Composio dashboard
- OAuth connections for each integrated app

---

## Delegation Tools

### delegate

Delegate a subtask to a specialized agent.

| Parameter | Type | Description | Required |
|-----------|------|-------------|----------|
| `agent` | string | Name of agent to delegate to | Yes |
| `prompt` | string | Task/prompt for sub-agent | Yes |
| `context` | string | Optional context to prepend | No |

**Description**: Enables multi-agent workflows where a primary agent hands off specialized work to purpose-built sub-agents with different provider/model configurations.

**Config Options**:
```toml
[[agents]]
name = "researcher"
provider = "openai"
model = "gpt-4o"
system_prompt = "You are a research assistant..."
max_depth = 3
max_iterations = 10
allowed_tools = ["web_search_tool", "memory_recall"]

[[agents]]
name = "coder"
provider = "anthropic"
model = "claude-sonnet-4-20250514"
system_prompt = "You are a coding assistant..."
```

**External Dependencies**: Configured agents in `[agents]` section

---

## PDF Tools

### pdf_read

Extract plain text from a PDF file.

| Parameter | Type | Description | Required |
|-----------|------|-------------|----------|
| `path` | string | Path to PDF file | Yes |
| `max_chars` | integer | Max characters to return (default: 50000, max: 200000) | No |

**Description**: Extracts text from PDF files. Image-only or encrypted PDFs return empty result. Requires `rag-pdf` build feature.

**Config Options**: Uses `[autonomy]` settings for path restrictions.

**External Dependencies**:
- **Build feature**: `cargo build --features rag-pdf`
- **Runtime**: PDF extraction library (enabled via feature flag)

---

## Schedule Tools

### schedule

View and manage scheduled tasks (alias for cron tools).

**Description**: Unified scheduling interface combining cron and one-time schedules.

**Config Options**: Same as `[cron]` config.

**External Dependencies**: None (built-in)

---

## Configuration Example

Full tool configuration in `config.toml`:

```toml
# Autonomy and security
[autonomy]
level = "supervised"
allowed_commands = ["git", "cargo", "npm", "pytest"]
max_actions_per_hour = 100

# Cron scheduling
[cron]
enabled = true
jobs_dir = ".zeroclaw/cron"

# Memory backend
[memory]
backend = "sqlite"
path = ".zeroclaw/memory.db"

# Browser automation
[browser]
enabled = true
allowed_domains = ["github.com", "docs.example.com"]

[browser.backend]
type = "agent_browser"

# HTTP requests
[http_request]
enabled = true
allowed_domains = ["api.example.com"]
max_response_size = 1048576

# Web search
[web_search]
enabled = true
provider = "duckduckgo"

# Composio integration
[composio]
entity_id = "default"

# Agent delegation
[[agents]]
name = "researcher"
provider = "openai"
model = "gpt-4o"
max_depth = 3
```

---

## Environment Variables

| Variable | Used By | Description |
|----------|---------|-------------|
| `PUSHOVER_TOKEN` | pushover | Pushover app token |
| `PUSHOVER_USER_KEY` | pushover | Pushover user key |
| `COMPOSIO_API_KEY` | composio | Composio API key |
| `BRAVE_API_KEY` | web_search_tool | Brave Search API key |
| `ZEROCLAW_API_KEY` | delegate | Fallback credential for agents |

---

## Security Considerations

1. **Path sandboxing**: All file operations enforce workspace boundaries
2. **Command allowlisting**: Shell commands can be restricted to specific binaries
3. **Domain allowlisting**: Browser and HTTP tools restrict to configured domains
4. **Rate limiting**: All tools respect `max_actions_per_hour` setting
5. **Environment sanitization**: Shell commands don't leak API keys via environment

See [`security/`](../security/) for detailed security policy configuration.
