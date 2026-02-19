# Data Contract Reference

All files live in `.opencode/webview/` within the current working directory.

## manifest.json

Session metadata. Written by `start_webview.sh`, read by server and SDK.

| Field | Type | Description |
|-------|------|-------------|
| `version` | string | Contract version (`"1.0"`) |
| `app.name` | string | App identifier (e.g., `"approval-review"`) |
| `app.entry` | string | Entry HTML path relative to `apps/` |
| `app.title` | string | Browser tab title |
| `session.id` | string | UUID for this session |
| `session.created_at` | string | ISO 8601 timestamp |
| `session.token` | string | 32-byte hex session token for auth |
| `session.agent_skill` | string | Name of the skill that launched this webview |
| `server.http_port` | int | HTTP port (default: 18420) |
| `server.ws_port` | int | WebSocket port (default: 18421) |
| `server.host` | string | Bind address (default: `"127.0.0.1"`) |

## state.json

Agent-to-webview state. Written by the agent via `write_state.sh`, read by the webview via SDK.

| Field | Type | Description |
|-------|------|-------------|
| `version` | int | Monotonically increasing counter (increment on each write) |
| `status` | string | Lifecycle status (see below) |
| `updated_at` | string | ISO 8601 timestamp |
| `title` | string | Human-readable title for the current state |
| `message` | string | Optional description or instructions |
| `data` | object | Arbitrary app-specific payload |
| `actions_requested` | array | Actions the agent wants the user to perform |

### Status Values

| Status | Meaning |
|--------|---------|
| `initializing` | Server starting up |
| `ready` | Webview loaded, waiting for agent data |
| `pending_review` | Agent has data for user to review |
| `waiting_input` | Agent needs user input to continue |
| `processing` | Agent is working on user's response |
| `completed` | Workflow finished |
| `error` | Something went wrong |

### actions_requested Items

| Field | Type | Description |
|-------|------|-------------|
| `id` | string | Unique action identifier (referenced in responses) |
| `type` | string | `approve`, `reject`, `select`, `input`, `confirm`, `custom` |
| `label` | string | Human-readable button/field label |
| `description` | string | Tooltip or helper text |
| `options` | array | For `select`: `[{value, label}]` |
| `required` | bool | Whether the action must be completed |

## actions.json

Webview-to-agent responses. Written by the webview via SDK, read by the agent via `read_actions.sh`.

| Field | Type | Description |
|-------|------|-------------|
| `version` | int | Incremented on each append |
| `actions` | array | User action responses |

### Action Response Items

| Field | Type | Description |
|-------|------|-------------|
| `id` | string | UUID for this response |
| `action_id` | string | References `id` from `actions_requested` |
| `type` | string | Same types as `actions_requested` |
| `timestamp` | string | ISO 8601 when user responded |
| `value` | any | `true/false` for approve/reject, string for input, string for select |
| `metadata` | object | Optional additional context (comments, etc.) |
