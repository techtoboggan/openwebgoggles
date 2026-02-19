# Client SDK API Reference

`opencode-webview-sdk.js` — Vanilla JS, zero dependencies.

## Loading

```html
<script src="/sdk/opencode-webview-sdk.js"></script>
```

Or as ES module:
```js
import OpenCodeWebview from './opencode-webview-sdk.js';
```

## Constructor

```js
const wv = new OpenCodeWebview(options?)
```

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `httpUrl` | string | `window.location.origin` | HTTP server base URL |
| `wsUrl` | string | Auto-detected from manifest | WebSocket server URL |
| `pollInterval` | number | `2000` | HTTP polling interval in ms (fallback mode) |

## Connection

| Method | Returns | Description |
|--------|---------|-------------|
| `connect()` | `Promise<this>` | Fetch manifest, connect WS, initialize state |
| `disconnect()` | void | Close all connections |
| `isConnected()` | boolean | Connection status |

## State (Agent -> Webview)

| Method | Returns | Description |
|--------|---------|-------------|
| `getState()` | object\|null | Current cached state |
| `getStatus()` | string\|null | `state.status` shorthand |
| `getData()` | object\|null | `state.data` shorthand |
| `getRequestedActions()` | array | `state.actions_requested` shorthand |
| `getManifest()` | object\|null | Session manifest |
| `onStateUpdate(cb)` | unsubscribe fn | Called when state changes |
| `onManifestUpdate(cb)` | unsubscribe fn | Called when manifest changes |

## Actions (Webview -> Agent)

| Method | Returns | Description |
|--------|---------|-------------|
| `sendAction(actionId, type, value, metadata?)` | Promise | Send any action |
| `approve(actionId, metadata?)` | Promise | Approve (value=true) |
| `reject(actionId, metadata?)` | Promise | Reject (value=false) |
| `submitInput(actionId, value, metadata?)` | Promise | Submit text input |
| `selectOption(actionId, value, metadata?)` | Promise | Select an option |
| `confirm(actionId, metadata?)` | Promise | Confirm (value=true) |

## Events

```js
const unsub = wv.on(eventName, callback);
unsub(); // unsubscribe
```

| Event | Data | Description |
|-------|------|-------------|
| `connected` | `{state, manifest}` | Initial connection established |
| `disconnected` | — | Connection lost |
| `state_updated` | state object | State changed |
| `manifest_updated` | manifest object | Manifest changed |
| `actions_updated` | actions object | Actions file changed |
| `actions_cleared` | — | Agent cleared actions |
| `error` | `{message}` | Error occurred |

## Utilities

| Method | Description |
|--------|-------------|
| `OpenCodeWebview.formatTimestamp(iso)` | Format ISO string to locale |

## Connection Behavior

1. Fetches `/_api/manifest` to get session token and server ports
2. Fetches `/_api/state` for initial state
3. Attempts WebSocket connection to `ws://host:ws_port?token=TOKEN`
4. If WS fails, falls back to HTTP polling at `pollInterval`
5. Auto-reconnects WS with exponential backoff (1s -> 30s max)
6. Queues actions during disconnection, flushes on reconnect
