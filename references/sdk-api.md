# Client SDK API Reference

`openwebgoggles-sdk.js` — Vanilla JS, zero dependencies.

## Loading

```html
<script src="/sdk/openwebgoggles-sdk.js"></script>
```

Or as ES module:
```js
import OpenWebGoggles from './openwebgoggles-sdk.js';
```

## Constructor

```js
const wv = new OpenWebGoggles(options?)
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
| `OpenWebGoggles.formatTimestamp(iso)` | Format ISO string to locale |

## Connection Behavior

1. Fetches `/_api/manifest` to get session token and server ports
2. Fetches `/_api/state` for initial state
3. Attempts WebSocket connection to `ws://host:ws_port?token=TOKEN`
4. If WS fails, falls back to HTTP polling at `pollInterval`
5. Auto-reconnects WS with exponential backoff (1s -> 30s max)
6. Queues actions during disconnection, flushes on reconnect

## Client-Side Navigation

The dynamic renderer supports instant page navigation without agent round-trips via the `navigateTo` property.

### Navigation Sources

| Source | Property | Behavior |
|--------|----------|----------|
| Action buttons | `navigateTo` on action object | Button click navigates instead of sending action |
| Item lists | `navigateTo` on item object | Item click navigates to target page |
| Table rows | `navigateToField` on table section | Row click reads page key from specified field |

### How It Works

All pages in a multi-page state are pre-rendered in the DOM on initial load. Navigation simply shows/hides the target page container — no network request, no agent round-trip.

When a `navigateTo` property is present on an action button, clicking it navigates to the specified page key instead of emitting an action to the agent. The same applies to items with `navigateTo` and table rows when `navigateToField` is set on the section.

### Navigation Control

| Property | Scope | Default | Description |
|----------|-------|---------|-------------|
| `showNav` | Top-level state | `true` | Show/hide the auto-generated page tab bar |
| `hidden` | Per-page | `false` | Exclude page from nav bar (still navigable via `navigateTo`) |

### Example

```json
{
  "showNav": false,
  "pages": {
    "home": {
      "label": "Home",
      "data": { "sections": [
        { "type": "items", "items": [
          { "title": "Settings", "navigateTo": "settings" }
        ]}
      ]}
    },
    "settings": {
      "label": "Settings",
      "hidden": true,
      "data": { "sections": [...] },
      "actions_requested": [
        { "id": "back", "label": "Back", "type": "ghost", "navigateTo": "home" }
      ]
    }
  }
}
```

Navigation is silent — the agent receives no action when the user switches pages via `navigateTo`. Use `webview_read()` if the agent needs to detect the active page.
