# openwebgoggles — JS SDK

Browser SDK for [OpenWebGoggles](https://github.com/techtoboggan/openwebgoggles) — human-in-the-loop UI panels for AI coding agents.

## Installation

```bash
npm install openwebgoggles
# or
yarn add openwebgoggles
```

## Usage

### ESM / bundler

```js
import OpenWebGoggles from 'openwebgoggles';

const wv = new OpenWebGoggles();
await wv.connect();

wv.onStateUpdate((state) => {
  document.getElementById('title').textContent = state.title ?? '';
});
```

### CommonJS

```js
const OpenWebGoggles = require('openwebgoggles');

const wv = new OpenWebGoggles();
wv.connect().then(() => { /* ready */ });
```

### Browser `<script>` tag

```html
<script src="/sdk/openwebgoggles-sdk.js"></script>
<script>
  const wv = new OpenWebGoggles();
  wv.connect().then(() => {
    wv.onStateUpdate((state) => renderUI(state));
  });
</script>
```

## API

See the [TypeScript definitions](./openwebgoggles.d.ts) for the full API surface.

```ts
const wv = new OpenWebGoggles(options?: OWGOptions);

// Connect to the running OpenWebGoggles server
await wv.connect(): Promise<OpenWebGoggles>

// Listen for state updates
wv.onStateUpdate(callback: (state: OWGState) => void): OWGUnsubscribeFn

// Send a user action back to the agent
await wv.sendAction(actionId, type, value, metadata?)
await wv.approve(actionId)
await wv.reject(actionId)
```

## Notes

- The SDK requires a browser environment (`window`, `WebSocket`, `SubtleCrypto`) at runtime.
- Importing in Node.js for type-checking or bundling is safe — only `connect()` needs a browser.
- Version is kept in sync with the Python `openwebgoggles` package on PyPI.

## License

Apache-2.0
