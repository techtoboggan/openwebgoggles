"use strict";
// MCP Apps PostMessage transport adapter.
// Implements the same interface as OpenWebGoggles SDK (connect, on, sendAction,
// getState, getManifest) but communicates via postMessage JSON-RPC with the
// MCP Apps host instead of WebSocket/HTTP to a localhost server.
//
// Security: Uses origin pinning per MCP spec — the first handshake uses "*",
// then all subsequent messages are validated against the discovered host origin.
// Also validates event.source === window.parent on every message.
//
// Used when the app runs inside a host iframe (Claude Desktop, VS Code, etc.).

(function (OWG) {
  // Guard: only define if OWG namespace exists (loaded after utils.js)
  if (!OWG) return;

  function MCPAppsTransport() {
    this._listeners = Object.create(null);
    this._state = null;
    this._connected = false;
    this._requestId = 0;
    this._pendingRequests = Object.create(null);
    this._initialized = false;
    // Origin pinning — discovered from host's first valid response
    this._pinnedOrigin = null;
  }

  MCPAppsTransport.prototype.connect = function () {
    var self = this;

    // Listen for postMessage from host — with origin + source validation
    window.addEventListener("message", function (event) {
      // Source validation: only accept messages from our direct parent
      if (event.source !== window.parent) return;

      // Origin validation: after pinning, reject mismatched origins
      if (self._pinnedOrigin !== null && event.origin !== self._pinnedOrigin) {
        console.warn("MCPAppsTransport: Rejected message from unexpected origin:", event.origin);
        return;
      }

      if (event.data && typeof event.data === "object") {
        // Pin origin on first valid JSON-RPC response from host
        if (self._pinnedOrigin === null && event.data.jsonrpc === "2.0") {
          self._pinnedOrigin = event.origin;
        }
        self._handleMessage(event.data);
      }
    });

    // Send ui/initialize handshake to host — first message uses "*" because
    // we don't know the parent origin yet (per MCP spec)
    return this._sendRequest("ui/initialize", {
      protocolVersion: "2026-01-26",
      clientInfo: {
        name: "OpenWebGoggles",
        version: "0.14.0"
      },
      capabilities: {}
    }).then(function (result) {
      self._initialized = true;
      self._connected = true;

      // Apply host theme if provided
      if (result && result.hostContext && result.hostContext.theme) {
        self._applyHostTheme(result.hostContext.theme);
      }

      // Initial state may come via the initialize result or via a
      // subsequent notification — emit connected either way
      self._emit("connected", { state: self._state });
      return self;
    }).catch(function (err) {
      // If ui/initialize isn't supported, still try to work
      self._connected = true;
      self._emit("connected", { state: self._state });
      return self;
    });
  };

  MCPAppsTransport.prototype.on = function (event, callback) {
    if (typeof callback !== "function") return;
    if (!this._listeners[event]) this._listeners[event] = [];
    if (this._listeners[event].length >= 100) return;
    this._listeners[event].push(callback);
  };

  MCPAppsTransport.prototype.sendAction = function (actionId, type, value, metadata) {
    var args = {
      action_id: actionId,
      action_type: type,
      value: value
    };
    if (metadata && metadata.context) {
      args.context = metadata.context;
    }

    // Call the server's _owg_action tool via the host's tool proxy
    return this._sendRequest("tools/call", {
      name: "_owg_action",
      arguments: args
    }).then(function (result) {
      return result;
    });
  };

  MCPAppsTransport.prototype.getState = function () {
    return this._state;
  };

  MCPAppsTransport.prototype.getManifest = function () {
    return null; // No manifest in MCP Apps mode
  };

  MCPAppsTransport.prototype.isConnected = function () {
    return this._connected;
  };

  MCPAppsTransport.prototype.disconnect = function () {
    this._connected = false;
  };

  // ─── Internal: postMessage JSON-RPC ────────────────────────────────────────

  MCPAppsTransport.prototype._sendRequest = function (method, params) {
    var id = ++this._requestId;
    var self = this;
    return new Promise(function (resolve, reject) {
      self._pendingRequests[id] = { resolve: resolve, reject: reject };

      // Set a 30s timeout per request
      var timer = setTimeout(function () {
        if (Object.prototype.hasOwnProperty.call(self._pendingRequests, id)) {
          delete self._pendingRequests[id];
          reject(new Error("Request timed out: " + method));
        }
      }, 30000);
      self._pendingRequests[id].timer = timer;

      // Use pinned origin when available, "*" only for the initial handshake
      var targetOrigin = self._pinnedOrigin || "*";
      window.parent.postMessage({
        jsonrpc: "2.0",
        id: id,
        method: method,
        params: params || {}
      }, targetOrigin);
    });
  };

  MCPAppsTransport.prototype._handleMessage = function (data) {
    // Ignore non-JSON-RPC messages
    if (data.jsonrpc !== "2.0") return;

    // Handle responses to our requests
    if (data.id !== undefined && data.id !== null) {
      var pending = this._pendingRequests[data.id];
      if (pending) {
        delete this._pendingRequests[data.id];
        if (pending.timer) clearTimeout(pending.timer);
        if (data.error) {
          pending.reject(data.error);
        } else {
          pending.resolve(data.result);
        }
      }
      return;
    }

    // Handle notifications from host (no id field)
    if (data.method) {
      this._handleNotification(data.method, data.params || {});
    }
  };

  MCPAppsTransport.prototype._isStateDowngrade = function (newState) {
    // Version monotonicity: reject state with version <= current (prevents replay/downgrade)
    if (newState && this._state &&
        typeof newState.version === "number" && typeof this._state.version === "number" &&
        newState.version <= this._state.version) {
      console.warn("MCPAppsTransport: Rejected state downgrade (v" + newState.version + " <= v" + this._state.version + ")");
      return true;
    }
    return false;
  };

  MCPAppsTransport.prototype._handleNotification = function (method, params) {
    // State delivered via tool input/result notifications
    if (method === "notifications/tools/input" || method === "ui/toolInput") {
      var inputState = params && params.arguments && params.arguments.state;
      if (inputState) {
        if (this._isStateDowngrade(inputState)) return;
        this._state = inputState;
        this._emit("state_updated", inputState);
      }
      return;
    }

    if (method === "notifications/tools/result" || method === "ui/toolResult") {
      var content = params && params.structuredContent;
      if (content) {
        if (this._isStateDowngrade(content)) return;
        this._state = content;
        this._emit("state_updated", content);
      }
      return;
    }

    // Host context updates (theme changes, etc.)
    if (method === "ui/context") {
      if (params && params.theme) {
        this._applyHostTheme(params.theme);
      }
      return;
    }

    // Close notification
    if (method === "ui/close" || method === "notifications/cancelled") {
      this._emit("close", { message: (params && params.reason) || "Session closed" });
      return;
    }
  };

  MCPAppsTransport.prototype._emit = function (event, data) {
    var cbs = this._listeners[event];
    if (!cbs) return;
    for (var i = 0; i < cbs.length; i++) {
      try {
        cbs[i](data);
      } catch (e) {
        console.error("MCPAppsTransport event handler error:", e);
      }
    }
  };

  MCPAppsTransport.prototype._applyHostTheme = function (theme) {
    // Map host theme to our CSS variables
    if (theme === "dark" || (theme && theme.colorScheme === "dark")) {
      document.body.removeAttribute("data-theme");
    } else if (theme === "light" || (theme && theme.colorScheme === "light")) {
      document.body.setAttribute("data-theme", "light");
    }
  };

  // Notify host when our content size changes
  MCPAppsTransport.prototype.notifySizeChanged = function (width, height) {
    var targetOrigin = this._pinnedOrigin || "*";
    window.parent.postMessage({
      jsonrpc: "2.0",
      method: "ui/notifications/size-changed",
      params: { width: width, height: height }
    }, targetOrigin);
  };

  OWG.MCPAppsTransport = MCPAppsTransport;
})(window.OWG || (window.OWG = Object.create(null)));
