"use strict";
// MCP Apps PostMessage transport adapter (AppBridge protocol).
// Implements the same interface as OpenWebGoggles SDK (connect, on, sendAction,
// getState, getManifest) but communicates via JSON-RPC 2.0 over postMessage
// with the MCP Apps host per the 2026-01-26 specification.
//
// Protocol reference: https://apps.extensions.modelcontextprotocol.io
//
// Notification methods (Host → View):
//   ui/notifications/tool-input          — full tool arguments
//   ui/notifications/tool-input-partial   — streaming partial arguments
//   ui/notifications/tool-result          — tool result with structuredContent
//   ui/notifications/tool-cancelled       — tool invocation cancelled
//   ui/notifications/host-context-changed — theme/display mode changes
//   ui/resource-teardown                  — host is tearing down the resource
//
// Request methods (View → Host):
//   ui/initialize      — handshake (capabilities exchange)
//   tools/call         — invoke server tool (e.g. _owg_action)
//   ui/open-link       — request host to open a URL
//   ui/message         — send a user message
//
// Security: Uses origin pinning per MCP spec — the first handshake uses "*",
// then all subsequent messages are validated against the discovered host origin.
// Also validates event.source === window.parent on every message.

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
    this._hostContext = null;
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
        version: "0.13.1"
      },
      capabilities: {},
      appCapabilities: {
        tools: { listChanged: false },
        availableDisplayModes: ["inline"]
      }
    }).then(function (result) {
      self._initialized = true;
      self._connected = true;

      // Store host context for later reference
      if (result && result.hostContext) {
        self._hostContext = result.hostContext;

        // Apply host theme if provided
        if (result.hostContext.theme) {
          self._applyHostTheme(result.hostContext.theme);
        }

        // Apply host CSS variables if provided
        if (result.hostContext.styles && result.hostContext.styles.variables) {
          self._applyHostStyles(result.hostContext.styles.variables);
        }
      }

      // Initial state may come via the initialize result or via a
      // subsequent tool-result notification — emit connected either way
      self._emit("connected", { state: self._state });
      return self;
    }).catch(function (err) {
      // If ui/initialize isn't supported, still try to work
      console.warn("MCPAppsTransport: ui/initialize failed, continuing anyway:", err);
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

  MCPAppsTransport.prototype._sendNotification = function (method, params) {
    var targetOrigin = this._pinnedOrigin || "*";
    window.parent.postMessage({
      jsonrpc: "2.0",
      method: method,
      params: params || {}
    }, targetOrigin);
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
      // Handle incoming requests from the host (have both id and method)
      if (data.method) {
        this._handleHostRequest(data);
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
    // ── AppBridge spec: ui/notifications/tool-input ──────────────────────────
    // Full tool arguments delivered after initialization.
    // State is in params.arguments.state (our webview tool's state argument).
    if (method === "ui/notifications/tool-input") {
      var inputState = params && params.arguments && params.arguments.state;
      if (inputState) {
        if (this._isStateDowngrade(inputState)) return;
        this._state = inputState;
        this._emit("state_updated", inputState);
      }
      return;
    }

    // ── AppBridge spec: ui/notifications/tool-input-partial ──────────────────
    // Streaming partial arguments (best-effort JSON recovery).
    if (method === "ui/notifications/tool-input-partial") {
      var partialState = params && params.arguments && params.arguments.state;
      if (partialState) {
        // Don't version-check partials — they're incremental
        this._state = partialState;
        this._emit("state_updated", partialState);
      }
      return;
    }

    // ── AppBridge spec: ui/notifications/tool-result ─────────────────────────
    // Tool result with structuredContent — the primary state delivery mechanism.
    if (method === "ui/notifications/tool-result") {
      var content = params && params.structuredContent;
      if (content) {
        if (this._isStateDowngrade(content)) return;
        this._state = content;
        this._emit("state_updated", content);
      }
      return;
    }

    // ── AppBridge spec: ui/notifications/host-context-changed ────────────────
    // Theme changes, display mode changes, container dimension changes.
    if (method === "ui/notifications/host-context-changed") {
      if (params) {
        // Merge into stored host context
        if (this._hostContext) {
          for (var key in params) {
            if (Object.prototype.hasOwnProperty.call(params, key)) {
              this._hostContext[key] = params[key];
            }
          }
        } else {
          this._hostContext = params;
        }
        if (params.theme) {
          this._applyHostTheme(params.theme);
        }
        if (params.styles && params.styles.variables) {
          this._applyHostStyles(params.styles.variables);
        }
      }
      return;
    }

    // ── AppBridge spec: ui/notifications/tool-cancelled ──────────────────────
    // Tool invocation was cancelled by the host.
    if (method === "ui/notifications/tool-cancelled") {
      this._emit("close", { message: (params && params.reason) || "Tool cancelled" });
      return;
    }

    // ── Standard MCP: ping ──────────────────────────────────────────────────
    // Keep-alive ping from host — respond immediately.
    // Note: pings have an id, so they'll be handled in _handleHostRequest
    // if they come as requests. This catches notification-style pings.

    // Unknown notification — log for debugging
    if (method.indexOf("ui/") === 0 || method.indexOf("notifications/") === 0) {
      console.debug("MCPAppsTransport: Unhandled notification:", method);
    }
  };

  // Handle incoming requests from the host (messages with both id and method)
  MCPAppsTransport.prototype._handleHostRequest = function (data) {
    var method = data.method;
    var id = data.id;

    // ── AppBridge spec: ping ────────────────────────────────────────────────
    if (method === "ping") {
      this._sendResponse(id, {});
      return;
    }

    // ── AppBridge spec: ui/resource-teardown ─────────────────────────────────
    // Host is tearing down the resource — clean up and respond.
    if (method === "ui/resource-teardown") {
      this._emit("close", { message: (data.params && data.params.reason) || "Resource teardown" });
      this._sendResponse(id, {});
      return;
    }

    // Unknown request — respond with error
    this._sendResponse(id, null, { code: -32601, message: "Method not found: " + method });
  };

  MCPAppsTransport.prototype._sendResponse = function (id, result, error) {
    var targetOrigin = this._pinnedOrigin || "*";
    var msg = { jsonrpc: "2.0", id: id };
    if (error) {
      msg.error = error;
    } else {
      msg.result = result;
    }
    window.parent.postMessage(msg, targetOrigin);
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

  MCPAppsTransport.prototype._applyHostStyles = function (variables) {
    // Apply host CSS custom properties for visual integration
    if (!variables || typeof variables !== "object") return;
    var style = document.documentElement.style;
    for (var name in variables) {
      if (Object.prototype.hasOwnProperty.call(variables, name)) {
        // Only apply CSS custom properties (--prefixed)
        if (name.indexOf("--") === 0) {
          style.setProperty(name, variables[name]);
        }
      }
    }
  };

  // Notify host when our content size changes
  MCPAppsTransport.prototype.notifySizeChanged = function (width, height) {
    this._sendNotification("ui/notifications/size-changed", {
      width: width,
      height: height
    });
  };

  OWG.MCPAppsTransport = MCPAppsTransport;
})(window.OWG || (window.OWG = Object.create(null)));
