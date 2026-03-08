/**
 * OpenWebGoggles SDK
 *
 * Vanilla JS client library for connecting browser-based webview apps
 * to the OpenCode CLI agent via WebSocket (primary) and HTTP polling (fallback).
 *
 * Usage:
 *   <script src="/sdk/openwebgoggles-sdk.js"></script>
 *   <script>
 *     const wv = new OpenWebGoggles();
 *     wv.connect().then(() => {
 *       wv.onStateUpdate((state) => renderUI(state));
 *     });
 *   </script>
 */
(function (root, factory) {
  if (typeof define === "function" && define.amd) {
    define([], factory);
  } else if (typeof module === "object" && module.exports) {
    module.exports = factory();
  } else {
    root.OpenWebGoggles = factory();
  }
})(typeof self !== "undefined" ? self : this, function () {
  "use strict";

  function uuid() {
    if (typeof crypto !== "undefined" && crypto.getRandomValues) {
      var buf = new Uint8Array(16);
      crypto.getRandomValues(buf);
      buf[6] = (buf[6] & 0x0f) | 0x40;
      buf[8] = (buf[8] & 0x3f) | 0x80;
      var hex = "";
      for (var i = 0; i < 16; i++) hex += ("0" + buf[i].toString(16)).slice(-2);
      return hex.slice(0,8)+"-"+hex.slice(8,12)+"-"+hex.slice(12,16)+"-"+hex.slice(16,20)+"-"+hex.slice(20);
    }
    return "xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx".replace(/[xy]/g, function (c) {
      var r = (Math.random() * 16) | 0;
      return (c === "x" ? r : (r & 0x3) | 0x8).toString(16);
    });
  }

  /**
   * Create a new OpenWebGoggles SDK instance.
   *
   * @param {Object} [options]
   * @param {string} [options.httpUrl] - Base HTTP URL for the webview server (default: window.location.origin)
   * @param {string} [options.wsUrl] - WebSocket URL override (default: derived from manifest)
   * @param {number} [options.pollInterval] - HTTP polling interval in ms when WebSocket unavailable (default: 2000)
   */
  function OpenWebGoggles(options) {
    options = options || {};

    this._httpUrl = options.httpUrl || window.location.origin;
    this._wsUrl = options.wsUrl || null;
    this._pollInterval = options.pollInterval || 2000;
    this._token = null;
    this._manifest = null;
    this._state = null;
    this._ws = null;
    this._connected = false;
    this._useWebSocket = true;
    this._pollTimer = null;
    this._reconnectTimer = null;
    this._reconnectDelay = 1000;
    this._maxReconnectDelay = 30000;
    this._listeners = Object.create(null);
    this._actionQueue = [];
    this._publicKey = null;       // Ed25519 public key hex from bootstrap
    this._verifyKey = null;       // CryptoKey for Ed25519 verification (async import)
    this._seenNonces = Object.create(null); // replay protection — no prototype chain
    this._nonceWindowMs = 300000; // 5 minute nonce window
    this._cryptoReady = false;    // whether SubtleCrypto HMAC is available
    this._maxMessageSize = 1048576; // 1MB max WS message size
    this._authenticated = false;  // set true after WS auth handshake succeeds
  }

  // --- Event system ---

  var MAX_LISTENERS_PER_EVENT = 100;  // Prevent listener accumulation / memory leak

  /**
   * Register a listener for an SDK event.
   * Returns an unsubscribe function — call it to remove the listener.
   * Duplicate registrations of the same callback are silently ignored.
   * At most 100 listeners per event; oldest is removed when the cap is exceeded.
   *
   * @param {string} event - Event name: "connected", "disconnected", "state_updated",
   *   "manifest_updated", "actions_updated", "actions_cleared", "close", "error"
   * @param {Function} callback - Handler called with the event payload
   * @returns {Function} Unsubscribe function
   */
  OpenWebGoggles.prototype.on = function (event, callback) {
    if (!this._listeners[event]) this._listeners[event] = [];
    // Prevent duplicate registration of the same callback
    for (var i = 0; i < this._listeners[event].length; i++) {
      if (this._listeners[event][i] === callback) {
        var self = this;
        return function () {
          self._listeners[event] = self._listeners[event].filter(function (cb) {
            return cb !== callback;
          });
        };
      }
    }
    // Cap listener count to prevent unbounded memory growth
    if (this._listeners[event].length >= MAX_LISTENERS_PER_EVENT) {
      console.warn("OpenWebGoggles: Listener limit reached for '" + event + "' — oldest listener removed");
      this._listeners[event].shift();
    }
    this._listeners[event].push(callback);
    var self = this;
    return function () {
      self._listeners[event] = self._listeners[event].filter(function (cb) {
        return cb !== callback;
      });
    };
  };

  OpenWebGoggles.prototype._emit = function (event, data) {
    var cbs = this._listeners[event] || [];
    for (var i = 0; i < cbs.length; i++) {
      try {
        cbs[i](data);
      } catch (e) {
        console.error("OpenWebGoggles: Error in " + event + " handler:", e);
      }
    }
  };

  // --- Convenience event subscribers ---

  /**
   * Shorthand: listen for state updates. Equivalent to `on("state_updated", callback)`.
   * @param {Function} callback - Receives the new state object
   * @returns {Function} Unsubscribe function
   */
  OpenWebGoggles.prototype.onStateUpdate = function (callback) {
    return this.on("state_updated", callback);
  };

  /**
   * Shorthand: listen for manifest updates. Equivalent to `on("manifest_updated", callback)`.
   * @param {Function} callback - Receives the new manifest object
   * @returns {Function} Unsubscribe function
   */
  OpenWebGoggles.prototype.onManifestUpdate = function (callback) {
    return this.on("manifest_updated", callback);
  };

  // --- Connection ---

  /**
   * Connect to the webview server.
   * Fetches the manifest, bootstraps auth, opens a WebSocket with HTTP polling fallback.
   * Resolves with `this` once the initial state is available.
   * @returns {Promise<OpenWebGoggles>}
   */
  OpenWebGoggles.prototype.connect = function () {
    var self = this;

    // Use server-injected bootstrap data if available (avoids a fetch round-trip)
    var bootstrap = (typeof window !== "undefined" && window.__OCV__) ? window.__OCV__ : null;

    var manifestPromise = bootstrap
      ? Promise.resolve(bootstrap.manifest)
      : this._fetchManifest();

    return manifestPromise.then(function (manifest) {
      self._manifest = manifest;
      self._token = manifest.session.token;
      // Read public key from bootstrap for Ed25519 signature verification
      if (bootstrap && bootstrap.publicKey) {
        self._publicKey = bootstrap.publicKey;
        // Best-effort async import — Ed25519 requires Chrome 130+/Firefox 130+/Safari 17+
        if (typeof crypto !== "undefined" && crypto.subtle && crypto.subtle.importKey) {
          self._importEdPublicKey(bootstrap.publicKey).then(function (key) {
            self._verifyKey = key;
          }).catch(function () {
            // Browser doesn't support Ed25519 yet — nonce replay still guards against replay
          });
        }
      }

      var server = manifest.server || {};
      var host = server.host || "127.0.0.1";
      var wsPort = server.ws_port || 18421;
      if (!self._wsUrl) {
        self._wsUrl = "ws://" + host + ":" + wsPort;
      }

      // Use injected state if available, otherwise fetch
      if (bootstrap && bootstrap.state && bootstrap.state.version !== undefined) {
        return bootstrap.state;
      }
      return self._fetchState();
    }).then(function (state) {
      self._state = state;
      self._connected = true;
      self._emit("connected", { state: state, manifest: self._manifest });

      // Try WebSocket for live updates, fall back to polling
      self._connectWebSocket();

      // Periodic nonce prune to prevent unbounded memory growth in long sessions
      if (self._noncePruneTimer) clearInterval(self._noncePruneTimer);
      self._noncePruneTimer = setInterval(function () {
        self._pruneNonces();
      }, 60000);

      return self;
    });
  };

  /**
   * Disconnect from the server.
   * Closes the WebSocket, stops polling, cancels reconnect timers.
   * Emits the "disconnected" event.
   */
  OpenWebGoggles.prototype.disconnect = function () {
    this._connected = false;
    if (this._noncePruneTimer) {
      clearInterval(this._noncePruneTimer);
      this._noncePruneTimer = null;
    }
    if (this._ws) {
      this._ws.close();
      this._ws = null;
    }
    if (this._pollTimer) {
      clearInterval(this._pollTimer);
      this._pollTimer = null;
    }
    if (this._reconnectTimer) {
      clearTimeout(this._reconnectTimer);
      this._reconnectTimer = null;
    }
    this._emit("disconnected");
  };

  /**
   * Returns true if the SDK has a live connection to the server.
   * @returns {boolean}
   */
  OpenWebGoggles.prototype.isConnected = function () {
    return this._connected;
  };

  // --- State accessors ---

  /**
   * Returns the current full state object, or null before connect.
   * @returns {Object|null}
   */
  OpenWebGoggles.prototype.getState = function () {
    return this._state;
  };

  /**
   * Returns `state.status`, or null before connect.
   * @returns {string|null}
   */
  OpenWebGoggles.prototype.getStatus = function () {
    return this._state ? this._state.status : null;
  };

  /**
   * Returns `state.data`, or null before connect.
   * @returns {Object|null}
   */
  OpenWebGoggles.prototype.getData = function () {
    return this._state ? this._state.data : null;
  };

  /**
   * Returns `state.actions_requested` array, or an empty array before connect.
   * @returns {Array}
   */
  OpenWebGoggles.prototype.getRequestedActions = function () {
    return this._state ? this._state.actions_requested || [] : [];
  };

  /**
   * Returns the server manifest, or null before connect.
   * @returns {Object|null}
   */
  OpenWebGoggles.prototype.getManifest = function () {
    return this._manifest;
  };

  // --- Actions (Webview -> Agent) ---

  OpenWebGoggles.prototype._pruneNonces = function () {
    var cutoff = Date.now() - this._nonceWindowMs;
    var nonces = this._seenNonces;
    for (var n in nonces) {
      if (Object.prototype.hasOwnProperty.call(nonces, n) && nonces[n] < cutoff) {
        delete nonces[n];
      }
    }
  };

  OpenWebGoggles.prototype._generateNonce = function () {
    var ts = Date.now().toString(16);
    var rand = "";
    if (typeof crypto !== "undefined" && crypto.getRandomValues) {
      var buf = new Uint8Array(8);
      crypto.getRandomValues(buf);
      for (var i = 0; i < buf.length; i++) rand += ("0" + buf[i].toString(16)).slice(-2);
    } else {
      for (var j = 0; j < 16; j++) rand += Math.floor(Math.random() * 16).toString(16);
    }
    return ts + rand;
  };

  OpenWebGoggles.prototype._sendWsSigned = function (message) {
    if (!this._ws || this._ws.readyState !== WebSocket.OPEN) return Promise.reject(new Error("WebSocket not open"));
    var self = this;
    var payload = JSON.stringify(message);
    var nonce = this._generateNonce();

    // Sign with HMAC-SHA256 using session token if SubtleCrypto available
    if (typeof crypto !== "undefined" && crypto.subtle && this._token) {
      var encoder = new TextEncoder();
      return crypto.subtle.importKey(
        "raw", encoder.encode(this._token),
        { name: "HMAC", hash: "SHA-256" }, false, ["sign"]
      ).then(function (key) {
        // Null-byte delimiter between nonce and payload for domain separation
        return crypto.subtle.sign("HMAC", key, encoder.encode(nonce + "\0" + payload));
      }).then(function (sigBuf) {
        if (!self._ws || self._ws.readyState !== WebSocket.OPEN) return;
        var sigArr = new Uint8Array(sigBuf);
        var sigHex = "";
        for (var i = 0; i < sigArr.length; i++) {
          sigHex += ("0" + sigArr[i].toString(16)).slice(-2);
        }
        self._ws.send(JSON.stringify({ nonce: nonce, sig: sigHex, p: message }));
      }).catch(function (err) {
        console.error("OpenWebGoggles: HMAC signing failed, message NOT sent:", err);
      });
    } else {
      // Fail-closed: refuse to send unsigned messages (security downgrade prevention)
      console.error("OpenWebGoggles: SubtleCrypto unavailable — message dropped (HMAC required for WS messages)");
      return Promise.reject(new Error("SubtleCrypto unavailable"));
    }
  };

  /**
   * Send an action to the agent.
   * Routes through WebSocket (HMAC-signed) when connected, HTTP otherwise.
   * Actions submitted while the WebSocket is still connecting are queued and flushed after auth.
   *
   * @param {string} actionId - The action button's id
   * @param {string} type - Action type: "approve", "reject", "input", "select", "confirm"
   * @param {*} value - Action payload (true/false for approve/reject, string for input)
   * @param {Object} [metadata] - Optional extra context
   * @returns {Promise}
   */
  OpenWebGoggles.prototype.sendAction = function (actionId, type, value, metadata) {
    var action = {
      action_id: actionId,
      type: type,
      value: value,
    };
    if (metadata) action.metadata = metadata;

    // Queue action if WS is still connecting (flushed when auth completes)
    if (this._ws && this._ws.readyState === WebSocket.CONNECTING) {
      this._actionQueue.push(action);
      return Promise.resolve({ queued: true });
    }

    // Send via WebSocket if connected (signed), otherwise via HTTP
    if (this._ws && this._ws.readyState === WebSocket.OPEN) {
      return this._sendWsSigned({ type: "action", data: action });
    } else {
      return this._postAction(action);
    }
  };

  /**
   * Send an approve action (type="approve", value=true).
   * @param {string} actionId
   * @param {Object} [metadata]
   * @returns {Promise}
   */
  OpenWebGoggles.prototype.approve = function (actionId, metadata) {
    return this.sendAction(actionId, "approve", true, metadata);
  };

  /**
   * Send a reject action (type="reject", value=false).
   * @param {string} actionId
   * @param {Object} [metadata]
   * @returns {Promise}
   */
  OpenWebGoggles.prototype.reject = function (actionId, metadata) {
    return this.sendAction(actionId, "reject", false, metadata);
  };

  /**
   * Send a text input action (type="input").
   * @param {string} actionId
   * @param {*} value
   * @param {Object} [metadata]
   * @returns {Promise}
   */
  OpenWebGoggles.prototype.submitInput = function (actionId, value, metadata) {
    return this.sendAction(actionId, "input", value, metadata);
  };

  /**
   * Send a select action (type="select").
   * @param {string} actionId
   * @param {*} value
   * @param {Object} [metadata]
   * @returns {Promise}
   */
  OpenWebGoggles.prototype.selectOption = function (actionId, value, metadata) {
    return this.sendAction(actionId, "select", value, metadata);
  };

  /**
   * Send a confirm action (type="confirm", value=true).
   * @param {string} actionId
   * @param {Object} [metadata]
   * @returns {Promise}
   */
  OpenWebGoggles.prototype.confirm = function (actionId, metadata) {
    return this.sendAction(actionId, "confirm", true, metadata);
  };

  // --- HTTP methods ---

  OpenWebGoggles.prototype._fetchManifest = function () {
    return this._httpGet("/_api/manifest");
  };

  OpenWebGoggles.prototype._fetchState = function () {
    return this._httpGet("/_api/state");
  };

  OpenWebGoggles.prototype._postAction = function (action) {
    return this._httpPost("/_api/actions", action);
  };

  OpenWebGoggles.prototype._httpGet = function (path) {
    var self = this;
    return fetch(this._httpUrl + path, {
      headers: this._authHeaders(),
    }).then(function (resp) {
      if (resp.status === 304) return self._state;
      if (!resp.ok) throw new Error("HTTP " + resp.status);
      return resp.json();
    });
  };

  OpenWebGoggles.prototype._httpPost = function (path, data) {
    return fetch(this._httpUrl + path, {
      method: "POST",
      headers: Object.assign({ "Content-Type": "application/json" }, this._authHeaders()),
      body: JSON.stringify(data),
    }).then(function (resp) {
      if (!resp.ok) throw new Error("HTTP " + resp.status);
      return resp.json();
    });
  };

  OpenWebGoggles.prototype._authHeaders = function () {
    if (this._token) {
      return { Authorization: "Bearer " + this._token };
    }
    return {};
  };

  // --- Ed25519 signature verification (server → browser) ---

  /**
   * Import an Ed25519 public key from a hex string for use with SubtleCrypto.verify().
   * Requires Chrome 130+, Firefox 130+, or Safari 17+. Returns a Promise<CryptoKey>.
   */
  OpenWebGoggles.prototype._importEdPublicKey = function (hexKey) {
    var bytes = new Uint8Array(hexKey.match(/.{1,2}/g).map(function (b) {
      return parseInt(b, 16);
    }));
    return crypto.subtle.importKey("raw", bytes, { name: "Ed25519" }, false, ["verify"]);
  };

  /**
   * Verify an Ed25519 signature over (nonce + payloadStr).
   * payloadStr must be the exact compact-JSON string that the server signed (raw.ps).
   * Returns a Promise<boolean>.
   */
  OpenWebGoggles.prototype._verifyEdDSA = function (verifyKey, nonce, payloadStr, sigHex) {
    var encoder = new TextEncoder();
    // Null-byte delimiter between nonce and payload for domain separation
    var message = encoder.encode(nonce + "\0" + payloadStr);
    var sigBytes = new Uint8Array(sigHex.match(/.{1,2}/g).map(function (b) {
      return parseInt(b, 16);
    }));
    return crypto.subtle.verify("Ed25519", verifyKey, sigBytes, message);
  };

  // --- WebSocket ---

  OpenWebGoggles.prototype._connectWebSocket = function () {
    if (!this._useWebSocket) {
      this._startPolling();
      return;
    }

    var self = this;
    // First-message auth: connect without token in URL, authenticate via first message
    var url = this._wsUrl;

    try {
      this._ws = new WebSocket(url);
    } catch (e) {
      console.warn("OpenWebGoggles: WebSocket not available, falling back to polling");
      this._useWebSocket = false;
      this._startPolling();
      return;
    }

    this._ws.onopen = function () {
      self._reconnectDelay = 1000;
      // Authenticate with first message (token never in URL)
      self._ws.send(JSON.stringify({ type: "auth", token: self._token }));
      // Stop polling if it was active
      if (self._pollTimer) {
        clearInterval(self._pollTimer);
        self._pollTimer = null;
      }
    };

    this._ws.onmessage = function (event) {
      try {
        // Payload size guard — reject oversized messages
        if (typeof event.data === "string" && event.data.length > self._maxMessageSize) {
          console.error("OpenWebGoggles: Rejected oversized WS message (" + event.data.length + " bytes, max " + self._maxMessageSize + ")");
          return;
        }
        var raw = JSON.parse(event.data);
        // Reject unsigned messages after auth handshake (defense-in-depth)
        if (self._authenticated && !raw.p && !raw.nonce && !raw.sig) {
          console.warn("OpenWebGoggles: Unsigned WS message after auth — skipping");
          return;
        }
        // Unwrap signed envelope if present
        var msg;
        if (raw.p && raw.nonce && raw.sig) {
          // Signed message from server — check nonce for replay first (cheap, synchronous)
          if (self._seenNonces[raw.nonce]) {
            console.warn("OpenWebGoggles: Replayed nonce, ignoring message");
            return;
          }
          // Record nonce before async verification to prevent replay during the await
          self._seenNonces[raw.nonce] = Date.now();
          self._pruneNonces();

          // Ed25519 signature verification — requires _verifyKey (imported async at connect)
          // and ps (compact payload string included by server alongside parsed p).
          if (self._verifyKey && raw.ps) {
            self._verifyEdDSA(self._verifyKey, raw.nonce, raw.ps, raw.sig).then(function (valid) {
              if (!valid) {
                console.error("OpenWebGoggles: Invalid Ed25519 signature — message rejected");
                return;
              }
              self._handleWsMessage(raw.p);
            }).catch(function (e) {
              console.error("OpenWebGoggles: Ed25519 verification error:", e);
            });
            return; // handled asynchronously above
          }
          // Require ps field when verify key is available — reject signed messages missing ps
          if (self._verifyKey && raw.sig && !raw.ps) {
            console.error("OpenWebGoggles: Signed message missing ps field — rejected");
            return;
          }
          // No verify key — if envelope has sig, log a warning
          if (raw.sig) {
            console.warn("OpenWebGoggles: Signed message received but verify key unavailable; accepting with nonce-only protection");
          }
          msg = raw.p;
        } else {
          msg = raw;
        }
        self._handleWsMessage(msg);
      } catch (e) {
        console.error("OpenWebGoggles: Invalid WS message:", e);
      }
    };

    this._ws.onclose = function () {
      self._ws = null;
      if (self._connected) {
        // Start polling as fallback
        self._startPolling();
        // Schedule reconnect with exponential backoff
        self._reconnectTimer = setTimeout(function () {
          if (self._connected) self._connectWebSocket();
        }, self._reconnectDelay);
        self._reconnectDelay = Math.min(self._reconnectDelay * 2, self._maxReconnectDelay);
      }
    };

    this._ws.onerror = function () {
      // onclose will fire after this
    };
  };

  OpenWebGoggles.prototype._handleWsMessage = function (msg) {
    switch (msg.type) {
      case "connected":
        this._authenticated = true;
        // Flush queued actions now that auth is acknowledged (signed)
        while (this._actionQueue.length > 0) {
          var action = this._actionQueue.shift();
          this._sendWsSigned({ type: "action", data: action });
        }
        if (msg.state) {
          this._state = msg.state;
          this._emit("state_updated", msg.state);
        }
        break;
      case "state_updated":
        // Version monotonicity: only accept strictly increasing versions (prevents state downgrade)
        if (msg.data && this._state && typeof msg.data.version === "number" && typeof this._state.version === "number") {
          if (msg.data.version <= this._state.version) {
            console.warn("OpenWebGoggles: Rejected state downgrade (v" + msg.data.version + " <= v" + this._state.version + ")");
            break;
          }
        }
        this._state = msg.data;
        this._emit("state_updated", msg.data);
        break;
      case "manifest_updated":
        this._manifest = msg.data;
        this._emit("manifest_updated", msg.data);
        break;
      case "actions_updated":
        this._emit("actions_updated", msg.data);
        break;
      case "actions_cleared":
        this._emit("actions_cleared", msg.data);
        break;
      case "close":
        this._emit("close", msg.data || {});
        // Auto-close the window after a short delay so the app can show a farewell state
        var delay = (msg.data && msg.data.delay_ms) ? msg.data.delay_ms : 1500;
        delay = Math.max(500, Math.min(delay, 10000));
        setTimeout(function () { window.close(); }, delay);
        break;
      case "heartbeat_ack":
        break;
      case "error":
        this._emit("error", msg);
        break;
    }
  };

  // --- HTTP Polling fallback ---

  OpenWebGoggles.prototype._startPolling = function () {
    if (this._pollTimer) return;

    var self = this;
    this._pollTimer = setInterval(function () {
      if (!self._connected) {
        clearInterval(self._pollTimer);
        self._pollTimer = null;
        return;
      }

      var sinceVersion = self._state ? self._state.version : 0;
      fetch(self._httpUrl + "/_api/state?since_version=" + sinceVersion, {
        headers: self._authHeaders(),
      })
        .then(function (resp) {
          if (resp.status === 304) return null;
          if (!resp.ok) return null;
          return resp.json();
        })
        .then(function (data) {
          // Version monotonicity: only accept strictly increasing versions
          var currentVersion = self._state ? self._state.version : -1;
          if (data && typeof data.version === "number" && data.version > currentVersion) {
            self._state = data;
            self._emit("state_updated", data);
          }
        })
        .catch(function () {
          // Silently ignore polling errors
        });
    }, this._pollInterval);
  };

  // --- Utility helpers ---

  /**
   * Format an ISO 8601 timestamp string into a locale-aware display string.
   * Returns an empty string if the input is falsy or unparseable.
   * @param {string} isoString - ISO 8601 timestamp
   * @returns {string}
   */
  OpenWebGoggles.formatTimestamp = function (isoString) {
    if (!isoString) return "";
    var d = new Date(isoString);
    return d.toLocaleString();
  };

  return OpenWebGoggles;
});
