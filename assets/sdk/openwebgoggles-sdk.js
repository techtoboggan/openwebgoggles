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
    return "xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx".replace(/[xy]/g, function (c) {
      var r = (Math.random() * 16) | 0;
      return (c === "x" ? r : (r & 0x3) | 0x8).toString(16);
    });
  }

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
    this._listeners = {};
    this._actionQueue = [];
    this._publicKey = null;       // Ed25519 public key hex from bootstrap
    this._verifyKey = null;       // CryptoKey for Ed25519 verification (async import)
    this._seenNonces = {};        // replay protection
    this._nonceWindowMs = 300000; // 5 minute nonce window
    this._cryptoReady = false;    // whether SubtleCrypto HMAC is available
    this._maxMessageSize = 1048576; // 1MB max WS message size
  }

  // --- Event system ---

  OpenWebGoggles.prototype.on = function (event, callback) {
    if (!this._listeners[event]) this._listeners[event] = [];
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

  OpenWebGoggles.prototype.onStateUpdate = function (callback) {
    return this.on("state_updated", callback);
  };

  OpenWebGoggles.prototype.onManifestUpdate = function (callback) {
    return this.on("manifest_updated", callback);
  };

  // --- Connection ---

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

      return self;
    });
  };

  OpenWebGoggles.prototype.disconnect = function () {
    this._connected = false;
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

  OpenWebGoggles.prototype.isConnected = function () {
    return this._connected;
  };

  // --- State accessors ---

  OpenWebGoggles.prototype.getState = function () {
    return this._state;
  };

  OpenWebGoggles.prototype.getStatus = function () {
    return this._state ? this._state.status : null;
  };

  OpenWebGoggles.prototype.getData = function () {
    return this._state ? this._state.data : null;
  };

  OpenWebGoggles.prototype.getRequestedActions = function () {
    return this._state ? this._state.actions_requested || [] : [];
  };

  OpenWebGoggles.prototype.getManifest = function () {
    return this._manifest;
  };

  // --- Actions (Webview -> Agent) ---

  // --- Crypto helpers ---

  OpenWebGoggles.prototype._pruneNonces = function () {
    var cutoff = Date.now() - this._nonceWindowMs;
    var nonces = this._seenNonces;
    for (var n in nonces) {
      if (nonces.hasOwnProperty(n) && nonces[n] < cutoff) {
        delete nonces[n];
      }
    }
  };

  OpenWebGoggles.prototype._generateNonce = function () {
    // Timestamp + random for uniqueness
    var ts = Date.now().toString(16);
    var rand = "";
    for (var i = 0; i < 16; i++) {
      rand += Math.floor(Math.random() * 16).toString(16);
    }
    return ts + rand;
  };

  OpenWebGoggles.prototype._sendWsSigned = function (message) {
    if (!this._ws || this._ws.readyState !== WebSocket.OPEN) return;
    var self = this;
    var payload = JSON.stringify(message);
    var nonce = this._generateNonce();

    // Sign with HMAC-SHA256 using session token if SubtleCrypto available
    if (typeof crypto !== "undefined" && crypto.subtle && this._token) {
      var encoder = new TextEncoder();
      crypto.subtle.importKey(
        "raw", encoder.encode(this._token),
        { name: "HMAC", hash: "SHA-256" }, false, ["sign"]
      ).then(function (key) {
        return crypto.subtle.sign("HMAC", key, encoder.encode(nonce + payload));
      }).then(function (sigBuf) {
        var sigArr = new Uint8Array(sigBuf);
        var sigHex = "";
        for (var i = 0; i < sigArr.length; i++) {
          sigHex += ("0" + sigArr[i].toString(16)).slice(-2);
        }
        self._ws.send(JSON.stringify({ nonce: nonce, sig: sigHex, p: message }));
      }).catch(function () {
        // Fallback: send unsigned (degraded security)
        console.warn("OpenWebGoggles: HMAC signing failed, sending unsigned message");
        self._ws.send(JSON.stringify(message));
      });
    } else {
      // No SubtleCrypto: send unsigned (degraded security)
      console.warn("OpenWebGoggles: SubtleCrypto unavailable, sending unsigned message (HMAC disabled)");
      this._ws.send(JSON.stringify(message));
    }
  };

  OpenWebGoggles.prototype.sendAction = function (actionId, type, value, metadata) {
    var action = {
      action_id: actionId,
      type: type,
      value: value,
    };
    if (metadata) action.metadata = metadata;

    // Send via WebSocket if connected (signed), otherwise via HTTP
    if (this._ws && this._ws.readyState === WebSocket.OPEN) {
      this._sendWsSigned({ type: "action", data: action });
      return Promise.resolve();
    } else {
      return this._postAction(action);
    }
  };

  OpenWebGoggles.prototype.approve = function (actionId, metadata) {
    return this.sendAction(actionId, "approve", true, metadata);
  };

  OpenWebGoggles.prototype.reject = function (actionId, metadata) {
    return this.sendAction(actionId, "reject", false, metadata);
  };

  OpenWebGoggles.prototype.submitInput = function (actionId, value, metadata) {
    return this.sendAction(actionId, "input", value, metadata);
  };

  OpenWebGoggles.prototype.selectOption = function (actionId, value, metadata) {
    return this.sendAction(actionId, "select", value, metadata);
  };

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
    var message = encoder.encode(nonce + payloadStr);
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
      // Flush queued actions (signed)
      while (self._actionQueue.length > 0) {
        var action = self._actionQueue.shift();
        self._sendWsSigned({ type: "action", data: action });
      }
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
          // No verify key or no ps field: nonce already recorded, accept message
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
        if (msg.state) {
          this._state = msg.state;
          this._emit("state_updated", msg.state);
        }
        break;
      case "state_updated":
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
          if (data && data.version !== (self._state ? self._state.version : -1)) {
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

  OpenWebGoggles.formatTimestamp = function (isoString) {
    if (!isoString) return "";
    var d = new Date(isoString);
    return d.toLocaleString();
  };

  return OpenWebGoggles;
});
