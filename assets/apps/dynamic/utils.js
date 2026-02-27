"use strict";
// Shared utilities for the dynamic renderer.
// Provides escaping, sanitization, markdown, CSS injection, and className helpers.

(function (OWG) {
  // ─── HTML escaping ──────────────────────────────────────────────────────────
  OWG.esc = function (s) {
    return String(s == null ? "" : s)
      .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
  };

  OWG.escAttr = function (s) {
    return String(s == null ? "" : s)
      .replace(/&/g, "&amp;").replace(/'/g, "&#39;").replace(/"/g, "&quot;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
  };

  // ─── className validation ───────────────────────────────────────────────────
  var SAFE_CLASS_RE = /^[a-zA-Z][a-zA-Z0-9_ -]*$/;
  OWG.safeClass = function (cls) {
    return (typeof cls === "string" && cls && SAFE_CLASS_RE.test(cls)) ? " " + cls : "";
  };

  // ─── Status badge class ─────────────────────────────────────────────────────
  OWG.statusBadgeClass = function (s) {
    s = (s || "").toLowerCase();
    if (s.includes("error") || s.includes("fail") || s.includes("reject")) return "badge-danger";
    if (s.includes("warn") || s.includes("pending") || s.includes("review")) return "badge-warn";
    if (s.includes("ok") || s.includes("success") || s.includes("approv") || s.includes("done") || s.includes("complete")) return "badge-ok";
    return "badge-info";
  };

  // ─── Custom CSS injection ───────────────────────────────────────────────────
  var _customStyleEl = null;
  var DANGEROUS_CSS_RE = [
    /expression\s*\(/i,
    /-moz-binding\s*:/i,
    /behavior\s*:\s*url\s*\(/i,
    /@import/i,
    /@charset/i,
    /@namespace/i,
    /@font-face/i,                   // Font exfiltration via unicode-range
    /url\s*\(/i,                     // Block ALL url() — prevents data exfiltration
    /\\u00[0-9a-fA-F]{2}/,          // Unicode escape obfuscation
    /\\[0-9a-fA-F]{1,6}/,           // CSS hex escape obfuscation
  ];

  OWG.isCSSSafe = function (css) {
    if (typeof css !== "string") return false;
    for (var i = 0; i < DANGEROUS_CSS_RE.length; i++) {
      if (DANGEROUS_CSS_RE[i].test(css)) return false;
    }
    return true;
  };

  /**
   * Scope CSS rules to #content so custom_css cannot affect security-critical
   * elements (header, connection indicator, session badge, validation errors).
   */
  function _scopeCSS(css) {
    // Prepend #content to each rule selector. Handles commas in selectors.
    return css.replace(
      /([^{}@]+)\{/g,
      function (match, selectors) {
        var scoped = selectors
          .split(",")
          .map(function (s) {
            s = s.trim();
            return s ? "#content " + s : s;
          })
          .join(", ");
        return scoped + " {";
      }
    );
  }

  OWG.injectCustomCSS = function (css) {
    if (!_customStyleEl) {
      _customStyleEl = document.createElement("style");
      _customStyleEl.setAttribute("data-owg", "custom");
      document.head.appendChild(_customStyleEl);
    }
    if (css && OWG.isCSSSafe(css)) {
      _customStyleEl.textContent = _scopeCSS(css);
    } else {
      _customStyleEl.textContent = "";
    }
  };

  // ─── Markdown rendering (opt-in) ────────────────────────────────────────────
  var PURIFY_CONFIG = {
    ALLOWED_TAGS: [
      "h1", "h2", "h3", "h4", "h5", "h6", "p", "br", "hr",
      "ul", "ol", "li", "strong", "em", "b", "i", "code", "pre",
      "blockquote", "a", "table", "thead", "tbody", "tr", "th", "td",
      "del", "sup", "sub", "span", "div", "details", "summary"
    ],
    ALLOWED_ATTR: ["href", "class"],
    ALLOW_DATA_ATTR: false,
    RETURN_TRUSTED_TYPE: false
  };

  var _purifyHookInstalled = false;
  function _ensurePurifyHook() {
    if (_purifyHookInstalled || typeof DOMPurify === "undefined") return;
    DOMPurify.addHook("afterSanitizeAttributes", function (node) {
      if (node.tagName === "A") {
        node.setAttribute("target", "_blank");
        node.setAttribute("rel", "noopener noreferrer");
      }
    });
    _purifyHookInstalled = true;
  }

  OWG.renderMarkdown = function (text) {
    if (typeof marked === "undefined" || typeof DOMPurify === "undefined") {
      return OWG.esc(text);
    }
    _ensurePurifyHook();
    var rawHTML = marked.parse(String(text || ""));
    return DOMPurify.sanitize(rawHTML, PURIFY_CONFIG);
  };

  OWG.markdownBlock = function (text) {
    return '<div class="markdown-content">' + OWG.renderMarkdown(text) + "</div>";
  };

  // ─── Defense-in-depth HTML sanitizer ────────────────────────────────────────
  var DANGEROUS_TAGS = /^(script|style|iframe|object|embed|form|meta|link|base|svg|math|template|noscript|xmp)$/i;
  var EVENT_ATTR_RE = /^on/i;
  var DANGEROUS_URL_RE = /^\s*(javascript|data\s*:|vbscript)\s*:/i;
  var SAFE_URL_PROTOCOL_RE = /^(https?:|mailto:|#|\/)/i;

  function sanitizeHTML(html) {
    try {
      var doc = new DOMParser().parseFromString(html, "text/html");
      cleanNode(doc.body);
      return doc.body.innerHTML;
    } catch (e) {
      return OWG.esc(html);
    }
  }

  function cleanNode(node) {
    var children = Array.prototype.slice.call(node.childNodes);
    for (var i = 0; i < children.length; i++) {
      var child = children[i];
      if (child.nodeType === 1) {
        if (DANGEROUS_TAGS.test(child.tagName)) {
          child.remove();
          continue;
        }
        var attrs = Array.prototype.slice.call(child.attributes);
        for (var j = 0; j < attrs.length; j++) {
          var name = attrs[j].name.toLowerCase();
          if (EVENT_ATTR_RE.test(name)) {
            child.removeAttribute(attrs[j].name);
          } else if (name === "href" || name === "src" || name === "action" || name === "formaction" || name === "xlink:href") {
            var val = attrs[j].value;
            if (DANGEROUS_URL_RE.test(val) || !SAFE_URL_PROTOCOL_RE.test(val.trim())) {
              child.removeAttribute(attrs[j].name);
            }
          }
        }
        cleanNode(child);
      }
    }
  }

  OWG.sanitizeHTML = sanitizeHTML;

  OWG.safeHTML = function (el, html) {
    el.innerHTML = sanitizeHTML(html);
  };

  // ─── ANSI color support (for log sections) ─────────────────────────────────
  // Converts basic ANSI escape codes to safe HTML spans with balanced open/close.
  OWG.escAnsi = function (escapedText) {
    // Input MUST be already HTML-escaped via esc(). ANSI codes use \u001b which
    // survives esc() since it's not an HTML special char.
    var openCount = 0;
    var ANSI_MAP = {
      "\u001b[31m": "ansi-red",
      "\u001b[32m": "ansi-green",
      "\u001b[33m": "ansi-yellow",
      "\u001b[34m": "ansi-blue",
      "\u001b[1m": "ansi-bold",
      "\u001b[2m": "ansi-dim",
    };
    var result = escapedText.replace(/\u001b\[([0-9;]*)m/g, function (match, code) {
      if (ANSI_MAP[match]) {
        openCount++;
        return '<span class="' + ANSI_MAP[match] + '">';
      }
      if (match === "\u001b[0m" && openCount > 0) {
        openCount--;
        return "</span>";
      }
      // Strip unrecognized codes and excess resets
      return "";
    });
    // Close any remaining open spans
    while (openCount-- > 0) result += "</span>";
    return result;
  };

})(window.OWG = window.OWG || {});
