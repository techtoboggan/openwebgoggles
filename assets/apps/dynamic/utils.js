"use strict";
// Shared utilities for the dynamic renderer.
// Provides escaping, sanitization, markdown, CSS injection, and className helpers.

(function (OWG) {
  // ─── HTML escaping ──────────────────────────────────────────────────────────
  OWG.esc = function (s) {
    return String(s == null ? "" : s)
      .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#39;");
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
    /@keyframes/i,                   // Global animation names bypass CSS scoping
    /@media/i,                       // @media bypasses CSS scoping (unscoped selectors inside block)
    /@supports/i,                    // Feature queries can probe browser state
    /@layer/i,                       // Cascade layer manipulation
    /url\s*\(/i,                     // Block ALL url() — prevents data exfiltration
    /\\/,                            // Block ALL backslash escapes — non-hex escapes bypass keyword patterns
    /\/\*/,                          // CSS comments can split keywords (e.g. ur/**/l())
    /[\u200b-\u200f\u202a-\u202e\u2060-\u2069\ufeff]/,  // zero-width / bidi chars
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
  // NOTE: Do NOT include input/button/select/textarea here — those are generated
  // by our own renderers (forms, actions) with esc()/escAttr() applied.  Stripping
  // them breaks the entire UI.  Markdown content goes through DOMPurify separately.
  //
  // SVG is allowed because charts.js generates safe data-driven SVG from validated
  // numeric data (all text via esc(), all attrs via escAttr()).  Dangerous SVG
  // children (script, foreignObject, use, etc.) are stripped by DANGEROUS_SVG_TAGS
  // while safe structural elements are allowlisted by SAFE_SVG_TAGS.
  var DANGEROUS_TAGS = /^(script|style|iframe|object|embed|form|meta|link|base|math|template|noscript|xmp)$/i;
  var DANGEROUS_SVG_TAGS = /^(script|foreignobject|use|set|handler|listener|animate|animatetransform|animatemotion)$/i;
  var SAFE_SVG_TAGS = /^(svg|g|rect|circle|ellipse|line|polyline|polygon|path|text|tspan|defs|clippath|lineargradient|radialgradient|stop)$/i;
  var EVENT_ATTR_RE = /^on/i;
  var DANGEROUS_URL_RE = /^\s*(javascript|data|vbscript)\s*:/i;
  var SAFE_URL_PROTOCOL_RE = /^(https?:|mailto:|#|\/[^\/])/i;

  function sanitizeHTML(html) {
    try {
      var doc = new DOMParser().parseFromString(html, "text/html");
      cleanNode(doc.body, false);
      return doc.body.innerHTML;
    } catch (e) {
      return OWG.esc(html);
    }
  }

  function cleanNode(node, inSVG) {
    var children = Array.prototype.slice.call(node.childNodes);
    for (var i = 0; i < children.length; i++) {
      var child = children[i];
      if (child.nodeType === 1) {
        var tag = (child.tagName || "").toLowerCase();
        if (inSVG) {
          // Inside SVG: strip known-dangerous SVG elements
          if (DANGEROUS_SVG_TAGS.test(tag)) {
            child.remove();
            continue;
          }
          // Only allow known-safe SVG elements
          if (!SAFE_SVG_TAGS.test(tag)) {
            child.remove();
            continue;
          }
        } else if (DANGEROUS_TAGS.test(tag)) {
          child.remove();
          continue;
        }
        // Strip event handler attributes and dangerous URLs
        var attrs = Array.prototype.slice.call(child.attributes);
        for (var j = 0; j < attrs.length; j++) {
          var name = attrs[j].name.toLowerCase();
          if (EVENT_ATTR_RE.test(name)) {
            child.removeAttribute(attrs[j].name);
          } else if (name === "id" || name === "name") {
            child.removeAttribute(attrs[j].name);
          } else if (name === "href" || name === "src" || name === "action" || name === "formaction" || name === "xlink:href") {
            var val = attrs[j].value;
            if (DANGEROUS_URL_RE.test(val) || !SAFE_URL_PROTOCOL_RE.test(val.trim())) {
              child.removeAttribute(attrs[j].name);
            }
          }
        }
        // Track SVG context: once inside <svg>, all descendants use SVG rules
        cleanNode(child, inSVG || tag === "svg");
      }
    }
  }

  OWG.sanitizeHTML = sanitizeHTML;

  OWG.safeHTML = function (el, html) {
    el.innerHTML = sanitizeHTML(html);
  };

  // ─── ANSI color support (for log sections) ─────────────────────────────────
  // Converts basic ANSI escape codes to safe HTML spans with balanced open/close.
  var MAX_ANSI_NESTING = 20;  // Cap nesting to prevent DoS via deeply nested ANSI codes

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
        if (openCount >= MAX_ANSI_NESTING) return "";  // Cap nesting depth
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

  // Install DOMPurify hook eagerly at module load time (not lazily on first render)
  // to ensure all markdown renders get target="_blank" and rel="noopener noreferrer"
  _ensurePurifyHook();

  // ─── Plugin DOM builder helper ──────────────────────────────────────────────
  // Provides a safe way for plugins to build HTML without using innerHTML directly.
  // Usage: OWG.h("div", {"class": "my-thing"}, "text content")
  //        OWG.h("ul", {}, [OWG.h("li", {}, "item 1"), OWG.h("li", {}, "item 2")])
  var _SAFE_TAGS = /^(div|span|p|h[1-6]|ul|ol|li|strong|em|code|pre|table|thead|tbody|tr|th|td|button|label|details|summary|hr|br|a|small|sub|sup|dl|dt|dd|blockquote|abbr|time|mark|del|ins|figure|figcaption|section|article|nav|header|footer)$/;
  OWG.h = function (tag, attrs, children) {
    if (!_SAFE_TAGS.test(tag)) return "";
    var html = "<" + tag;
    if (attrs) {
      var akeys = Object.keys(attrs);
      for (var ai = 0; ai < akeys.length; ai++) {
        var k = akeys[ai];
        // Block event handlers and dangerous attributes
        if (/^on/i.test(k)) continue;
        html += " " + OWG.escAttr(k) + '="' + OWG.escAttr(String(attrs[k])) + '"';
      }
    }
    if (tag === "br" || tag === "hr") return html + ">";
    html += ">";
    if (typeof children === "string") {
      html += children; // Caller is responsible for escaping (use OWG.esc() for text)
    } else if (Array.isArray(children)) {
      for (var ci = 0; ci < children.length; ci++) {
        if (typeof children[ci] === "string") html += children[ci];
      }
    }
    html += "</" + tag + ">";
    return html;
  };

  // ─── Internationalization (i18n) ─────────────────────────────────────────
  // OWG.t(key) returns the localized string for a given key.
  // Override via state.locale (language code) or state.strings (custom map).
  // Built-in locales: en (default), es, fr, de, ja, zh, ko, pt.
  var _builtinStrings = {
    en: {
      "session_prefix": "Session: ",
      "connection_lost": "Connection lost",
      "disconnected_default": "The host disconnected unexpectedly.",
      "session_closed": "Session closed",
      "default_title": "OpenWebGoggles",
      "action_sent": "\u2713 Sent \u2014 waiting for agent\u2026",
      "copy": "Copy",
      "copy_clipboard": "Copy to clipboard",
      "choose_file": "Choose file",
      "choose_files": "Choose files",
      "no_file_chosen": "No file chosen",
      "file_too_large": "\u26a0 File too large (max {0} KB)",
      "file_read_error": "\u26a0 Error reading file",
      "filter_placeholder": "Filter rows\u2026",
      "filter_label": "Filter table",
      "rows_count": "{0} rows",
      "rows_filtered": "{0} of {1} rows",
      "no_network_nodes": "No network nodes",
      "network_label": "Network diagram",
      "no_heatmap_data": "No heatmap data",
      "heatmap_label": "Heatmap",
      "no_timeline_items": "No timeline items",
      "no_valid_timeline": "No valid timeline items",
      "timeline_label": "Timeline",
      "field_required": "This field is required",
      "invalid_format": "Invalid format",
      "too_short": "Too short (min {0} characters)",
      "too_long": "Too long (max {0} characters)",
      "min_value": "Must be at least {0}",
      "max_value": "Must be at most {0}",
      "must_be_option": "Value must be one of the provided options"
    },
    es: {
      "session_prefix": "Sesi\u00f3n: ",
      "connection_lost": "Conexi\u00f3n perdida",
      "disconnected_default": "El servidor se desconect\u00f3 inesperadamente.",
      "session_closed": "Sesi\u00f3n cerrada",
      "action_sent": "\u2713 Enviado \u2014 esperando al agente\u2026",
      "copy": "Copiar",
      "copy_clipboard": "Copiar al portapapeles",
      "choose_file": "Elegir archivo",
      "choose_files": "Elegir archivos",
      "no_file_chosen": "Ning\u00fan archivo seleccionado",
      "file_too_large": "\u26a0 Archivo muy grande (m\u00e1x {0} KB)",
      "file_read_error": "\u26a0 Error al leer archivo",
      "filter_placeholder": "Filtrar filas\u2026",
      "filter_label": "Filtrar tabla",
      "rows_count": "{0} filas",
      "rows_filtered": "{0} de {1} filas",
      "field_required": "Este campo es obligatorio",
      "invalid_format": "Formato no v\u00e1lido",
      "too_short": "Muy corto (m\u00edn {0} caracteres)",
      "too_long": "Muy largo (m\u00e1x {0} caracteres)",
      "min_value": "Debe ser al menos {0}",
      "max_value": "Debe ser como m\u00e1ximo {0}",
      "must_be_option": "El valor debe ser una de las opciones",
      "default_title": "OpenWebGoggles",
      "no_network_nodes": "Sin nodos de red",
      "network_label": "Diagrama de red",
      "no_heatmap_data": "Sin datos de mapa de calor",
      "heatmap_label": "Mapa de calor",
      "no_timeline_items": "Sin elementos de l\u00ednea de tiempo",
      "no_valid_timeline": "Sin elementos v\u00e1lidos de l\u00ednea de tiempo",
      "timeline_label": "L\u00ednea de tiempo"
    },
    fr: {
      "session_prefix": "Session\u00a0: ",
      "connection_lost": "Connexion perdue",
      "disconnected_default": "L\u2019h\u00f4te s\u2019est d\u00e9connect\u00e9 de mani\u00e8re inattendue.",
      "session_closed": "Session ferm\u00e9e",
      "action_sent": "\u2713 Envoy\u00e9 \u2014 en attente de l\u2019agent\u2026",
      "copy": "Copier",
      "copy_clipboard": "Copier dans le presse-papiers",
      "choose_file": "Choisir un fichier",
      "choose_files": "Choisir des fichiers",
      "no_file_chosen": "Aucun fichier choisi",
      "filter_placeholder": "Filtrer les lignes\u2026",
      "filter_label": "Filtrer le tableau",
      "rows_count": "{0} lignes",
      "rows_filtered": "{0} sur {1} lignes",
      "field_required": "Ce champ est obligatoire",
      "invalid_format": "Format invalide",
      "too_short": "Trop court (min {0} caract\u00e8res)",
      "too_long": "Trop long (max {0} caract\u00e8res)",
      "min_value": "Doit \u00eatre au moins {0}",
      "max_value": "Doit \u00eatre au plus {0}",
      "must_be_option": "La valeur doit \u00eatre une des options",
      "default_title": "OpenWebGoggles",
      "file_too_large": "\u26a0 Fichier trop volumineux (max {0} Ko)",
      "file_read_error": "\u26a0 Erreur de lecture du fichier",
      "no_network_nodes": "Aucun n\u0153ud r\u00e9seau",
      "network_label": "Diagramme r\u00e9seau",
      "no_heatmap_data": "Aucune donn\u00e9e de carte thermique",
      "heatmap_label": "Carte thermique",
      "no_timeline_items": "Aucun \u00e9l\u00e9ment chronologique",
      "no_valid_timeline": "Aucun \u00e9l\u00e9ment chronologique valide",
      "timeline_label": "Chronologie"
    },
    de: {
      "session_prefix": "Sitzung: ",
      "connection_lost": "Verbindung verloren",
      "disconnected_default": "Der Host hat sich unerwartet getrennt.",
      "session_closed": "Sitzung geschlossen",
      "action_sent": "\u2713 Gesendet \u2014 warte auf Agent\u2026",
      "copy": "Kopieren",
      "copy_clipboard": "In Zwischenablage kopieren",
      "choose_file": "Datei ausw\u00e4hlen",
      "choose_files": "Dateien ausw\u00e4hlen",
      "no_file_chosen": "Keine Datei ausgew\u00e4hlt",
      "filter_placeholder": "Zeilen filtern\u2026",
      "filter_label": "Tabelle filtern",
      "rows_count": "{0} Zeilen",
      "rows_filtered": "{0} von {1} Zeilen",
      "field_required": "Dieses Feld ist erforderlich",
      "invalid_format": "Ung\u00fcltiges Format",
      "too_short": "Zu kurz (min. {0} Zeichen)",
      "too_long": "Zu lang (max. {0} Zeichen)",
      "min_value": "Muss mindestens {0} sein",
      "max_value": "Darf h\u00f6chstens {0} sein",
      "must_be_option": "Der Wert muss eine der Optionen sein",
      "default_title": "OpenWebGoggles",
      "file_too_large": "\u26a0 Datei zu gro\u00df (max. {0} KB)",
      "file_read_error": "\u26a0 Fehler beim Lesen der Datei",
      "no_network_nodes": "Keine Netzwerkknoten",
      "network_label": "Netzwerkdiagramm",
      "no_heatmap_data": "Keine Heatmap-Daten",
      "heatmap_label": "Heatmap",
      "no_timeline_items": "Keine Zeitleistenelemente",
      "no_valid_timeline": "Keine g\u00fcltigen Zeitleistenelemente",
      "timeline_label": "Zeitleiste"
    },
    ja: {
      "session_prefix": "\u30bb\u30c3\u30b7\u30e7\u30f3: ",
      "connection_lost": "\u63a5\u7d9a\u304c\u5207\u308c\u307e\u3057\u305f",
      "session_closed": "\u30bb\u30c3\u30b7\u30e7\u30f3\u7d42\u4e86",
      "action_sent": "\u2713 \u9001\u4fe1\u6e08\u307f \u2014 \u30a8\u30fc\u30b8\u30a7\u30f3\u30c8\u5f85\u3061\u2026",
      "copy": "\u30b3\u30d4\u30fc",
      "copy_clipboard": "\u30af\u30ea\u30c3\u30d7\u30dc\u30fc\u30c9\u306b\u30b3\u30d4\u30fc",
      "choose_file": "\u30d5\u30a1\u30a4\u30eb\u3092\u9078\u629e",
      "filter_placeholder": "\u884c\u3092\u30d5\u30a3\u30eb\u30bf\u30fc\u2026",
      "field_required": "\u3053\u306e\u30d5\u30a3\u30fc\u30eb\u30c9\u306f\u5fc5\u9808\u3067\u3059",
      "invalid_format": "\u7121\u52b9\u306a\u5f62\u5f0f\u3067\u3059",
      "default_title": "OpenWebGoggles",
      "disconnected_default": "\u30db\u30b9\u30c8\u304c\u4e88\u671f\u305b\u305a\u5207\u65ad\u3055\u308c\u307e\u3057\u305f\u3002",
      "choose_files": "\u30d5\u30a1\u30a4\u30eb\u3092\u9078\u629e",
      "no_file_chosen": "\u30d5\u30a1\u30a4\u30eb\u672a\u9078\u629e",
      "file_too_large": "\u26a0 \u30d5\u30a1\u30a4\u30eb\u304c\u5927\u304d\u3059\u304e\u307e\u3059\uff08\u6700\u5927 {0} KB\uff09",
      "file_read_error": "\u26a0 \u30d5\u30a1\u30a4\u30eb\u8aad\u307f\u53d6\u308a\u30a8\u30e9\u30fc",
      "filter_label": "\u30c6\u30fc\u30d6\u30eb\u3092\u30d5\u30a3\u30eb\u30bf\u30fc",
      "rows_count": "{0} \u884c",
      "rows_filtered": "{1} \u4e2d {0} \u884c",
      "no_network_nodes": "\u30cd\u30c3\u30c8\u30ef\u30fc\u30af\u30ce\u30fc\u30c9\u306a\u3057",
      "network_label": "\u30cd\u30c3\u30c8\u30ef\u30fc\u30af\u56f3",
      "no_heatmap_data": "\u30d2\u30fc\u30c8\u30de\u30c3\u30d7\u30c7\u30fc\u30bf\u306a\u3057",
      "heatmap_label": "\u30d2\u30fc\u30c8\u30de\u30c3\u30d7",
      "no_timeline_items": "\u30bf\u30a4\u30e0\u30e9\u30a4\u30f3\u9805\u76ee\u306a\u3057",
      "no_valid_timeline": "\u6709\u52b9\u306a\u30bf\u30a4\u30e0\u30e9\u30a4\u30f3\u9805\u76ee\u306a\u3057",
      "timeline_label": "\u30bf\u30a4\u30e0\u30e9\u30a4\u30f3",
      "too_short": "\u77ed\u3059\u304e\u307e\u3059\uff08\u6700\u5c0f {0} \u6587\u5b57\uff09",
      "too_long": "\u9577\u3059\u304e\u307e\u3059\uff08\u6700\u5927 {0} \u6587\u5b57\uff09",
      "min_value": "{0} \u4ee5\u4e0a\u3067\u3042\u308b\u5fc5\u8981\u304c\u3042\u308a\u307e\u3059",
      "max_value": "{0} \u4ee5\u4e0b\u3067\u3042\u308b\u5fc5\u8981\u304c\u3042\u308a\u307e\u3059",
      "must_be_option": "\u5024\u306f\u9078\u629e\u80a2\u306e\u3044\u305a\u308c\u304b\u3067\u3042\u308b\u5fc5\u8981\u304c\u3042\u308a\u307e\u3059"
    },
    zh: {
      "session_prefix": "\u4f1a\u8bdd\uff1a",
      "connection_lost": "\u8fde\u63a5\u5df2\u65ad\u5f00",
      "session_closed": "\u4f1a\u8bdd\u5df2\u5173\u95ed",
      "action_sent": "\u2713 \u5df2\u53d1\u9001 \u2014 \u7b49\u5f85\u4ee3\u7406\u2026",
      "copy": "\u590d\u5236",
      "copy_clipboard": "\u590d\u5236\u5230\u526a\u8d34\u677f",
      "choose_file": "\u9009\u62e9\u6587\u4ef6",
      "filter_placeholder": "\u7b5b\u9009\u884c\u2026",
      "field_required": "\u6b64\u5b57\u6bb5\u4e3a\u5fc5\u586b\u9879",
      "invalid_format": "\u683c\u5f0f\u65e0\u6548",
      "default_title": "OpenWebGoggles",
      "disconnected_default": "\u4e3b\u673a\u610f\u5916\u65ad\u5f00\u8fde\u63a5\u3002",
      "choose_files": "\u9009\u62e9\u6587\u4ef6",
      "no_file_chosen": "\u672a\u9009\u62e9\u6587\u4ef6",
      "file_too_large": "\u26a0 \u6587\u4ef6\u8fc7\u5927\uff08\u6700\u5927 {0} KB\uff09",
      "file_read_error": "\u26a0 \u8bfb\u53d6\u6587\u4ef6\u51fa\u9519",
      "filter_label": "\u7b5b\u9009\u8868\u683c",
      "rows_count": "{0} \u884c",
      "rows_filtered": "{1} \u4e2d {0} \u884c",
      "no_network_nodes": "\u65e0\u7f51\u7edc\u8282\u70b9",
      "network_label": "\u7f51\u7edc\u56fe",
      "no_heatmap_data": "\u65e0\u70ed\u529b\u56fe\u6570\u636e",
      "heatmap_label": "\u70ed\u529b\u56fe",
      "no_timeline_items": "\u65e0\u65f6\u95f4\u7ebf\u9879\u76ee",
      "no_valid_timeline": "\u65e0\u6709\u6548\u65f6\u95f4\u7ebf\u9879\u76ee",
      "timeline_label": "\u65f6\u95f4\u7ebf",
      "too_short": "\u592a\u77ed\uff08\u6700\u5c11 {0} \u4e2a\u5b57\u7b26\uff09",
      "too_long": "\u592a\u957f\uff08\u6700\u591a {0} \u4e2a\u5b57\u7b26\uff09",
      "min_value": "\u5fc5\u987b\u81f3\u5c11\u4e3a {0}",
      "max_value": "\u5fc5\u987b\u6700\u591a\u4e3a {0}",
      "must_be_option": "\u503c\u5fc5\u987b\u662f\u63d0\u4f9b\u7684\u9009\u9879\u4e4b\u4e00"
    }
  };

  var _activeLocale = "en";
  var _activeStrings = _builtinStrings.en;

  // Set locale from state. Called during render.
  // state.locale: "en", "es", "fr", "de", "ja", "zh"
  // state.strings: custom overrides {"key": "value"} (merged on top of locale)
  OWG.setLocale = function (locale, customStrings) {
    _activeLocale = (locale || "en").toLowerCase().split("-")[0]; // "en-US" → "en"
    var base = _builtinStrings[_activeLocale] || _builtinStrings.en;
    if (customStrings && typeof customStrings === "object") {
      // Merge custom strings on top of locale strings
      _activeStrings = {};
      var k;
      for (k in base) {
        if (Object.prototype.hasOwnProperty.call(base, k)) _activeStrings[k] = base[k];
      }
      for (k in customStrings) {
        if (Object.prototype.hasOwnProperty.call(customStrings, k)) _activeStrings[k] = customStrings[k];
      }
    } else {
      _activeStrings = base;
    }
  };

  // Translate a key, with optional placeholder substitution.
  // OWG.t("rows_count", 42) → "42 rows"
  // OWG.t("too_short", 5) → "Too short (min 5 characters)"
  OWG.t = function (key) {
    var str = _activeStrings[key] || _builtinStrings.en[key] || key;
    // Replace {0}, {1}, etc. with additional arguments
    for (var i = 1; i < arguments.length; i++) {
      str = str.replace("{" + (i - 1) + "}", arguments[i]);
    }
    return str;
  };

  OWG.getLocale = function () { return _activeLocale; };

})(window.OWG = window.OWG || {});
