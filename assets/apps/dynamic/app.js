"use strict";
// Dynamic UI renderer — orchestrator module.
// Reads everything from state.json schema — no custom code needed.
// Uses addEventListener (CSP-safe) instead of inline event handlers.
//
// Depends on: utils.js, sections.js, validation.js, behaviors.js (loaded first)

(function () {
  var U = window.OWG;

  // Shared state exposed via OWG for use by sub-modules
  // Use Object.create(null) to prevent prototype chain interference
  U.formValues = Object.create(null);
  U.fieldValidators = Object.create(null);

  // Transport detection: MCP Apps (iframe) vs standalone browser (WebSocket)
  var wv;
  var isMCPApps = !!(window.__OWG_MCP_APPS__ && window.parent !== window);
  if (isMCPApps && U.MCPAppsTransport) {
    wv = new U.MCPAppsTransport();
  } else {
    wv = new OpenWebGoggles();
  }

  var done = false;

  var els = {
    loading:    document.getElementById("loading"),
    content:    document.getElementById("content"),
    hdrTitle:   document.getElementById("hdr-title"),
    hdrBadge:   document.getElementById("hdr-badge"),
    hdrSession: document.getElementById("hdr-session"),
    connDot:    document.getElementById("conn-dot"),
    closeBar:   document.getElementById("close-bar"),
    closeBtn:   document.getElementById("close-btn"),
  };

  // Hide header in MCP Apps mode (host provides its own chrome)
  if (isMCPApps) {
    var hdr = document.querySelector("header");
    if (hdr) hdr.style.display = "none";
  }

  // ─── Close Session ──────────────────────────────────────────────────────────
  function sendCloseAction() {
    if (done) return;
    done = true;
    if (els.closeBar) els.closeBar.classList.add("hidden");
    wv.sendAction("owg_session_closed", "session_closed", { reason: "user_closed" }).catch(function (err) {
      console.error("Close action failed:", err);
    });
  }

  if (els.closeBtn) {
    els.closeBtn.addEventListener("click", sendCloseAction);
  }

  // Notify the agent when the browser window/tab is closed (browser mode only).
  // fetch() with keepalive:true continues after the page unloads; avoids the
  // deprecated synchronous XHR and works with Bearer auth unlike sendBeacon().
  window.addEventListener("beforeunload", function () {
    if (done || isMCPApps) return;
    var token = wv && wv._token;
    var base  = wv && wv._httpUrl;
    if (!token || !base) return;
    fetch(base + "/_api/actions", {
      method:    "POST",
      headers:   { "Content-Type": "application/json", "Authorization": "Bearer " + token },
      body:      JSON.stringify({ action_id: "owg_session_closed", type: "session_closed", value: { reason: "window_closed" } }),
      keepalive: true,
    });
  });

  wv.connect()
    .then(function (instance) {
      if (!isMCPApps) {
        var m = instance.getManifest();
        if (m && m.session) els.hdrSession.textContent = U.t("session_prefix") + m.session.id.slice(0, 8);
        els.connDot.classList.add("on");
      }
      if (els.closeBar) els.closeBar.classList.remove("hidden");
      render(instance.getState());
    })
    .catch(function (err) {
      U.safeHTML(els.loading, "<p style='color:var(--red)'>Connection failed: " + U.esc(String(err)) + "</p>");
    });

  wv.on("connected",     function (d) { render(d.state); });
  wv.on("state_updated", function (s) { if (!done) render(s); });
  wv.on("disconnected",  function (d) {
    // Host disconnect (crash, tab close) — show non-dismissable overlay
    if (done) return;
    done = true;
    if (els.closeBar) els.closeBar.classList.add("hidden");
    var wrap = document.createElement("div");
    wrap.className = "done-state";
    var icon = document.createElement("div");
    icon.className = "done-icon";
    icon.textContent = "\u26a0";
    var label = document.createElement("div");
    label.style.cssText = "color:var(--yellow);font-weight:600";
    label.textContent = U.t("connection_lost");
    var msg = document.createElement("div");
    msg.className = "done-msg";
    msg.textContent = (d && d.message) || U.t("disconnected_default");
    wrap.appendChild(icon);
    wrap.appendChild(label);
    wrap.appendChild(msg);
    els.content.textContent = "";
    els.content.appendChild(wrap);
  });
  wv.on("close",         function (d) {
    done = true;
    if (els.closeBar) els.closeBar.classList.add("hidden");
    // Build close message via DOM API (prevents HTML structure injection)
    var wrap = document.createElement("div");
    wrap.className = "done-state";
    var icon = document.createElement("div");
    icon.className = "done-icon";
    icon.textContent = "\u2713";
    var label = document.createElement("div");
    label.style.cssText = "color:var(--green);font-weight:600";
    label.textContent = U.t("session_closed");
    var msg = document.createElement("div");
    msg.className = "done-msg";
    msg.textContent = (d && d.message) || "";
    wrap.appendChild(icon);
    wrap.appendChild(label);
    wrap.appendChild(msg);
    els.content.textContent = "";
    els.content.appendChild(wrap);
  });

  // Clear all keys from an Object.create(null) dict without replacing it
  // (OWG namespace is frozen — properties can't be reassigned, but inner objects are mutable)
  function clearObj(obj) { for (var k in obj) delete obj[k]; }

  // Safe shallow copy that skips prototype-polluting keys (__proto__, constructor, prototype).
  // Uses Object.create(null) to produce a prototype-less dict — prevents any
  // prototype chain interference when the copy is serialized to JSON.
  var DANGEROUS_KEYS = /^(__proto__|constructor|prototype)$/;
  function safeCopy(obj) {
    var copy = Object.create(null);
    for (var k in obj) {
      if (!DANGEROUS_KEYS.test(k)) copy[k] = obj[k];
    }
    return copy;
  }

  // ─── Main renderer ──────────────────────────────────────────────────────────
  function render(state) {
    if (!state) return;
    clearObj(U.formValues);
    clearObj(U.fieldValidators);

    // Header
    // Set locale from state before rendering
    U.setLocale(state.locale, state.strings);

    var title = state.title || U.t("default_title");
    document.title = title + " \u2014 OpenWebGoggles";
    els.hdrTitle.textContent = title;

    var status = (state.status || "").replace(/_/g, " ");
    if (status) {
      els.hdrBadge.textContent = status;
      els.hdrBadge.className = "badge " + U.statusBadgeClass(state.status);
    } else {
      els.hdrBadge.textContent = "";
    }

    // Apply theme (dark is default, light via data-theme="light", system follows OS)
    var theme = state.theme || "dark";
    if (theme === "system") {
      var prefersDark = window.matchMedia && window.matchMedia("(prefers-color-scheme: dark)").matches;
      document.body.removeAttribute("data-theme");
      if (!prefersDark) document.body.setAttribute("data-theme", "light");
    } else if (theme === "light") {
      document.body.setAttribute("data-theme", "light");
    } else {
      document.body.removeAttribute("data-theme");
    }

    // Inject custom CSS
    U.injectCustomCSS(state.custom_css || "");

    // Check for layout mode
    var hasLayout = state.layout && state.layout.type && state.layout.type !== "default";
    var html = "";

    // Message
    if (state.message) {
      var msgCls = "message-box" + U.safeClass(state.message_className);
      if (state.message_format === "markdown") {
        html += '<div class="' + msgCls + '">' + U.markdownBlock(state.message) + "</div>";
      } else {
        html += '<div class="' + msgCls + '">' + U.esc(state.message) + "</div>";
      }
    }

    // Check for pages mode
    var hasPages = state.pages && typeof state.pages === "object" && Object.keys(state.pages).length > 0;

    if (hasPages) {
      html += renderPages(state);
    } else if (hasLayout) {
      html += renderLayout(state);
    } else {
      // Standard single-column sections
      var ui = (state.data && state.data.ui) || state.data || {};
      var sections = ui.sections || [];
      sections.forEach(function (sec, si) {
        html += U.renderSection(sec, si);
      });
    }

    // Top-level actions
    var actions = state.actions_requested || ((state.data && (state.data.ui || state.data)) || {}).actions || [];
    if (actions.length) {
      html += '<div class="section"><div class="actions-bar" id="main-actions">';
      actions.forEach(function (a) {
        html += U.renderActionButton(a, "main");
      });
      html += "</div></div>";
    }

    els.loading.classList.add("hidden");
    els.content.classList.remove("hidden");
    U.safeHTML(els.content, html);

    // Bind events + post-render hooks
    bindEvents();
    U.bindSectionEvents(els.content);
    U.bindValidation(els.content);
    U.initBehaviors(state);
    U.postRenderSections();
  }

  // ─── Layout renderer ────────────────────────────────────────────────────────
  function renderLayout(state) {
    var layout = state.layout;
    var panels = state.panels || {};
    var html = "";

    if (layout.type === "sidebar") {
      var sw = layout.sidebarWidth || "300px";
      // Validate CSS length on client side (defense-in-depth — server already checks)
      if (!/^[0-9]+(px|em|rem|%)$/.test(sw)) sw = "300px";
      html += '<div class="layout-sidebar" style="--sidebar-width:' + U.escAttr(sw) + '">';
      html += '<div class="layout-panel layout-sidebar-panel">';
      (panels.sidebar && panels.sidebar.sections || []).forEach(function (sec, si) {
        html += U.renderSection(sec, "sb-" + si);
      });
      html += "</div>";
      html += '<div class="layout-panel layout-main-panel">';
      (panels.main && panels.main.sections || []).forEach(function (sec, si) {
        html += U.renderSection(sec, "main-" + si);
      });
      html += "</div></div>";
    } else if (layout.type === "split") {
      html += '<div class="layout-split">';
      html += '<div class="layout-panel">';
      (panels.left && panels.left.sections || []).forEach(function (sec, si) {
        html += U.renderSection(sec, "left-" + si);
      });
      html += "</div>";
      html += '<div class="layout-panel">';
      (panels.right && panels.right.sections || []).forEach(function (sec, si) {
        html += U.renderSection(sec, "right-" + si);
      });
      html += "</div></div>";
    }

    return html;
  }

  // ─── Event binding ──────────────────────────────────────────────────────────
  function bindEvents() {
    // Action buttons
    els.content.querySelectorAll("[data-action-id]").forEach(function (btn) {
      btn.addEventListener("click", function () {
        // Client-side page navigation — instant, no agent round-trip needed
        var navTarget = btn.getAttribute("data-navigate-to");
        if (navTarget) {
          U.navigateToPage(navTarget);
          return;
        }
        handleAction(
          btn.getAttribute("data-action-id"),
          btn.getAttribute("data-action-type") || "action",
          btn.getAttribute("data-action-scope") || "",
          btn
        );
      });
    });

    // Page navigation buttons
    els.content.querySelectorAll(".owg-nav-btn[data-page]").forEach(function (btn) {
      btn.addEventListener("click", function () {
        var target = btn.getAttribute("data-page");
        // Update nav active state
        els.content.querySelectorAll(".owg-nav-btn[data-page]").forEach(function (b) {
          b.classList.toggle("owg-nav-active", b.getAttribute("data-page") === target);
        });
        // Show/hide pages (class-based — survives sanitizeHTML style stripping)
        els.content.querySelectorAll(".owg-page[data-page-id]").forEach(function (p) {
          p.classList.toggle("owg-page-hidden", p.getAttribute("data-page-id") !== target);
        });
        // Pure client-side page switching — no action emitted to agent
      });
    });

    // Form field inputs
    els.content.querySelectorAll("[data-field-key]").forEach(function (el) {
      var key = el.getAttribute("data-field-key");
      var tag = el.tagName.toLowerCase();
      var type = el.type;
      var event = (tag === "select") ? "change"
               : (type === "checkbox") ? "change"
               : "input";
      el.addEventListener(event, function () {
        if (type === "checkbox") {
          U.formValues[key] = el.checked;
        } else if (type === "number" || type === "range") {
          var parsed = parseFloat(el.value);
          U.formValues[key] = el.value === "" ? "" : (isNaN(parsed) ? 0 : parsed);
          // Update live value display for sliders
          if (type === "range") {
            var valSpan = document.getElementById(el.id + "-val");
            if (valSpan) {
              var unit = el.dataset && el.dataset.unit ? " " + el.dataset.unit : "";
              valSpan.textContent = el.value + unit;
            }
          }
        } else {
          U.formValues[key] = el.value;
        }
        // Re-evaluate behaviors on every change
        U.evaluateBehaviors();
      });
    });
  }

  // ─── Error banner (transport/action failures) ────────────────────────────────
  var _errorBannerTimer = null;
  function showErrorBanner(message) {
    var existing = document.getElementById("owg-error-banner");
    if (existing && existing.parentNode) existing.parentNode.removeChild(existing);
    if (_errorBannerTimer) { clearTimeout(_errorBannerTimer); _errorBannerTimer = null; }

    var banner = document.createElement("div");
    banner.id = "owg-error-banner";
    banner.className = "owg-callout owg-callout-error";
    banner.style.cssText = "display:flex;justify-content:space-between;align-items:flex-start;gap:8px";

    var text = document.createElement("span");
    text.textContent = message;

    var dismiss = document.createElement("button");
    dismiss.textContent = "\xd7";
    dismiss.style.cssText = "background:none;border:none;cursor:pointer;font-size:1.2em;line-height:1;flex-shrink:0;padding:0";
    dismiss.addEventListener("click", function () {
      if (banner.parentNode) banner.parentNode.removeChild(banner);
      if (_errorBannerTimer) { clearTimeout(_errorBannerTimer); _errorBannerTimer = null; }
    });

    banner.appendChild(text);
    banner.appendChild(dismiss);

    var content = els.content;
    if (content && !content.classList.contains("hidden")) {
      content.insertBefore(banner, content.firstChild);
    }
    _errorBannerTimer = setTimeout(function () {
      if (banner.parentNode) banner.parentNode.removeChild(banner);
      _errorBannerTimer = null;
    }, 10000);
  }

  // ─── Action handler ─────────────────────────────────────────────────────────
  function handleAction(actionId, type, scope, btn) {
    if (done) return;

    // Validate required fields before submit
    if (type === "approve" || type === "confirm" || type === "primary" || type === "submit" || type === "success") {
      var errors = U.validateAllRequired();
      if (errors) {
        U.showAllErrors(errors);
        return;
      }
    }

    // Collect value
    var value;
    if (type === "approve" || type === "confirm" || type === "primary") {
      value = Object.keys(U.formValues).length ? safeCopy(U.formValues) : true;
    } else if (type === "reject" || type === "danger" || type === "delete") {
      value = Object.keys(U.formValues).length ? safeCopy(U.formValues) : false;
    } else if (type === "submit") {
      value = safeCopy(U.formValues);
    } else {
      var itemId = btn && btn.dataset && btn.dataset.item;
      value = itemId !== undefined ? { item_id: itemId, form: safeCopy(U.formValues) } : safeCopy(U.formValues);
    }

    // Build action payload with optional context
    var context = Object.create(null);
    if (btn && btn.dataset) {
      if (btn.dataset.itemIndex !== undefined) {
        context.item_index = parseInt(btn.dataset.itemIndex, 10);
        if (btn.dataset.item) context.item_id = btn.dataset.item;
      }
      if (btn.dataset.sectionIndex !== undefined) {
        var parsedIdx = parseInt(btn.dataset.sectionIndex, 10);
        context.section_index = isNaN(parsedIdx) ? btn.dataset.sectionIndex : parsedIdx;
      }
      if (btn.dataset.sectionId) context.section_id = btn.dataset.sectionId;
    }
    var hasContext = Object.keys(context).length > 0;

    btn.disabled = true;
    btn.textContent = "\u2026";

    var actionPromise;
    if (hasContext) {
      // Use sendAction with metadata containing context
      actionPromise = wv.sendAction(actionId, type, value, { context: context });
    } else {
      actionPromise = wv.sendAction(actionId, type, value);
    }

    actionPromise.then(function () {
      if (btn.parentElement) {
        U.safeHTML(btn.parentElement, '<span style="color:var(--green);font-size:12px">' + U.esc(U.t("action_sent")) + '</span>');
      }
    }).catch(function (err) {
      btn.disabled = false;
      btn.textContent = actionId;
      console.error("Action failed:", err);
      showErrorBanner(String((err && err.message) || err));
    });
  }
  // ─── Emit action (for use by sub-modules like sections.js) ────────────────
  U.emitAction = function (actionId, type, value, context) {
    if (done) return;
    var hasContext = context && Object.keys(context).length > 0;
    var actionPromise;
    if (hasContext) {
      actionPromise = wv.sendAction(actionId, type, value, { context: context });
    } else {
      actionPromise = wv.sendAction(actionId, type, value);
    }
    actionPromise.catch(function (err) {
      console.error("Emitted action failed:", err);
      showErrorBanner(String((err && err.message) || err));
    });
  };

  // ─── Client-side page navigation (no agent round-trip) ────────────────────
  U.navigateToPage = function (pageKey) {
    if (!pageKey) return false;
    // Check page exists (iterate + compare to avoid CSS selector injection)
    var found = false;
    els.content.querySelectorAll(".owg-page[data-page-id]").forEach(function (p) {
      if (p.getAttribute("data-page-id") === pageKey) found = true;
    });
    if (!found) return false;
    // Update nav active state
    els.content.querySelectorAll(".owg-nav-btn[data-page]").forEach(function (b) {
      b.classList.toggle("owg-nav-active", b.getAttribute("data-page") === pageKey);
    });
    // Show/hide pages (class-based — survives sanitizeHTML style stripping)
    els.content.querySelectorAll(".owg-page[data-page-id]").forEach(function (p) {
      p.classList.toggle("owg-page-hidden", p.getAttribute("data-page-id") !== pageKey);
    });
    // Pure client-side navigation — no action emitted, no agent round-trip.
    // The agent can detect the active page via webview_read() if needed.
    return true;
  };

  // ─── Pages renderer ────────────────────────────────────────────────────────
  function renderPages(state) {
    var pages = state.pages;
    var pageKeys = Object.keys(pages);
    var active = state.activePage || pageKeys[0];
    var html = "";
    if (state.showNav !== false) {
      html += '<nav class="owg-nav">';
      pageKeys.forEach(function (pk) {
        var page = pages[pk];
        if (page.hidden) return;
        var cls = pk === active ? " owg-nav-active" : "";
        html += '<button class="owg-nav-btn' + cls + '" data-page="' + U.escAttr(pk) + '">' +
          U.esc(page.label || pk) + "</button>";
      });
      html += "</nav>";
    }

    // Render all pages (hidden except active) for instant client-side switching
    pageKeys.forEach(function (pk) {
      var page = pages[pk];
      var hiddenCls = pk === active ? "" : " owg-page-hidden";
      html += '<div class="owg-page' + hiddenCls + '" data-page-id="' + U.escAttr(pk) + '">';
      if (page.message) {
        if (page.message_format === "markdown") {
          html += '<div class="message-box">' + U.markdownBlock(page.message) + "</div>";
        } else {
          html += '<div class="message-box">' + U.esc(page.message) + "</div>";
        }
      }
      var ui = (page.data && page.data.ui) || page.data || {};
      (ui.sections || []).forEach(function (sec, si) {
        html += U.renderSection(sec, "page-" + pk + "-" + si);
      });
      var pageActions = page.actions_requested || [];
      if (pageActions.length) {
        html += '<div class="section"><div class="actions-bar">';
        pageActions.forEach(function (a) {
          html += U.renderActionButton(a, "page-" + pk);
        });
        html += "</div></div>";
      }
      html += "</div>";
    });

    return html;
  }
})();

// Freeze the OWG namespace after all modules are loaded to prevent post-init
// tampering with escape functions (defense-in-depth against prototype pollution).
if (typeof Object.freeze === "function") {
  Object.freeze(window.OWG);
}
