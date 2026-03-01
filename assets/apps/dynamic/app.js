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

  var wv = new OpenWebGoggles();
  var done = false;

  var els = {
    loading:    document.getElementById("loading"),
    content:    document.getElementById("content"),
    hdrTitle:   document.getElementById("hdr-title"),
    hdrBadge:   document.getElementById("hdr-badge"),
    hdrSession: document.getElementById("hdr-session"),
    connDot:    document.getElementById("conn-dot"),
  };

  wv.connect()
    .then(function (instance) {
      var m = instance.getManifest();
      if (m && m.session) els.hdrSession.textContent = "Session: " + m.session.id.slice(0, 8);
      els.connDot.classList.add("on");
      render(instance.getState());
    })
    .catch(function (err) {
      U.safeHTML(els.loading, "<p style='color:var(--red)'>Connection failed: " + U.esc(String(err)) + "</p>");
    });

  wv.on("connected",     function (d) { render(d.state); });
  wv.on("state_updated", function (s) { if (!done) render(s); });
  wv.on("close",         function (d) {
    done = true;
    // Build close message via DOM API (prevents HTML structure injection)
    var wrap = document.createElement("div");
    wrap.className = "done-state";
    var icon = document.createElement("div");
    icon.className = "done-icon";
    icon.textContent = "\u2713";
    var label = document.createElement("div");
    label.style.cssText = "color:var(--green);font-weight:600";
    label.textContent = "Session closed";
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

  // Safe shallow copy that skips prototype-polluting keys (__proto__, constructor, prototype)
  var DANGEROUS_KEYS = /^(__proto__|constructor|prototype)$/;
  function safeCopy(obj) {
    var copy = {};
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
    var title = state.title || "OpenCode";
    document.title = title + " \u2014 OpenWebGoggles";
    els.hdrTitle.textContent = title;

    var status = (state.status || "").replace(/_/g, " ");
    if (status) {
      els.hdrBadge.textContent = status;
      els.hdrBadge.className = "badge " + U.statusBadgeClass(state.status);
    } else {
      els.hdrBadge.textContent = "";
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
        // Show/hide pages
        els.content.querySelectorAll(".owg-page[data-page-id]").forEach(function (p) {
          p.style.display = p.getAttribute("data-page-id") === target ? "" : "none";
        });
        // Emit page switch action so agent can react
        if (typeof U.emitAction === "function") {
          U.emitAction("_page_switch", "action", target, { page: target });
        }
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
        } else if (type === "number") {
          U.formValues[key] = parseFloat(el.value) || 0;
        } else {
          U.formValues[key] = el.value;
        }
        // Re-evaluate behaviors on every change
        U.evaluateBehaviors();
      });
    });
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
    var context = {};
    if (btn && btn.dataset) {
      if (btn.dataset.itemIndex !== undefined) {
        context.item_index = parseInt(btn.dataset.itemIndex, 10);
        if (btn.dataset.item) context.item_id = btn.dataset.item;
      }
      if (btn.dataset.sectionIndex !== undefined) {
        context.section_index = parseInt(btn.dataset.sectionIndex, 10) || btn.dataset.sectionIndex;
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
        U.safeHTML(btn.parentElement, '<span style="color:var(--green);font-size:12px">\u2713 Sent \u2014 waiting for agent...</span>');
      }
    }).catch(function (err) {
      btn.disabled = false;
      btn.textContent = actionId;
      console.error("Action failed:", err);
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
    });
  };

  // ─── Pages renderer ────────────────────────────────────────────────────────
  function renderPages(state) {
    var pages = state.pages;
    var pageKeys = Object.keys(pages);
    var active = state.activePage || pageKeys[0];
    var html = '<nav class="owg-nav">';
    pageKeys.forEach(function (pk) {
      var page = pages[pk];
      var cls = pk === active ? " owg-nav-active" : "";
      html += '<button class="owg-nav-btn' + cls + '" data-page="' + U.escAttr(pk) + '">' +
        U.esc(page.label || pk) + "</button>";
    });
    html += "</nav>";

    // Render all pages (hidden except active) for instant client-side switching
    pageKeys.forEach(function (pk) {
      var page = pages[pk];
      var display = pk === active ? "" : ' style="display:none"';
      html += '<div class="owg-page" data-page-id="' + U.escAttr(pk) + '"' + display + ">";
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
