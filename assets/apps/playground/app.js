"use strict";
// OpenWebGoggles Playground — interactive state editor with live preview.
//
// Depends on: utils.js, sections.js, charts.js, validation.js, behaviors.js
// (loaded from the dynamic app's rendering modules)

(function () {
  var U = window.OWG;
  if (!U) { document.getElementById("status").textContent = "Error: OWG modules not loaded"; return; }

  // Shared state for rendering (same interface as dynamic app)
  U.formValues = U.formValues || Object.create(null);
  U.fieldValidators = U.fieldValidators || Object.create(null);

  var editor = document.getElementById("editor");
  var preview = document.getElementById("preview");
  var status = document.getElementById("status");
  var presetBar = document.getElementById("preset-bar");
  var btnFormat = document.getElementById("btn-format");
  var btnCopy = document.getElementById("btn-copy");
  var btnTheme = document.getElementById("btn-theme");
  var resizeHandle = document.getElementById("resize-handle");
  var editorPanel = document.getElementById("pg-editor");

  var debounceTimer = null;
  var currentThemeOverride = null;

  // ─── Presets ──────────────────────────────────────────────────────────────

  var PRESETS = {
    "Confirm": {
      title: "Deploy to production?",
      message: "This will deploy v2.3.1 to all 12 servers.",
      status: "pending_review",
      data: { sections: [
        { type: "text", content: "**Changes:**\n- Fix auth timeout\n- Update rate limits\n- New health endpoint", format: "markdown" }
      ]},
      actions_requested: [
        { id: "confirm", label: "Confirm", type: "approve" },
        { id: "cancel", label: "Cancel", type: "reject" }
      ]
    },
    "Form": {
      title: "New User",
      message: "Fill in the details for the new team member.",
      status: "waiting_input",
      data: { sections: [{
        type: "form",
        fields: [
          { key: "name", label: "Full Name", type: "text", required: true },
          { key: "email", label: "Email", type: "email", required: true },
          { key: "role", label: "Role", type: "select", options: ["Admin", "Editor", "Viewer"] },
          { key: "notes", label: "Notes", type: "textarea", placeholder: "Optional context..." }
        ]
      }]},
      actions_requested: [
        { id: "submit", label: "Create User", type: "primary" }
      ]
    },
    "Table": {
      title: "Open Pull Requests",
      status: "ready",
      data: { sections: [{
        type: "table",
        columns: [
          { key: "pr", label: "PR" },
          { key: "author", label: "Author" },
          { key: "status", label: "Status" },
          { key: "files", label: "Files" }
        ],
        rows: [
          { pr: "#42 Fix auth", author: "alice", status: "Ready", files: "3" },
          { pr: "#43 Add dark mode", author: "bob", status: "Draft", files: "8" },
          { pr: "#44 Bump deps", author: "dependabot", status: "Ready", files: "1" }
        ],
        filterable: true
      }]},
      actions_requested: [
        { id: "merge_all", label: "Merge Ready", type: "approve" },
        { id: "skip", label: "Skip", type: "ghost" }
      ]
    },
    "Progress": {
      title: "Building Project",
      status: "processing",
      data: { sections: [{
        type: "progress",
        percentage: 65,
        tasks: [
          { label: "Install dependencies", status: "complete" },
          { label: "Compile TypeScript", status: "complete" },
          { label: "Run tests", status: "running" },
          { label: "Bundle assets", status: "pending" }
        ]
      }]}
    },
    "Dashboard": {
      title: "API Health",
      status: "ready",
      data: { sections: [{
        type: "metrics",
        columns: 4,
        cards: [
          { label: "Requests/s", value: "1,234", delta: "+12%", trend: "up" },
          { label: "Error Rate", value: "0.3%", delta: "-0.1%", trend: "down" },
          { label: "P99 Latency", value: "142ms", delta: "+8ms", trend: "up" },
          { label: "Uptime", value: "99.97%" }
        ]
      }]}
    },
    "Chart": {
      title: "Monthly Revenue",
      status: "ready",
      data: { sections: [{
        type: "chart",
        chartType: "bar",
        data: {
          labels: ["Jan", "Feb", "Mar", "Apr", "May", "Jun"],
          datasets: [
            { label: "2025", data: [100, 120, 115, 140, 155, 170] },
            { label: "2024", data: [80, 95, 90, 105, 110, 125] }
          ]
        }
      }]}
    },
    "Diff": {
      title: "Review: Fix timing attack",
      message: "Replaces == with constant-time comparison.",
      status: "pending_review",
      data: { sections: [{
        type: "diff",
        content: "--- a/auth.py\n+++ b/auth.py\n@@ -42,7 +42,7 @@\n def verify_token(token: str) -> bool:\n-    return token == SECRET\n+    return hmac.compare_digest(token, SECRET)"
      }]},
      actions_requested: [
        { id: "approve", label: "Approve", type: "approve" },
        { id: "request_changes", label: "Request Changes", type: "reject" }
      ]
    },
    "Log": {
      title: "Build Output",
      status: "processing",
      data: { sections: [{
        type: "log",
        maxLines: 200,
        lines: [
          "$ npm install",
          "\x1b[32m✓\x1b[0m 847 packages installed (2.1s)",
          "$ npm run build",
          "Compiling 42 files...",
          "\x1b[33mwarn\x1b[0m: unused import in auth.ts:3",
          "\x1b[32m✓\x1b[0m Build complete (4.7s)",
          "$ npm test",
          "Running 128 tests...",
          "\x1b[32m✓\x1b[0m 128 passed, 0 failed"
        ]
      }]}
    },
    "Light": {
      title: "Light Theme Demo",
      message: "This panel uses the light color scheme.",
      status: "ready",
      theme: "light",
      data: { sections: [{
        type: "metrics",
        columns: 3,
        cards: [
          { label: "Users", value: "2,847", delta: "+5.2%", trend: "up" },
          { label: "Revenue", value: "$142k", delta: "+12%", trend: "up" },
          { label: "Churn", value: "1.8%", delta: "-0.3%", trend: "down" }
        ]
      }]}
    },
    "Pages": {
      title: "Project Setup",
      pages: {
        config: {
          label: "Configuration",
          data: { sections: [{
            type: "form",
            fields: [
              { key: "name", label: "Project Name", type: "text", required: true },
              { key: "lang", label: "Language", type: "select", options: ["Python", "TypeScript", "Go"] }
            ]
          }]}
        },
        review: {
          label: "Review",
          data: { sections: [
            { type: "text", content: "Review your settings before creating the project.", format: "markdown" }
          ]},
          actions_requested: [
            { id: "create", label: "Create Project", type: "approve" }
          ]
        }
      }
    }
  };

  // ─── Preset buttons ───────────────────────────────────────────────────────

  Object.keys(PRESETS).forEach(function (name) {
    var btn = document.createElement("button");
    btn.className = "pg-preset-btn";
    btn.textContent = name;
    btn.addEventListener("click", function () {
      var json = JSON.stringify(PRESETS[name], null, 2);
      editor.value = json;
      renderPreview(json);
    });
    presetBar.appendChild(btn);
  });

  // ─── Render preview ───────────────────────────────────────────────────────

  function clearObj(obj) {
    for (var k in obj) {
      if (Object.prototype.hasOwnProperty.call(obj, k)) delete obj[k];
    }
  }

  function renderPreview(jsonStr) {
    var state;
    try {
      state = JSON.parse(jsonStr);
      setStatus("ok", "Valid JSON");
    } catch (e) {
      setStatus("err", "Parse error: " + e.message);
      return;
    }

    if (typeof state !== "object" || state === null || Array.isArray(state)) {
      setStatus("err", "State must be a JSON object");
      return;
    }

    clearObj(U.formValues);
    clearObj(U.fieldValidators);

    // Apply theme
    var theme = currentThemeOverride || state.theme || "dark";
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
    if (U.injectCustomCSS) U.injectCustomCSS(state.custom_css || "");

    var html = "";

    // Title
    if (state.title) {
      html += '<div style="font-size:18px;font-weight:600;margin-bottom:12px">' + U.esc(state.title) + '</div>';
    }

    // Status badge
    if (state.status) {
      var statusText = state.status.replace(/_/g, " ");
      html += '<div style="margin-bottom:16px"><span class="badge ' + U.statusBadgeClass(state.status) + '">' + U.esc(statusText) + '</span></div>';
    }

    // Message
    if (state.message) {
      var msgCls = "message-box" + U.safeClass(state.message_className);
      if (state.message_format === "markdown") {
        html += '<div class="' + msgCls + '">' + U.markdownBlock(state.message) + '</div>';
      } else {
        html += '<div class="' + msgCls + '">' + U.esc(state.message) + '</div>';
      }
    }

    // Pages mode
    var hasPages = state.pages && typeof state.pages === "object" && Object.keys(state.pages).length > 0;
    if (hasPages) {
      html += renderPages(state);
    } else {
      // Sections
      var hasLayout = state.layout && state.layout.type && state.layout.type !== "default";
      if (hasLayout) {
        html += renderLayout(state);
      } else {
        var ui = (state.data && state.data.ui) || state.data || {};
        var sections = ui.sections || [];
        sections.forEach(function (sec, si) {
          html += U.renderSection(sec, si);
        });
      }
    }

    // Actions
    var actions = state.actions_requested || ((state.data && (state.data.ui || state.data)) || {}).actions || [];
    if (actions.length) {
      html += '<div class="section"><div class="actions-bar">';
      actions.forEach(function (a) {
        html += U.renderActionButton(a, "pg");
      });
      html += '</div></div>';
    }

    U.safeHTML(preview, html);

    // Post-render hooks
    if (U.bindSectionEvents) U.bindSectionEvents(preview);
    if (U.bindValidation) U.bindValidation(preview);
    if (U.initBehaviors) U.initBehaviors(state);
    if (U.postRenderSections) U.postRenderSections();

    setStatus("ok", "Valid \u2014 " + Object.keys(state).length + " keys, " + jsonStr.length + " bytes");
  }

  // ─── Layout renderer (mirrors dynamic/app.js) ────────────────────────────

  function renderLayout(state) {
    var layout = state.layout;
    var panels = state.panels || {};
    var html = "";
    if (layout.type === "sidebar") {
      var sw = layout.sidebarWidth || "300px";
      if (!/^[0-9]+(px|em|rem|%)$/.test(sw)) sw = "300px";
      html += '<div class="layout-sidebar" style="--sidebar-width:' + U.escAttr(sw) + '">';
      html += '<div class="layout-panel layout-sidebar-panel">';
      (panels.sidebar && panels.sidebar.sections || []).forEach(function (sec, si) { html += U.renderSection(sec, "sb-" + si); });
      html += '</div><div class="layout-panel layout-main-panel">';
      (panels.main && panels.main.sections || []).forEach(function (sec, si) { html += U.renderSection(sec, "main-" + si); });
      html += '</div></div>';
    } else if (layout.type === "split") {
      html += '<div class="layout-split">';
      html += '<div class="layout-panel">';
      (panels.left && panels.left.sections || []).forEach(function (sec, si) { html += U.renderSection(sec, "left-" + si); });
      html += '</div><div class="layout-panel">';
      (panels.right && panels.right.sections || []).forEach(function (sec, si) { html += U.renderSection(sec, "right-" + si); });
      html += '</div></div>';
    }
    return html;
  }

  // ─── Pages renderer (mirrors dynamic/app.js) ─────────────────────────────

  function renderPages(state) {
    var pages = state.pages;
    var keys = Object.keys(pages);
    var html = '<div class="owg-nav">';
    keys.forEach(function (k, i) {
      var p = pages[k];
      var label = (p && p.label) || k;
      var cls = "owg-nav-btn" + (i === 0 ? " owg-nav-active" : "");
      html += '<button class="' + cls + '" data-page="' + U.escAttr(k) + '">' + U.esc(label) + '</button>';
    });
    html += '</div>';
    keys.forEach(function (k, i) {
      var p = pages[k];
      var hidden = i !== 0 ? " owg-page-hidden" : "";
      html += '<div class="owg-page' + hidden + '" data-page-id="' + U.escAttr(k) + '">';
      var sections = (p.data && p.data.sections) || [];
      sections.forEach(function (sec, si) { html += U.renderSection(sec, k + "-" + si); });
      var pageActions = p.actions_requested || [];
      if (pageActions.length) {
        html += '<div class="section"><div class="actions-bar">';
        pageActions.forEach(function (a) { html += U.renderActionButton(a, k); });
        html += '</div></div>';
      }
      html += '</div>';
    });
    return html;
  }

  // ─── Status bar ───────────────────────────────────────────────────────────

  function setStatus(type, msg) {
    status.innerHTML = "";
    var span = document.createElement("span");
    span.className = type === "ok" ? "pg-status-ok" : "pg-status-err";
    span.textContent = msg;
    status.appendChild(span);
  }

  // ─── Editor events ────────────────────────────────────────────────────────

  editor.addEventListener("input", function () {
    clearTimeout(debounceTimer);
    debounceTimer = setTimeout(function () {
      var val = editor.value.trim();
      if (val) renderPreview(val);
    }, 300);
  });

  // Tab key inserts spaces instead of switching focus
  editor.addEventListener("keydown", function (e) {
    if (e.key === "Tab") {
      e.preventDefault();
      var start = editor.selectionStart;
      var end = editor.selectionEnd;
      editor.value = editor.value.substring(0, start) + "  " + editor.value.substring(end);
      editor.selectionStart = editor.selectionEnd = start + 2;
    }
    // Ctrl+Shift+F to format
    if ((e.ctrlKey || e.metaKey) && e.shiftKey && e.key === "F") {
      e.preventDefault();
      formatJSON();
    }
  });

  // ─── Toolbar buttons ──────────────────────────────────────────────────────

  btnFormat.addEventListener("click", formatJSON);

  btnCopy.addEventListener("click", function () {
    if (editor.value) {
      navigator.clipboard.writeText(editor.value).then(function () {
        btnCopy.textContent = "Copied!";
        setTimeout(function () { btnCopy.textContent = "Copy"; }, 1500);
      });
    }
  });

  var themes = ["dark", "light", "system"];
  var themeIdx = 0;
  btnTheme.addEventListener("click", function () {
    themeIdx = (themeIdx + 1) % themes.length;
    currentThemeOverride = themes[themeIdx];
    btnTheme.textContent = "Theme: " + currentThemeOverride;
    var val = editor.value.trim();
    if (val) renderPreview(val);
  });

  function formatJSON() {
    try {
      var parsed = JSON.parse(editor.value);
      editor.value = JSON.stringify(parsed, null, 2);
      setStatus("ok", "Formatted");
    } catch (e) {
      setStatus("err", "Cannot format: " + e.message);
    }
  }

  // ─── Resize handle ────────────────────────────────────────────────────────

  var isResizing = false;
  resizeHandle.addEventListener("mousedown", function (e) {
    isResizing = true;
    resizeHandle.classList.add("active");
    e.preventDefault();
  });
  document.addEventListener("mousemove", function (e) {
    if (!isResizing) return;
    var newWidth = Math.max(200, Math.min(e.clientX, window.innerWidth - 200));
    editorPanel.style.width = newWidth + "px";
  });
  document.addEventListener("mouseup", function () {
    if (isResizing) {
      isResizing = false;
      resizeHandle.classList.remove("active");
    }
  });

  // ─── Page navigation (event delegation for preview) ───────────────────────

  preview.addEventListener("click", function (e) {
    var btn = e.target.closest(".owg-nav-btn");
    if (!btn) return;
    var pageId = btn.getAttribute("data-page");
    if (!pageId) return;
    // Toggle active nav button
    var navBtns = preview.querySelectorAll(".owg-nav-btn");
    for (var i = 0; i < navBtns.length; i++) {
      navBtns[i].classList.toggle("owg-nav-active", navBtns[i] === btn);
    }
    // Toggle page visibility
    var pages = preview.querySelectorAll(".owg-page");
    for (var j = 0; j < pages.length; j++) {
      pages[j].classList.toggle("owg-page-hidden", pages[j].getAttribute("data-page-id") !== pageId);
    }
  });

  // ─── Load default preset on start ─────────────────────────────────────────

  var defaultPreset = JSON.stringify(PRESETS["Confirm"], null, 2);
  editor.value = defaultPreset;
  renderPreview(defaultPreset);

})();
