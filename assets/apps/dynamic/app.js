"use strict";
// Dynamic UI renderer — reads everything from state.json schema.
// No custom code needed. Agent writes a schema, this renders it.

(function () {
  var wv = new OpenCodeWebview();
  var formValues = {};  // collects field values before submit
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
      els.loading.innerHTML = "<p style='color:var(--red)'>Connection failed: " + esc(String(err)) + "</p>";
    });

  wv.on("connected",     function (d) { render(d.state); });
  wv.on("state_updated", function (s) { if (!done) render(s); });
  wv.on("close",         function (d) {
    done = true;
    els.content.innerHTML = '<div class="done-state"><div class="done-icon">✓</div><div style="color:var(--green);font-weight:600">Session closed</div><div class="done-msg">' + esc((d && d.message) || "") + "</div></div>";
  });

  // ─── Main renderer ───────────────────────────────────────────────────────────
  function render(state) {
    if (!state) return;
    formValues = {};

    // Header
    var title = state.title || "OpenCode";
    document.title = title + " — OpenCode Webview";
    els.hdrTitle.textContent = title;

    var status = (state.status || "").replace(/_/g, " ");
    if (status) {
      els.hdrBadge.textContent = status;
      els.hdrBadge.className = "badge " + statusBadgeClass(state.status);
    } else {
      els.hdrBadge.textContent = "";
    }

    var ui = (state.data && state.data.ui) || state.data || {};
    var sections = ui.sections || [];
    var actions  = state.actions_requested || ui.actions || [];

    var html = "";

    // Message
    if (state.message) {
      html += '<div class="message-box">' + esc(state.message) + "</div>";
    }

    // Sections
    sections.forEach(function (sec, si) {
      html += renderSection(sec, si);
    });

    // Top-level actions (outside sections)
    if (actions.length) {
      html += '<div class="section"><div class="actions-bar" id="main-actions">';
      actions.forEach(function (a) {
        html += renderActionButton(a, "main");
      });
      html += "</div></div>";
    }

    els.loading.classList.add("hidden");
    els.content.classList.remove("hidden");
    els.content.innerHTML = html;
  }

  // ─── Section renderer ─────────────────────────────────────────────────────────
  function renderSection(sec, si) {
    var html = '<div class="section">';
    if (sec.title) html += '<div class="section-title">' + esc(sec.title) + "</div>";

    switch (sec.type) {
      case "form":      html += renderForm(sec, si);    break;
      case "items":     html += renderItems(sec, si);   break;
      case "text":      html += renderText(sec);        break;
      case "actions":   html += renderActionsSection(sec); break;
      default:          html += renderForm(sec, si);    break; // default to form
    }

    html += "</div>";
    return html;
  }

  // ─── Form ─────────────────────────────────────────────────────────────────────
  function renderForm(sec, si) {
    var fields = sec.fields || [];
    var cols = sec.columns === 2 ? "cols-2" : "cols-1";
    var html = '<div class="fields-grid ' + cols + '">';
    fields.forEach(function (f, fi) {
      html += renderField(f, si, fi);
    });
    html += "</div>";
    if (sec.actions && sec.actions.length) {
      html += '<div class="actions-bar" style="margin-top:12px">';
      sec.actions.forEach(function (a) {
        html += renderActionButton(a, "sec-" + si);
      });
      html += "</div>";
    }
    return html;
  }

  function renderField(f, si, fi) {
    var id = "f-" + si + "-" + fi;
    var key = f.key || id;
    var label = f.label || key;
    var desc = f.description ? '<div class="field-desc">' + esc(f.description) + "</div>" : "";

    // Pre-populate form values with defaults
    if (f.value !== undefined) formValues[key] = f.value;
    else if (f.default !== undefined) formValues[key] = f.default;

    var inner = "";
    switch (f.type) {
      case "textarea":
        inner = '<textarea id="' + id + '" rows="' + (f.rows || 3) + '" placeholder="' + esc(f.placeholder || "") + '" ' +
          'oninput="window._ocv_set(\'' + key + '\',this.value)">' + esc(f.value || f.default || "") + "</textarea>";
        break;
      case "select": {
        var opts = (f.options || []).map(function (o) {
          var v = typeof o === "object" ? o.value : o;
          var l = typeof o === "object" ? o.label : o;
          var sel = String(v) === String(f.value || f.default || "") ? " selected" : "";
          return '<option value="' + escAttr(v) + '"' + sel + ">" + esc(l) + "</option>";
        }).join("");
        inner = '<select id="' + id + '" onchange="window._ocv_set(\'' + key + '\',this.value)">' + opts + "</select>";
        break;
      }
      case "checkbox": {
        var chk = (f.value || f.default) ? " checked" : "";
        inner = '<label class="checkbox-wrap"><input type="checkbox" id="' + id + '"' + chk +
          ' onchange="window._ocv_set(\'' + key + '\',this.checked)"><span class="checkbox-label">' + esc(f.label || "") + "</span></label>";
        return '<div class="field">' + inner + desc + "</div>";
      }
      case "number":
        inner = '<input type="number" id="' + id + '" value="' + escAttr(String(f.value || f.default || "")) + '" ' +
          'placeholder="' + escAttr(f.placeholder || "") + '" min="' + (f.min || "") + '" max="' + (f.max || "") + '" ' +
          'oninput="window._ocv_set(\'' + key + '\',parseFloat(this.value)||0)">';
        break;
      case "static":
        inner = '<div class="field-static' + (f.mono ? " mono" : "") + '">' + esc(f.value || "") + "</div>";
        break;
      default: // text / email / url
        inner = '<input type="' + (f.type || "text") + '" id="' + id + '" value="' + escAttr(String(f.value || f.default || "")) + '" ' +
          'placeholder="' + escAttr(f.placeholder || "") + '" oninput="window._ocv_set(\'' + key + '\',this.value)">';
    }

    return '<div class="field"><div class="field-label">' + esc(label) + "</div>" + inner + desc + "</div>";
  }

  // ─── Items list ───────────────────────────────────────────────────────────────
  function renderItems(sec, si) {
    var items = sec.items || [];
    var html = '<div class="items-list">';
    items.forEach(function (item, ii) {
      html += '<div class="item-row">';
      html += '<div class="item-content">';
      if (item.title) html += '<div class="item-title">' + esc(item.title) + "</div>";
      if (item.subtitle) html += '<div class="item-subtitle">' + esc(item.subtitle) + "</div>";
      html += "</div>";
      if (item.actions && item.actions.length) {
        html += '<div class="item-actions">';
        item.actions.forEach(function (a) {
          var actionWithItem = Object.assign({}, a, { _item_id: item.id || String(ii) });
          html += renderActionButton(actionWithItem, "item-" + si + "-" + ii);
        });
        html += "</div>";
      }
      html += "</div>";
    });
    html += "</div>";
    return html;
  }

  // ─── Text block ───────────────────────────────────────────────────────────────
  function renderText(sec) {
    return '<div class="message-box">' + esc(sec.content || "") + "</div>";
  }

  // ─── Actions section ──────────────────────────────────────────────────────────
  function renderActionsSection(sec) {
    var html = '<div class="actions-bar">';
    (sec.actions || []).forEach(function (a) {
      html += renderActionButton(a, "sec-actions");
    });
    html += "</div>";
    return html;
  }

  // ─── Action button ────────────────────────────────────────────────────────────
  function renderActionButton(a, scope) {
    var btnClass = "btn btn-sm";
    switch (a.style || a.type) {
      case "approve": case "confirm": case "primary": btnClass += " btn-primary"; break;
      case "reject":  case "danger":  case "delete":  btnClass += " btn-danger";  break;
      case "success": case "submit":                  btnClass += " btn-success"; break;
      case "warning":                                 btnClass += " btn-warning"; break;
      case "ghost":                                   btnClass += " btn-ghost";   break;
    }
    var dataItem = a._item_id !== undefined ? ' data-item="' + escAttr(a._item_id) + '"' : "";
    var onclick = "window._ocv_action('" + escAttr(a.id) + "','" + escAttr(a.type || "action") + "','" + escAttr(scope) + "',this)";
    return '<button class="' + btnClass + '" onclick="' + onclick + '"' +
      dataItem + ' title="' + escAttr(a.description || "") + '">' + esc(a.label) + "</button>";
  }

  // ─── Global handlers (called from inline onclick) ─────────────────────────────
  window._ocv_set = function (key, value) {
    formValues[key] = value;
  };

  window._ocv_action = function (actionId, type, scope, btn) {
    if (done) return;

    // Collect value: form values, item id, or boolean
    var value;
    if (type === "approve" || type === "confirm" || type === "primary") {
      value = Object.keys(formValues).length ? Object.assign({}, formValues) : true;
    } else if (type === "reject" || type === "danger" || type === "delete") {
      value = Object.keys(formValues).length ? Object.assign({}, formValues) : false;
    } else if (type === "submit") {
      value = Object.assign({}, formValues);
    } else {
      // For item-scoped actions, include the item id
      var itemId = btn && btn.dataset && btn.dataset.item;
      value = itemId !== undefined ? { item_id: itemId, form: Object.assign({}, formValues) } : Object.assign({}, formValues);
    }

    btn.disabled = true;
    btn.textContent = "…";

    wv.sendAction(actionId, type, value).then(function () {
      // Replace the action button area with a sent indicator unless state update arrives
      if (btn.parentElement) {
        btn.parentElement.innerHTML = '<span style="color:var(--green);font-size:12px">✓ Sent — waiting for agent...</span>';
      }
    }).catch(function (err) {
      btn.disabled = false;
      btn.textContent = actionId;
      console.error("Action failed:", err);
    });
  };

  // ─── Utilities ────────────────────────────────────────────────────────────────
  function esc(s) {
    return String(s == null ? "" : s)
      .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
  }
  function escAttr(s) {
    return String(s == null ? "" : s).replace(/'/g, "&#39;").replace(/"/g, "&quot;");
  }
  function statusBadgeClass(s) {
    s = (s || "").toLowerCase();
    if (s.includes("error") || s.includes("fail") || s.includes("reject")) return "badge-danger";
    if (s.includes("warn") || s.includes("pending") || s.includes("review")) return "badge-warn";
    if (s.includes("ok") || s.includes("success") || s.includes("approv") || s.includes("done") || s.includes("complete")) return "badge-ok";
    return "badge-info";
  }
})();
