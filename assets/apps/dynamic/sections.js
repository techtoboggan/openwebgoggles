"use strict";
// Section renderers for the dynamic UI — form, items, text, actions, plus
// new rich section types: progress, log, diff, table, tabs.

(function (OWG) {
  var esc = OWG.esc;
  var escAttr = OWG.escAttr;
  var safeClass = OWG.safeClass;
  var markdownBlock = OWG.markdownBlock;

  // Module-scope state for tabs — preserved across render() calls
  var activeTabs = {};

  // ─── Section dispatcher ─────────────────────────────────────────────────────
  OWG.renderSection = function (sec, si) {
    var secId = sec.id ? ' data-section-id="' + escAttr(sec.id) + '"' : '';
    var html = '<div class="section' + safeClass(sec.className) + '"' + secId + ' data-section-index="' + si + '">';
    if (sec.title) html += '<div class="section-title">' + esc(sec.title) + "</div>";

    switch (sec.type) {
      case "form":      html += renderForm(sec, si);            break;
      case "items":     html += renderItems(sec, si);           break;
      case "text":      html += renderText(sec);                break;
      case "actions":   html += renderActionsSection(sec);      break;
      case "progress":  html += renderProgress(sec);            break;
      case "log":       html += renderLog(sec);                 break;
      case "diff":      html += renderDiff(sec);                break;
      case "table":     html += renderTable(sec, si);           break;
      case "tabs":      html += renderTabs(sec, si);            break;
      default:          html += renderForm(sec, si);            break;
    }

    html += "</div>";
    return html;
  };

  // ─── Form ───────────────────────────────────────────────────────────────────
  function renderForm(sec, si) {
    var fields = sec.fields || [];
    var cols = sec.columns === 2 ? "cols-2" : "cols-1";
    var html = '<div class="fields-grid ' + cols + '">';
    fields.forEach(function (f, fi) {
      html += OWG.renderField(f, si, fi);
    });
    html += "</div>";
    if (sec.actions && sec.actions.length) {
      html += '<div class="actions-bar" style="margin-top:12px">';
      sec.actions.forEach(function (a) {
        html += OWG.renderActionButton(a, "sec-" + si);
      });
      html += "</div>";
    }
    return html;
  }

  // ─── Field renderer ─────────────────────────────────────────────────────────
  // formValues and fieldValidators are stored on OWG by app.js
  OWG.renderField = function (f, si, fi) {
    var id = "f-" + si + "-" + fi;
    var key = f.key || id;
    var label = f.label || key;
    var desc = "";
    if (f.description) {
      desc = f.description_format === "markdown"
        ? '<div class="field-desc">' + markdownBlock(f.description) + "</div>"
        : '<div class="field-desc">' + esc(f.description) + "</div>";
    }
    var dataKey = ' data-field-key="' + escAttr(key) + '"';

    // Pre-populate form values with defaults
    if (f.value !== undefined) OWG.formValues[key] = f.value;
    else if (f.default !== undefined) OWG.formValues[key] = f.default;

    // Store validation config if present
    if (f.required || f.pattern || f.minLength || f.maxLength || f.errorMessage) {
      OWG.fieldValidators[key] = {
        required: !!f.required,
        pattern: f.pattern || null,
        minLength: f.minLength || null,
        maxLength: f.maxLength || null,
        min: f.min,
        max: f.max,
        errorMessage: f.errorMessage || null,
        type: f.type || "text"
      };
    }

    var requiredAttr = f.required ? ' data-required="true"' : '';

    var inner = "";
    switch (f.type) {
      case "textarea":
        inner = '<textarea id="' + id + '" rows="' + (f.rows || 3) + '" placeholder="' + esc(f.placeholder || "") + '"' +
          dataKey + requiredAttr + '>' + esc(f.value || f.default || "") + "</textarea>";
        break;
      case "select": {
        var opts = (f.options || []).map(function (o) {
          var v = typeof o === "object" ? o.value : o;
          var l = typeof o === "object" ? o.label : o;
          var sel = String(v) === String(f.value || f.default || "") ? " selected" : "";
          return '<option value="' + escAttr(v) + '"' + sel + ">" + esc(l) + "</option>";
        }).join("");
        inner = '<select id="' + id + '"' + dataKey + requiredAttr + '>' + opts + "</select>";
        break;
      }
      case "checkbox": {
        var chk = (f.value || f.default) ? " checked" : "";
        inner = '<label class="checkbox-wrap"><input type="checkbox" id="' + id + '"' + chk +
          dataKey + requiredAttr + '><span class="checkbox-label">' + esc(f.label || "") + "</span></label>";
        return '<div class="field' + safeClass(f.className) + '">' + inner + desc +
          '<div class="field-error" data-error-for="' + escAttr(key) + '"></div></div>';
      }
      case "number":
        inner = '<input type="number" id="' + id + '" value="' + escAttr(String(f.value || f.default || "")) + '" ' +
          'placeholder="' + escAttr(f.placeholder || "") + '" min="' + escAttr(String(f.min != null ? f.min : "")) + '" max="' + escAttr(String(f.max != null ? f.max : "")) + '"' +
          dataKey + requiredAttr + '>';
        break;
      case "static":
        if (f.format === "markdown") {
          inner = '<div class="field-static">' + markdownBlock(f.value || "") + "</div>";
        } else {
          inner = '<div class="field-static' + (f.mono ? " mono" : "") + '">' + esc(f.value || "") + "</div>";
        }
        break;
      default: {
        var ALLOWED_INPUT_TYPES = {text:1, email:1, url:1, tel:1, search:1, password:1, date:1, time:1, color:1};
        var inputType = (f.type && ALLOWED_INPUT_TYPES[f.type]) ? f.type : "text";
        inner = '<input type="' + inputType + '" id="' + id + '" value="' + escAttr(String(f.value || f.default || "")) + '" ' +
          'placeholder="' + escAttr(f.placeholder || "") + '"' + dataKey + requiredAttr + '>';
      }
    }

    var requiredMark = f.required ? '<span class="field-required">*</span>' : '';
    return '<div class="field' + safeClass(f.className) + '"><div class="field-label">' + esc(label) + requiredMark + "</div>" +
      inner + desc + '<div class="field-error" data-error-for="' + escAttr(key) + '"></div></div>';
  };

  // ─── Items list ─────────────────────────────────────────────────────────────
  function renderItems(sec, si) {
    var items = sec.items || [];
    var html = '<div class="items-list">';
    items.forEach(function (item, ii) {
      html += '<div class="item-row' + safeClass(item.className) + '">';
      html += '<div class="item-content">';
      if (item.title) {
        html += item.format === "markdown"
          ? '<div class="item-title">' + markdownBlock(item.title) + "</div>"
          : '<div class="item-title">' + esc(item.title) + "</div>";
      }
      if (item.subtitle) {
        html += item.format === "markdown"
          ? '<div class="item-subtitle">' + markdownBlock(item.subtitle) + "</div>"
          : '<div class="item-subtitle">' + esc(item.subtitle) + "</div>";
      }
      html += "</div>";
      if (item.actions && item.actions.length) {
        html += '<div class="item-actions">';
        item.actions.forEach(function (a) {
          var actionWithContext = Object.assign({}, a, {
            _item_id: item.id || String(ii),
            _item_index: ii,
            _section_index: si,
            _section_id: sec.id || ""
          });
          html += OWG.renderActionButton(actionWithContext, "item-" + si + "-" + ii);
        });
        html += "</div>";
      }
      html += "</div>";
    });
    html += "</div>";
    return html;
  }

  // ─── Text block ─────────────────────────────────────────────────────────────
  function renderText(sec) {
    if (sec.format === "markdown") {
      return '<div class="message-box">' + markdownBlock(sec.content || "") + "</div>";
    }
    return '<div class="message-box">' + esc(sec.content || "") + "</div>";
  }

  // ─── Actions section ────────────────────────────────────────────────────────
  function renderActionsSection(sec) {
    var html = '<div class="actions-bar">';
    (sec.actions || []).forEach(function (a) {
      html += OWG.renderActionButton(a, "sec-actions");
    });
    html += "</div>";
    return html;
  }

  // ─── Action button ──────────────────────────────────────────────────────────
  OWG.renderActionButton = function (a, scope) {
    var btnClass = "btn btn-sm";
    switch (a.style || a.type) {
      case "approve": case "confirm": case "primary": btnClass += " btn-primary"; break;
      case "reject":  case "danger":  case "delete":  btnClass += " btn-danger";  break;
      case "success": case "submit":                  btnClass += " btn-success"; break;
      case "warning":                                 btnClass += " btn-warning"; break;
      case "ghost":                                   btnClass += " btn-ghost";   break;
    }
    var dataAttrs = ' data-action-id="' + escAttr(a.id) + '"' +
      ' data-action-type="' + escAttr(a.type || "action") + '"' +
      ' data-action-scope="' + escAttr(scope) + '"';

    // Item context for per-item actions
    if (a._item_id !== undefined) {
      dataAttrs += ' data-item="' + escAttr(a._item_id) + '"';
      dataAttrs += ' data-item-index="' + a._item_index + '"';
      if (a._section_id) dataAttrs += ' data-section-id="' + escAttr(a._section_id) + '"';
      dataAttrs += ' data-section-index="' + a._section_index + '"';
    }

    return '<button class="' + btnClass + '"' + dataAttrs +
      ' title="' + escAttr(a.description || "") + '">' + esc(a.label) + "</button>";
  };

  // ═══════════════════════════════════════════════════════════════════════════
  // New section types
  // ═══════════════════════════════════════════════════════════════════════════

  // ─── Progress ───────────────────────────────────────────────────────────────
  var STATUS_ICONS = {pending: "\u25CB", in_progress: "\u25D0", completed: "\u25CF", failed: "\u2715", skipped: "\u2298"};
  var STATUS_CLASSES = {pending: "", in_progress: "owg-text-blue", completed: "owg-text-green", failed: "owg-text-red", skipped: "owg-text-muted"};

  function renderProgress(sec) {
    var tasks = sec.tasks || [];
    var pct = sec.percentage;
    var html = "";

    if (pct !== undefined && pct !== null) {
      var clamped = Math.min(100, Math.max(0, pct));
      html += '<div class="progress-bar-wrap"><div class="progress-bar-fill" style="width:' + clamped + '%"></div>' +
        '<span class="progress-pct">' + Math.round(clamped) + "%</span></div>";
    }

    html += '<div class="progress-tasks">';
    tasks.forEach(function (t) {
      var icon = STATUS_ICONS[t.status] || STATUS_ICONS.pending;
      var cls = STATUS_CLASSES[t.status] || "";
      html += '<div class="progress-task ' + cls + '"><span class="progress-icon">' + icon + "</span> " + esc(t.label || "") + "</div>";
    });
    html += "</div>";
    return html;
  }

  // ─── Log ────────────────────────────────────────────────────────────────────
  function renderLog(sec) {
    var lines = sec.lines || [];
    var maxLines = sec.maxLines || 500;
    var displayLines = lines.slice(-maxLines);
    var autoScroll = sec.autoScroll !== false ? "true" : "false";

    var html = '<div class="log-container" data-autoscroll="' + autoScroll + '">';
    displayLines.forEach(function (line) {
      html += '<div class="log-line">' + OWG.escAnsi(esc(String(line))) + "</div>";
    });
    html += "</div>";
    return html;
  }

  // ─── Diff ───────────────────────────────────────────────────────────────────
  function renderDiff(sec) {
    var content = sec.content || "";
    var lines = content.split("\n");
    var html = '<div class="diff-container">';

    var oldNum = 0, newNum = 0;
    lines.forEach(function (line) {
      var cls = "diff-line";
      var gutterOld = "", gutterNew = "";

      if (line.startsWith("@@")) {
        cls += " diff-hunk";
        // Parse hunk header: @@ -oldStart,oldLen +newStart,newLen @@
        var match = line.match(/@@ -(\d+)(?:,\d+)? \+(\d+)/);
        if (match) { oldNum = parseInt(match[1], 10) - 1; newNum = parseInt(match[2], 10) - 1; }
        gutterOld = "..."; gutterNew = "...";
      } else if (line.startsWith("+++") || line.startsWith("---") || line.startsWith("diff ") || line.startsWith("index ")) {
        cls += " diff-meta";
      } else if (line.startsWith("+")) {
        cls += " diff-add";
        newNum++;
        gutterNew = String(newNum);
      } else if (line.startsWith("-")) {
        cls += " diff-remove";
        oldNum++;
        gutterOld = String(oldNum);
      } else {
        cls += " diff-context";
        oldNum++; newNum++;
        gutterOld = String(oldNum);
        gutterNew = String(newNum);
      }

      html += '<div class="' + cls + '">' +
        '<span class="diff-gutter diff-gutter-old">' + esc(gutterOld) + '</span>' +
        '<span class="diff-gutter diff-gutter-new">' + esc(gutterNew) + '</span>' +
        '<span class="diff-text">' + esc(line) + "</span></div>";
    });

    html += "</div>";
    return html;
  }

  // ─── Table ──────────────────────────────────────────────────────────────────
  function renderTable(sec, si) {
    var cols = sec.columns || [];
    var rows = sec.rows || [];
    var selectable = !!sec.selectable;
    var tableKey = "_table_" + si + "_selected";

    // Initialize selection in formValues
    if (selectable) OWG.formValues[tableKey] = [];

    var html = '<div class="table-container"><table class="owg-table" data-table-index="' + si + '">';

    // Header
    html += "<thead><tr>";
    if (selectable) html += '<th class="table-check-col"><input type="checkbox" data-table-select-all="' + si + '"></th>';
    cols.forEach(function (col) {
      html += '<th data-sort-key="' + escAttr(col.key) + '" data-table-index="' + si + '" class="table-sortable">' +
        esc(col.label || col.key) + ' <span class="sort-indicator"></span></th>';
    });
    html += "</tr></thead>";

    // Body
    html += "<tbody>";
    rows.forEach(function (row, ri) {
      html += "<tr>";
      if (selectable) html += '<td><input type="checkbox" data-table-row="' + si + '" data-row-index="' + ri + '"></td>';
      cols.forEach(function (col) {
        var cellVal = row[col.key];
        html += "<td>" + esc(cellVal != null ? String(cellVal) : "") + "</td>";
      });
      html += "</tr>";
    });
    html += "</tbody></table></div>";
    return html;
  }

  // ─── Tabs ───────────────────────────────────────────────────────────────────
  function renderTabs(sec, si) {
    var tabs = sec.tabs || [];
    if (!tabs.length) return "";

    var tabsKey = "tabs-" + si;
    var activeId = activeTabs[tabsKey] || sec.activeTab || (tabs[0] && tabs[0].id) || "";

    var html = '<div class="tabs-container" data-tabs-id="' + si + '">';

    // Tab bar
    html += '<div class="tabs-bar">';
    tabs.forEach(function (tab) {
      var active = tab.id === activeId ? " tabs-active" : "";
      html += '<button class="tabs-btn' + active + '" data-tab-target="' + escAttr(tab.id) + '" data-tabs-parent="' + si + '">' +
        esc(tab.label || tab.id) + "</button>";
    });
    html += "</div>";

    // Tab panels
    tabs.forEach(function (tab) {
      var display = tab.id === activeId ? "" : ' style="display:none"';
      html += '<div class="tabs-panel" data-tab-id="' + escAttr(tab.id) + '" data-tabs-parent="' + si + '"' + display + '>';
      (tab.sections || []).forEach(function (nested, ni) {
        html += OWG.renderSection(nested, si + "-tab-" + tab.id + "-" + ni);
      });
      html += "</div>";
    });

    html += "</div>";
    return html;
  }

  // ─── Post-render hooks ──────────────────────────────────────────────────────
  // Called by app.js after safeHTML + bindEvents to handle section-specific setup.
  OWG.postRenderSections = function () {
    // Auto-scroll log containers
    var logs = document.querySelectorAll('.log-container[data-autoscroll="true"]');
    for (var i = 0; i < logs.length; i++) {
      logs[i].scrollTop = logs[i].scrollHeight;
    }
  };

  // ─── Tab/table event binding (called from app.js bindEvents) ────────────────
  OWG.bindSectionEvents = function (root) {
    // Tab switching
    root.querySelectorAll("[data-tab-target]").forEach(function (btn) {
      btn.addEventListener("click", function () {
        var target = btn.getAttribute("data-tab-target");
        var parent = btn.getAttribute("data-tabs-parent");
        activeTabs["tabs-" + parent] = target;

        // Update active button
        root.querySelectorAll('[data-tabs-parent="' + parent + '"].tabs-btn').forEach(function (b) {
          b.classList.toggle("tabs-active", b.getAttribute("data-tab-target") === target);
        });
        // Show/hide panels
        root.querySelectorAll('.tabs-panel[data-tabs-parent="' + parent + '"]').forEach(function (p) {
          p.style.display = p.getAttribute("data-tab-id") === target ? "" : "none";
        });
      });
    });

    // Table select-all checkboxes
    root.querySelectorAll("[data-table-select-all]").forEach(function (chk) {
      chk.addEventListener("change", function () {
        var ti = chk.getAttribute("data-table-select-all");
        var rows = root.querySelectorAll('[data-table-row="' + ti + '"]');
        var selected = [];
        rows.forEach(function (r, i) {
          r.checked = chk.checked;
          if (chk.checked) selected.push(i);
        });
        OWG.formValues["_table_" + ti + "_selected"] = selected;
      });
    });

    // Table row checkboxes
    root.querySelectorAll("[data-table-row]").forEach(function (chk) {
      chk.addEventListener("change", function () {
        var ti = chk.getAttribute("data-table-row");
        var selected = [];
        root.querySelectorAll('[data-table-row="' + ti + '"]').forEach(function (r, i) {
          if (r.checked) selected.push(i);
        });
        OWG.formValues["_table_" + ti + "_selected"] = selected;
      });
    });

    // Table column sorting
    root.querySelectorAll(".table-sortable").forEach(function (th) {
      th.addEventListener("click", function () {
        var key = th.getAttribute("data-sort-key");
        var ti = th.getAttribute("data-table-index");
        var table = root.querySelector('.owg-table[data-table-index="' + ti + '"]');
        if (!table) return;

        var tbody = table.querySelector("tbody");
        var rows = Array.prototype.slice.call(tbody.querySelectorAll("tr"));
        var colIdx = Array.prototype.indexOf.call(th.parentNode.children, th);

        // Toggle sort direction
        var asc = th.getAttribute("data-sort-dir") !== "asc";
        th.setAttribute("data-sort-dir", asc ? "asc" : "desc");

        // Clear other indicators
        table.querySelectorAll(".sort-indicator").forEach(function (s) { s.textContent = ""; });
        th.querySelector(".sort-indicator").textContent = asc ? " \u25B2" : " \u25BC";

        rows.sort(function (a, b) {
          var aVal = a.children[colIdx] ? a.children[colIdx].textContent : "";
          var bVal = b.children[colIdx] ? b.children[colIdx].textContent : "";
          var aNum = parseFloat(aVal), bNum = parseFloat(bVal);
          if (!isNaN(aNum) && !isNaN(bNum)) return asc ? aNum - bNum : bNum - aNum;
          return asc ? aVal.localeCompare(bVal) : bVal.localeCompare(aVal);
        });

        rows.forEach(function (row) { tbody.appendChild(row); });
      });
    });
  };

})(window.OWG = window.OWG || {});
