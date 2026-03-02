"use strict";
// Section renderers for the dynamic UI — form, items, text, actions, plus
// rich section types: progress, log, diff, table, tabs, metric, chart.

(function (OWG) {
  var esc = OWG.esc;
  var escAttr = OWG.escAttr;
  var safeClass = OWG.safeClass;
  var markdownBlock = OWG.markdownBlock;

  // Module-scope state for tabs — preserved across render() calls
  var activeTabs = Object.create(null);

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
      case "metric":    html += renderMetric(sec, si);          break;
      case "chart":     html += OWG.renderChart(sec, si);       break;
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
      var navAttr = item.navigateTo ? ' data-navigate-to="' + escAttr(item.navigateTo) + '"' : '';
      var navClass = item.navigateTo ? " owg-item-navigable" : "";
      html += '<div class="item-row' + navClass + safeClass(item.className) + '"' + navAttr + '>';
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
          var actionWithContext = Object.create(null);
          for (var _k in a) {
            if (!/^(__proto__|constructor|prototype)$/.test(_k)) actionWithContext[_k] = a[_k];
          }
          actionWithContext._item_id = item.id || String(ii);
          actionWithContext._item_index = ii;
          actionWithContext._section_index = si;
          actionWithContext._section_id = sec.id || "";
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
    return '<div class="message-box message-box-plain">' + esc(sec.content || "") + "</div>";
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

    // Client-side page navigation
    if (a.navigateTo) {
      dataAttrs += ' data-navigate-to="' + escAttr(a.navigateTo) + '"';
    }

    // Item context for per-item actions
    if (a._item_id !== undefined) {
      dataAttrs += ' data-item="' + escAttr(a._item_id) + '"';
      dataAttrs += ' data-item-index="' + escAttr(String(a._item_index)) + '"';
      if (a._section_id) dataAttrs += ' data-section-id="' + escAttr(a._section_id) + '"';
      dataAttrs += ' data-section-index="' + escAttr(String(a._section_index)) + '"';
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
    var clickable = !!sec.clickable;
    var clickAction = sec.clickActionId || "_table_row_click";
    var tableKey = "_table_" + si + "_selected";

    // Initialize selection in formValues
    if (selectable) OWG.formValues[tableKey] = [];

    var navigateToField = sec.navigateToField || "";

    var tableAttrs = ' data-table-index="' + si + '"';
    if (clickable) {
      tableAttrs += ' data-clickable="true" data-click-action="' + escAttr(clickAction) + '"';
      if (navigateToField) {
        tableAttrs += ' data-navigate-to-field="' + escAttr(navigateToField) + '"';
      }
    }
    var html = '<div class="table-container"><table class="owg-table"' + tableAttrs + '>';

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
      var trCls = clickable ? ' class="owg-table-clickable"' : "";
      html += "<tr" + trCls + ">";
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

  // ─── Metric cards ──────────────────────────────────────────────────────────
  function renderMetric(sec) {
    var cards = sec.cards || [];
    var cols = sec.columns || 4;
    if (cols < 1 || cols > 6) cols = 4;
    var html = '<div class="metric-grid" style="grid-template-columns: repeat(' + cols + ', 1fr)">';
    cards.forEach(function (card) {
      html += '<div class="metric-card">';
      html += '<div class="metric-label">' + esc(card.label || "") + "</div>";
      html += '<div class="metric-value-row">';
      html += '<span class="metric-value">' + esc(String(card.value != null ? card.value : "")) + "</span>";
      if (card.unit) html += '<span class="metric-unit">' + esc(card.unit) + "</span>";
      html += "</div>";
      if (card.change) {
        var dirClass = card.changeDirection === "up" ? "metric-up"
          : card.changeDirection === "down" ? "metric-down"
          : "metric-neutral";
        var arrow = card.changeDirection === "up" ? "\u25B2"
          : card.changeDirection === "down" ? "\u25BC"
          : "\u25CF";
        html += '<div class="metric-change ' + dirClass + '">';
        html += '<span class="metric-arrow">' + arrow + "</span> " + esc(card.change);
        html += "</div>";
      }
      if (card.sparkline && card.sparkline.length > 1) {
        html += OWG.renderSparkline(card.sparkline, 120, 32);
      }
      html += "</div>";
    });
    html += "</div>";
    return html;
  }

  // ─── Sparkline (inline SVG from data array) ───────────────────────────────
  OWG.renderSparkline = function (values, width, height) {
    if (!values || values.length < 2) return "";
    width = width || 120;
    height = height || 32;
    var min = Infinity, max = -Infinity;
    for (var i = 0; i < values.length; i++) {
      var v = Number(values[i]);
      if (v < min) min = v;
      if (v > max) max = v;
    }
    var range = max - min || 1;
    var pad = 1; // 1px padding so line isn't clipped at edges
    var drawH = height - pad * 2;
    var points = [];
    for (var j = 0; j < values.length; j++) {
      var x = (j / (values.length - 1)) * width;
      var y = pad + drawH - ((Number(values[j]) - min) / range) * drawH;
      points.push(x.toFixed(1) + "," + y.toFixed(1));
    }
    return '<svg class="owg-sparkline" viewBox="0 0 ' + width + " " + height +
      '" width="' + width + '" height="' + height +
      '" xmlns="http://www.w3.org/2000/svg">' +
      '<polyline points="' + escAttr(points.join(" ")) +
      '" fill="none" stroke="var(--blue)" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/></svg>';
  };

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
      var hiddenCls = tab.id === activeId ? "" : " owg-tabs-hidden";
      html += '<div class="tabs-panel' + hiddenCls + '" data-tab-id="' + escAttr(tab.id) + '" data-tabs-parent="' + si + '">';
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

  // ─── Selector-safe query helper (prevents CSS selector injection) ───────────
  function _esc(value) {
    return (typeof CSS !== "undefined" && CSS.escape) ? CSS.escape(value) : value.replace(/([\\"'\[\](){}|^$+*.?:#>~!])/g, "\\$&");
  }

  // ─── Tab/table event binding (called from app.js bindEvents) ────────────────
  OWG.bindSectionEvents = function (root) {
    // Tab switching — use dataset comparison to avoid selector injection
    root.querySelectorAll("[data-tab-target]").forEach(function (btn) {
      btn.addEventListener("click", function () {
        var target = btn.getAttribute("data-tab-target");
        var parent = btn.getAttribute("data-tabs-parent");
        activeTabs["tabs-" + parent] = target;

        // Update active button (iterate + compare, not string-concat selector)
        root.querySelectorAll("[data-tabs-parent].tabs-btn").forEach(function (b) {
          if (b.getAttribute("data-tabs-parent") === parent) {
            b.classList.toggle("tabs-active", b.getAttribute("data-tab-target") === target);
          }
        });
        // Show/hide panels (class-based — survives sanitizeHTML style stripping)
        root.querySelectorAll(".tabs-panel[data-tabs-parent]").forEach(function (p) {
          if (p.getAttribute("data-tabs-parent") === parent) {
            p.classList.toggle("owg-tabs-hidden", p.getAttribute("data-tab-id") !== target);
          }
        });
      });
    });

    // Table select-all checkboxes
    root.querySelectorAll("[data-table-select-all]").forEach(function (chk) {
      chk.addEventListener("change", function () {
        var ti = chk.getAttribute("data-table-select-all");
        var selected = [];
        var rowIdx = 0;
        root.querySelectorAll("[data-table-row]").forEach(function (r) {
          if (r.getAttribute("data-table-row") !== ti) return;
          r.checked = chk.checked;
          if (chk.checked) selected.push(rowIdx);
          rowIdx++;
        });
        OWG.formValues["_table_" + ti + "_selected"] = selected;
      });
    });

    // Table row checkboxes
    root.querySelectorAll("[data-table-row]").forEach(function (chk) {
      chk.addEventListener("change", function () {
        var ti = chk.getAttribute("data-table-row");
        var selected = [];
        var rowIdx = 0;
        root.querySelectorAll("[data-table-row]").forEach(function (r) {
          if (r.getAttribute("data-table-row") !== ti) return;
          if (r.checked) selected.push(rowIdx);
          rowIdx++;
        });
        OWG.formValues["_table_" + ti + "_selected"] = selected;
      });
    });

    // Navigable items (client-side page navigation on click)
    root.querySelectorAll(".owg-item-navigable[data-navigate-to]").forEach(function (item) {
      item.addEventListener("click", function (e) {
        // Don't navigate if user clicked an action button within the item
        if (e.target.closest("[data-action-id]")) return;
        var target = item.getAttribute("data-navigate-to");
        if (target && typeof OWG.navigateToPage === "function") {
          OWG.navigateToPage(target);
        }
      });
    });

    // Clickable table rows (drill-down or client-side navigation)
    root.querySelectorAll('.owg-table[data-clickable="true"]').forEach(function (table) {
      var tbody = table.querySelector("tbody");
      if (!tbody) return;
      var actionId = table.getAttribute("data-click-action") || "_table_row_click";
      var navField = table.getAttribute("data-navigate-to-field") || "";
      var ti = table.getAttribute("data-table-index");
      // Collect column keys from header for building row data
      var colKeys = [];
      table.querySelectorAll("thead th[data-sort-key]").forEach(function (th) {
        colKeys.push(th.getAttribute("data-sort-key"));
      });
      tbody.querySelectorAll("tr").forEach(function (tr, ri) {
        tr.addEventListener("click", function (e) {
          // Don't fire row click if user clicked a checkbox (selectable coexistence)
          if (e.target.type === "checkbox") return;
          var rowData = {};
          var cells = tr.querySelectorAll("td");
          // If selectable, skip the checkbox column
          var offset = table.querySelector("[data-table-select-all]") ? 1 : 0;
          colKeys.forEach(function (key, ci) {
            var cell = cells[ci + offset];
            rowData[key] = cell ? cell.textContent : "";
          });
          // Client-side navigation if navigateToField is set and row has the target page
          if (navField && rowData[navField] && typeof OWG.navigateToPage === "function") {
            OWG.navigateToPage(rowData[navField]);
            return;
          }
          // Fall back to emitting action to agent
          if (typeof OWG.emitAction === "function") {
            OWG.emitAction(actionId, "action", rowData, {
              section_index: ti,
              row_index: ri
            });
          }
        });
      });
    });

    // Table column sorting
    root.querySelectorAll(".table-sortable").forEach(function (th) {
      th.addEventListener("click", function () {
        var key = th.getAttribute("data-sort-key");
        var ti = th.getAttribute("data-table-index");
        var table = root.querySelector('.owg-table[data-table-index="' + _esc(ti) + '"]');
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

        // Rebuild selected indices after sort
        var newSelected = [];
        var sortRowIdx = 0;
        tbody.querySelectorAll("[data-table-row]").forEach(function (r) {
          if (r.getAttribute("data-table-row") !== ti) return;
          if (r.checked) newSelected.push(sortRowIdx);
          sortRowIdx++;
        });
        if (OWG.formValues["_table_" + ti + "_selected"]) {
          OWG.formValues["_table_" + ti + "_selected"] = newSelected;
        }
      });
    });
  };

})(window.OWG = window.OWG || {});
