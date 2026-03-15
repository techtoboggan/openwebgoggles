"use strict";
// Section renderers for the dynamic UI — form, items, text, actions, plus
// rich section types: progress, log, diff, table, tabs, metric, chart.

(function (OWG) {
  var esc = OWG.esc;
  var escAttr = OWG.escAttr;
  var safeClass = OWG.safeClass;
  var markdownBlock = OWG.markdownBlock;

  // ─── Plugin registry ──────────────────────────────────────────────────────
  // Custom section renderers registered by plugins before OWG freeze.
  // Plugins call OWG.registerPlugin(typeName, renderFn) to register.
  var _plugins = Object.create(null);
  var _pluginPostRender = [];
  var _BUILTINS = ["form","items","text","actions","progress","log","diff","table","tabs","metric","chart","tree","timeline","heatmap","network"];

  OWG.registerPlugin = function (typeName, renderFn) {
    if (typeof typeName !== "string" || !/^[a-z][a-z0-9_-]{0,30}$/.test(typeName)) {
      console.error("OWG plugin: invalid type name:", typeName);
      return false;
    }
    if (typeof renderFn !== "function") {
      console.error("OWG plugin: render must be a function for type:", typeName);
      return false;
    }
    if (_BUILTINS.indexOf(typeName) !== -1) {
      console.error("OWG plugin: cannot override built-in type:", typeName);
      return false;
    }
    _plugins[typeName] = renderFn;
    return true;
  };

  OWG.registerPluginPostRender = function (fn) {
    if (typeof fn === "function") _pluginPostRender.push(fn);
  };

  OWG.getRegisteredPlugins = function () {
    return Object.keys(_plugins);
  };

  // Module-scope state for tabs — preserved across render() calls
  var activeTabs = Object.create(null);

  // ─── Section dispatcher ─────────────────────────────────────────────────────
  OWG.renderSection = function (sec, si) {
    var secId = sec.id ? ' data-section-id="' + escAttr(sec.id) + '"' : '';
    var html = '<div class="section' + safeClass(sec.className) + '"' + secId + ' data-section-index="' + si + '">';

    var bodyId = "sec-body-" + si;
    var isCollapsible = !!sec.collapsible && !!sec.title;
    var isCollapsed = isCollapsible && !!sec.collapsed;

    if (sec.title) {
      if (isCollapsible) {
        html += '<div class="section-title section-title-collapsible" data-collapse-target="' + escAttr(String(bodyId)) + '">' +
          '<span class="section-toggle">' + (isCollapsed ? "\u25B6" : "\u25BC") + "</span>" + esc(sec.title) + "</div>";
      } else {
        html += '<div class="section-title">' + esc(sec.title) + "</div>";
      }
    }

    var bodyHtml = "";
    switch (sec.type) {
      case "form":      bodyHtml += renderForm(sec, si);            break;
      case "items":     bodyHtml += renderItems(sec, si);           break;
      case "text":      bodyHtml += renderText(sec);                break;
      case "actions":   bodyHtml += renderActionsSection(sec);      break;
      case "progress":  bodyHtml += renderProgress(sec);            break;
      case "log":       bodyHtml += renderLog(sec);                 break;
      case "diff":      bodyHtml += renderDiff(sec);                break;
      case "table":     bodyHtml += renderTable(sec, si);           break;
      case "tabs":      bodyHtml += renderTabs(sec, si);            break;
      case "metric":    bodyHtml += renderMetric(sec, si);          break;
      case "chart":     bodyHtml += OWG.renderChart(sec, si);       break;
      case "tree":      bodyHtml += renderTree(sec, si);            break;
      case "timeline":  bodyHtml += renderTimeline(sec);            break;
      case "heatmap":   bodyHtml += renderHeatmap(sec);             break;
      case "network":   bodyHtml += renderNetwork(sec, si);         break;
      default:
        if (Object.prototype.hasOwnProperty.call(_plugins, sec.type)) {
          bodyHtml += _plugins[sec.type](sec, si, OWG);
        } else {
          bodyHtml += renderForm(sec, si);
        }
        break;
    }

    if (isCollapsible) {
      html += '<div class="section-body' + (isCollapsed ? " section-body-collapsed" : "") + '" id="' + escAttr(String(bodyId)) + '">' + bodyHtml + "</div>";
    } else {
      html += bodyHtml;
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
      case "static": {
        var staticContent = f.value || "";
        var copyBtnStatic = f.copyable ? '<button class="owg-copy-btn" aria-label="Copy" data-copy-content="' + escAttr(staticContent) + '">\u2398</button>' : '';
        if (f.format === "markdown") {
          inner = '<div class="field-static">' + copyBtnStatic + markdownBlock(staticContent) + "</div>";
        } else {
          inner = '<div class="field-static' + (f.mono ? " mono" : "") + '">' + copyBtnStatic + esc(staticContent) + "</div>";
        }
        break;
      }
      case "slider": {
        var sliderVal = f.value != null ? f.value : (f.default != null ? f.default : (f.min || 0));
        var sliderMin = f.min != null ? escAttr(String(f.min)) : "0";
        var sliderMax = f.max != null ? escAttr(String(f.max)) : "100";
        var sliderStep = f.step != null ? escAttr(String(f.step)) : "1";
        var spanId = id + "-val";
        var unitAttr = f.unit ? ' data-unit="' + escAttr(String(f.unit)) + '"' : '';
        inner = '<div class="slider-wrap">' +
          '<input type="range" id="' + id + '" min="' + sliderMin + '" max="' + sliderMax + '" step="' + sliderStep + '" value="' + escAttr(String(sliderVal)) + '"' + unitAttr + dataKey + '>' +
          '<span class="slider-value" id="' + escAttr(spanId) + '">' + esc(String(sliderVal)) + (f.unit ? ' ' + esc(String(f.unit)) : '') + '</span>' +
          '</div>';
        OWG.formValues[key] = sliderVal;
        // Store validator with min/max for range validation
        OWG.fieldValidators[key] = OWG.fieldValidators[key] || { required: !!f.required, type: "slider" };
        OWG.fieldValidators[key].min = f.min != null ? f.min : null;
        OWG.fieldValidators[key].max = f.max != null ? f.max : null;
        break;
      }
      case "date":
        inner = '<input type="date" id="' + id + '" value="' + escAttr(f.value || f.default || "") + '"' +
          (f.min ? ' min="' + escAttr(String(f.min)) + '"' : '') +
          (f.max ? ' max="' + escAttr(String(f.max)) + '"' : '') +
          dataKey + requiredAttr + '>';
        break;
      case "datetime":
        inner = '<input type="datetime-local" id="' + id + '" value="' + escAttr(f.value || f.default || "") + '"' +
          (f.min ? ' min="' + escAttr(String(f.min)) + '"' : '') +
          (f.max ? ' max="' + escAttr(String(f.max)) + '"' : '') +
          dataKey + requiredAttr + '>';
        break;
      case "autocomplete": {
        var dlId = id + "-dl";
        var acOpts = (f.options || []).map(function (o) {
          var v = typeof o === "object" ? String(o.value) : String(o);
          return '<option value="' + escAttr(v) + '">';
        }).join("");
        inner = '<input type="text" id="' + id + '" list="' + escAttr(dlId) + '"' +
          ' value="' + escAttr(String(f.value || f.default || "")) + '"' +
          ' placeholder="' + escAttr(f.placeholder || "") + '"' +
          (f.allowCustom === false ? ' data-allow-custom="false"' : '') +
          dataKey + requiredAttr + '>' +
          '<datalist id="' + escAttr(dlId) + '">' + acOpts + '</datalist>';
        if (f.allowCustom === false) {
          OWG.fieldValidators[key] = OWG.fieldValidators[key] || { required: !!f.required, type: "autocomplete" };
          OWG.fieldValidators[key].allowCustom = false;
          OWG.fieldValidators[key].options = (f.options || []).map(function (o) {
            return typeof o === "object" ? String(o.value) : String(o);
          });
        }
        break;
      }
      case "file": {
        var acceptAttr = f.accept ? ' accept="' + escAttr(String(f.accept)) + '"' : '';
        var multipleAttr = f.multiple ? ' multiple' : '';
        var maxSizeBytes = f.maxSize || 524288; // default 512 KB
        inner = '<div class="file-upload-wrap">' +
          '<input type="file" id="' + id + '"' + acceptAttr + multipleAttr +
          ' data-max-size="' + escAttr(String(maxSizeBytes)) + '"' +
          dataKey + requiredAttr + ' style="display:none">' +
          '<label for="' + escAttr(id) + '" class="file-upload-btn">Choose file' + (f.multiple ? 's' : '') + '\u2026</label>' +
          '<span class="file-upload-status" id="' + escAttr(id) + '-status">No file chosen</span>' +
          '</div>';
        // File validator: track required + maxSize
        OWG.fieldValidators[key] = OWG.fieldValidators[key] || { required: !!f.required, type: "file" };
        OWG.fieldValidators[key].maxSize = maxSizeBytes;
        OWG.fieldValidators[key].multiple = !!f.multiple;
        // Default value: null (no file selected)
        OWG.formValues[key] = null;
        break;
      }
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
    var copyBtn = sec.copyable ? '<button class="owg-copy-btn" aria-label="Copy to clipboard" data-copy-content="' + escAttr(sec.content || "") + '">\u2398</button>' : '';
    if (sec.format === "markdown") {
      return '<div class="message-box' + (sec.copyable ? " message-box-copyable" : "") + '">' + copyBtn + markdownBlock(sec.content || "") + "</div>";
    }
    return '<div class="message-box message-box-plain' + (sec.copyable ? " message-box-copyable" : "") + '">' + copyBtn + esc(sec.content || "") + "</div>";
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
    var filterable = !!sec.filterable;
    var filterPh = sec.filterPlaceholder || "Filter rows...";
    var html = "";
    if (filterable) {
      html += '<div class="table-filter-bar">' +
        '<input type="search" class="owg-table-filter" placeholder="' + escAttr(filterPh) + '" data-table-filter="' + escAttr(String(si)) + '" aria-label="Filter table">' +
        '<span class="table-row-count" data-table-count="' + escAttr(String(si)) + '"></span>' +
        '</div>';
    }
    html += '<div class="table-container"><table class="owg-table"' + tableAttrs + '>';

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
    // Run plugin post-render hooks
    for (var pi = 0; pi < _pluginPostRender.length; pi++) {
      try { _pluginPostRender[pi](); } catch (e) { console.error("Plugin post-render error:", e); }
    }
  };

  // ─── Selector-safe query helper (prevents CSS selector injection) ───────────
  function _esc(value) {
    return (typeof CSS !== "undefined" && CSS.escape) ? CSS.escape(value) : value.replace(/([\\"'\[\](){}|^$+*.?:#>~!])/g, "\\$&");
  }

  // ─── Network Diagram ────────────────────────────────────────────────────────
  function renderNetwork(sec, si) {
    var nodes = Array.isArray(sec.nodes) ? sec.nodes : [];
    var edges = Array.isArray(sec.edges) ? sec.edges : [];
    if (!nodes.length) return '<div class="owg-network-empty">No network nodes</div>';

    var W = 580, H = 360;
    var nodeR = 22;
    var iterations = 80;
    var colorMap = { blue: "#58a6ff", green: "#3fb950", red: "#f85149", yellow: "#d29922", purple: "#a371f7", orange: "#f0883e", cyan: "#39c5cf", pink: "#e85aad" };

    // Initialize node positions in a circle
    var pos = [];
    for (var i = 0; i < nodes.length; i++) {
      var angle = (2 * Math.PI * i) / nodes.length;
      pos.push({ x: W / 2 + (W / 3) * Math.cos(angle), y: H / 2 + (H / 3) * Math.sin(angle) });
    }

    // Build adjacency for spring forces
    var nodeIdxMap = Object.create(null);
    for (var ni = 0; ni < nodes.length; ni++) nodeIdxMap[nodes[ni].id] = ni;

    // Force-directed layout: repulsion + spring
    var springLen = 120, repulse = 8000, damping = 0.85;
    var vx = [], vy = [];
    for (var vi = 0; vi < nodes.length; vi++) { vx.push(0); vy.push(0); }

    for (var it = 0; it < iterations; it++) {
      var fx = [], fy = [];
      for (var fi = 0; fi < nodes.length; fi++) { fx.push(0); fy.push(0); }

      // Repulsion between all pairs
      for (var a = 0; a < nodes.length; a++) {
        for (var b = a + 1; b < nodes.length; b++) {
          var dx = pos[a].x - pos[b].x, dy = pos[a].y - pos[b].y;
          var dist = Math.sqrt(dx * dx + dy * dy) || 1;
          var force = repulse / (dist * dist);
          var nx2 = dx / dist, ny2 = dy / dist;
          fx[a] += force * nx2; fy[a] += force * ny2;
          fx[b] -= force * nx2; fy[b] -= force * ny2;
        }
      }

      // Spring attraction for edges
      for (var ei2 = 0; ei2 < edges.length; ei2++) {
        var srcIdx = nodeIdxMap[edges[ei2].from], dstIdx = nodeIdxMap[edges[ei2].to];
        if (srcIdx == null || dstIdx == null) continue;
        var dx2 = pos[dstIdx].x - pos[srcIdx].x, dy2 = pos[dstIdx].y - pos[srcIdx].y;
        var dist2 = Math.sqrt(dx2 * dx2 + dy2 * dy2) || 1;
        var springF = (dist2 - springLen) * 0.05;
        var nxs = dx2 / dist2, nys = dy2 / dist2;
        fx[srcIdx] += springF * nxs; fy[srcIdx] += springF * nys;
        fx[dstIdx] -= springF * nxs; fy[dstIdx] -= springF * nys;
      }

      // Center gravity
      for (var gi = 0; gi < nodes.length; gi++) {
        fx[gi] += (W / 2 - pos[gi].x) * 0.01;
        fy[gi] += (H / 2 - pos[gi].y) * 0.01;
      }

      // Integrate
      for (var ii = 0; ii < nodes.length; ii++) {
        vx[ii] = (vx[ii] + fx[ii]) * damping;
        vy[ii] = (vy[ii] + fy[ii]) * damping;
        pos[ii].x = Math.max(nodeR + 5, Math.min(W - nodeR - 5, pos[ii].x + vx[ii]));
        pos[ii].y = Math.max(nodeR + 5, Math.min(H - nodeR - 5, pos[ii].y + vy[ii]));
      }
    }

    var uid = "owg-net-" + si;
    var svg = '<svg id="' + escAttr(uid) + '" class="owg-network-svg" viewBox="0 0 ' + W + " " + H + '" role="img" aria-label="Network diagram">';

    // Arrow marker
    svg += '<defs><marker id="' + escAttr(uid) + '-arrow" markerWidth="8" markerHeight="6" refX="8" refY="3" orient="auto">' +
      '<polygon points="0 0, 8 3, 0 6" class="owg-net-arrowhead"/></marker></defs>';

    // Edges
    for (var edi = 0; edi < edges.length; edi++) {
      var edge = edges[edi];
      var si2 = nodeIdxMap[edge.from], di = nodeIdxMap[edge.to];
      if (si2 == null || di == null) continue;
      var sx = pos[si2].x, sy = pos[si2].y, dx3 = pos[di].x, dy3 = pos[di].y;
      // Shorten line to node radius
      var dlen = Math.sqrt((dx3-sx)*(dx3-sx)+(dy3-sy)*(dy3-sy)) || 1;
      var ex = dx3 - (dx3-sx)/dlen*(nodeR+2), ey = dy3 - (dy3-sy)/dlen*(nodeR+2);
      svg += '<line x1="' + sx + '" y1="' + sy + '" x2="' + ex + '" y2="' + ey + '" class="owg-net-edge" marker-end="url(#' + escAttr(uid) + '-arrow)"/>';
      if (edge.label) {
        var mx = (sx + dx3) / 2, my = (sy + dy3) / 2;
        svg += '<text x="' + mx + '" y="' + (my - 4) + '" class="owg-net-edge-label" text-anchor="middle">' + esc(String(edge.label)) + "</text>";
      }
    }

    // Nodes
    for (var ni2 = 0; ni2 < nodes.length; ni2++) {
      var node = nodes[ni2];
      var px = pos[ni2].x, py = pos[ni2].y;
      var fill = colorMap[node.color] || (node.color && node.color.charAt(0) === "#" ? node.color : "var(--blue)");
      svg += '<circle cx="' + px + '" cy="' + py + '" r="' + nodeR + '" class="owg-net-node" style="fill:' + escAttr(fill) + '">';
      if (node.id) svg += "<title>" + esc(String(node.id)) + "</title>";
      svg += "</circle>";
      var displayLabel = node.label != null ? String(node.label) : String(node.id || "");
      svg += '<text x="' + px + '" y="' + (py + 4) + '" class="owg-net-label" text-anchor="middle">' + esc(displayLabel) + "</text>";
    }

    svg += "</svg>";
    return '<div class="owg-network">' + svg + "</div>";
  }

  // ─── Heatmap / Matrix ───────────────────────────────────────────────────────
  function renderHeatmap(sec) {
    var xLabels = Array.isArray(sec.xLabels) ? sec.xLabels : [];
    var yLabels = Array.isArray(sec.yLabels) ? sec.yLabels : [];
    var values = Array.isArray(sec.values) ? sec.values : [];
    if (!xLabels.length || !yLabels.length) return '<div class="owg-heatmap-empty">No heatmap data</div>';

    // Find min/max for color scale
    var minVal = Infinity, maxVal = -Infinity;
    for (var ri = 0; ri < values.length; ri++) {
      var row = values[ri];
      if (!Array.isArray(row)) continue;
      for (var ci = 0; ci < row.length; ci++) {
        var v = row[ci];
        if (typeof v === "number" && isFinite(v)) {
          if (v < minVal) minVal = v;
          if (v > maxVal) maxVal = v;
        }
      }
    }
    if (!isFinite(minVal)) { minVal = 0; maxVal = 1; }
    var range = maxVal - minVal || 1;

    // Parse color scale
    var cs = Array.isArray(sec.colorScale) && sec.colorScale.length === 2 ? sec.colorScale : null;
    var minColor = cs ? cs[0] : "#eaffea";
    var maxColor = cs ? cs[1] : "#ff4444";

    // Parse hex color to [r,g,b]
    function hexToRgb(hex) {
      var h = hex.replace("#", "");
      if (h.length === 3) h = h[0]+h[0]+h[1]+h[1]+h[2]+h[2];
      return [parseInt(h.slice(0,2),16), parseInt(h.slice(2,4),16), parseInt(h.slice(4,6),16)];
    }
    var r0, g0, b0, r1, g1, b1;
    // Only parse hex colors (theme names need CSS variables — use defaults for them)
    if (minColor.charAt(0) === "#" && maxColor.charAt(0) === "#") {
      var c0 = hexToRgb(minColor), c1 = hexToRgb(maxColor);
      r0 = c0[0]; g0 = c0[1]; b0 = c0[2];
      r1 = c1[0]; g1 = c1[1]; b1 = c1[2];
    } else {
      r0 = 234; g0 = 255; b0 = 234;  // #eaffea default
      r1 = 255; g1 = 68; b1 = 68;    // #ff4444 default
    }

    function cellColor(val) {
      var t = (val - minVal) / range;
      var r = Math.round(r0 + (r1 - r0) * t);
      var g = Math.round(g0 + (g1 - g0) * t);
      var b = Math.round(b0 + (b1 - b0) * t);
      return "rgb(" + r + "," + g + "," + b + ")";
    }

    var cellSize = Math.max(20, Math.min(50, Math.floor(400 / Math.max(xLabels.length, 1))));
    var labelW = 60;
    var headerH = 30;
    var svgW = labelW + xLabels.length * cellSize + 10;
    var svgH = headerH + yLabels.length * cellSize + 4;

    var svg = '<svg class="owg-heatmap-svg" viewBox="0 0 ' + svgW + " " + svgH + '" role="img" aria-label="Heatmap">';

    // X-axis labels
    for (var xi = 0; xi < xLabels.length; xi++) {
      var cx = labelW + xi * cellSize + cellSize / 2;
      svg += '<text x="' + cx + '" y="' + (headerH - 6) + '" class="owg-hm-label owg-hm-xlabel" text-anchor="middle">' + esc(String(xLabels[xi])) + "</text>";
    }

    // Rows
    for (var yi = 0; yi < yLabels.length; yi++) {
      var rowY = headerH + yi * cellSize;
      // Y-axis label
      svg += '<text x="' + (labelW - 4) + '" y="' + (rowY + cellSize / 2 + 4) + '" class="owg-hm-label owg-hm-ylabel" text-anchor="end">' + esc(String(yLabels[yi])) + "</text>";
      var rowData = Array.isArray(values[yi]) ? values[yi] : [];
      for (var xi2 = 0; xi2 < xLabels.length; xi2++) {
        var cellVal = rowData[xi2];
        var fill = (typeof cellVal === "number" && isFinite(cellVal)) ? cellColor(cellVal) : "#888";
        var displayVal = (typeof cellVal === "number") ? (Math.round(cellVal * 100) / 100).toString() : "";
        svg += '<rect x="' + (labelW + xi2 * cellSize + 1) + '" y="' + (rowY + 1) + '" width="' + (cellSize - 2) + '" height="' + (cellSize - 2) + '" rx="2" style="fill:' + escAttr(fill) + '" class="owg-hm-cell">';
        svg += '<title>' + esc(String(xLabels[xi2])) + " / " + esc(String(yLabels[yi])) + ": " + esc(displayVal) + "</title>";
        svg += "</rect>";
      }
    }
    svg += "</svg>";
    return '<div class="owg-heatmap">' + svg + "</div>";
  }

  // ─── Timeline / Gantt ───────────────────────────────────────────────────────
  function renderTimeline(sec) {
    var items = Array.isArray(sec.items) ? sec.items : [];
    if (!items.length) return '<div class="owg-timeline-empty">No timeline items</div>';

    // Parse dates and find overall range
    var parsed = [];
    var minMs = Infinity, maxMs = -Infinity;
    for (var i = 0; i < items.length; i++) {
      var it = items[i];
      var s = new Date(String(it.start)).getTime();
      var e = new Date(String(it.end)).getTime();
      if (isNaN(s) || isNaN(e) || e < s) continue;
      if (s < minMs) minMs = s;
      if (e > maxMs) maxMs = e;
      parsed.push({ label: String(it.label || ""), start: s, end: e, color: String(it.color || ""), group: String(it.group || "") });
    }
    if (!parsed.length) return '<div class="owg-timeline-empty">No valid timeline items</div>';

    // Extend range slightly for visual breathing room
    var pad = Math.max((maxMs - minMs) * 0.02, 86400000); // min 1 day padding
    var rangeStart = minMs - pad;
    var rangeEnd = maxMs + pad;
    var rangeMs = rangeEnd - rangeStart;

    // Layout constants
    var svgW = 680;
    var rowH = 28;
    var labelW = 140;
    var barArea = svgW - labelW - 10;
    var headerH = 28;
    var svgH = headerH + parsed.length * rowH + 4;

    // Color map
    var colorMap = { blue: "var(--blue)", green: "var(--green)", red: "var(--red)", yellow: "var(--yellow)", purple: "#a371f7", orange: "#f0883e", cyan: "#39c5cf", pink: "#e85aad" };

    function msToX(ms) {
      return labelW + ((ms - rangeStart) / rangeMs) * barArea;
    }

    // Build tick marks (4-6 ticks across range)
    var tickCount = Math.min(6, Math.max(2, Math.round(rangeMs / 86400000 / 7)));
    var tickStep = rangeMs / tickCount;
    var ticks = [];
    for (var ti = 0; ti <= tickCount; ti++) {
      var tms = rangeStart + ti * tickStep;
      var td = new Date(tms);
      var tLabel = td.getFullYear() + "-" + ("0" + (td.getMonth() + 1)).slice(-2) + "-" + ("0" + td.getDate()).slice(-2);
      ticks.push({ x: msToX(tms), label: tLabel });
    }

    var svg = '<svg class="owg-timeline-svg" viewBox="0 0 ' + svgW + " " + svgH + '" role="img" aria-label="Timeline">';

    // Grid lines + tick labels
    svg += '<g class="owg-tl-grid">';
    for (var gi = 0; gi < ticks.length; gi++) {
      var gx = ticks[gi].x;
      svg += '<line x1="' + gx + '" y1="' + headerH + '" x2="' + gx + '" y2="' + svgH + '" class="owg-tl-gridline"/>';
      svg += '<text x="' + gx + '" y="' + (headerH - 6) + '" class="owg-tl-tick" text-anchor="middle">' + esc(ticks[gi].label) + "</text>";
    }
    svg += "</g>";

    // Bars
    for (var bi = 0; bi < parsed.length; bi++) {
      var p = parsed[bi];
      var y = headerH + bi * rowH;
      var x1 = msToX(p.start);
      var x2 = msToX(p.end);
      var bw = Math.max(x2 - x1, 2);
      var fill = colorMap[p.color] || (p.color.charAt(0) === "#" ? p.color : "var(--blue)");

      // Label (clipped to labelW)
      svg += '<text x="' + (labelW - 6) + '" y="' + (y + rowH / 2 + 4) + '" class="owg-tl-label" text-anchor="end">' + esc(p.label) + "</text>";

      // Bar background
      svg += '<rect x="' + x1 + '" y="' + (y + 4) + '" width="' + bw + '" height="' + (rowH - 8) + '" rx="3" class="owg-tl-bar" style="fill:' + escAttr(fill) + '"/>';
    }

    svg += "</svg>";
    return '<div class="owg-timeline">' + svg + "</div>";
  }

  // ─── Tree / Hierarchy ───────────────────────────────────────────────────────
  function renderTree(sec, si) {
    var nodes = Array.isArray(sec.nodes) ? sec.nodes : [];
    var expandAll = !!sec.expandAll;
    var selectable = !!sec.selectable;
    var clickActionId = String(sec.clickActionId || "");

    function renderNodes(items, depth) {
      if (!items || !items.length) return "";
      var h = '<ul class="owg-tree-list' + (depth === 0 ? " owg-tree-root" : "") + '">';
      for (var i = 0; i < items.length; i++) {
        var node = items[i];
        var hasChildren = Array.isArray(node.children) && node.children.length > 0;
        var nodeId = "owg-tree-" + si + "-" + depth + "-" + i;
        var label = node.label != null ? String(node.label) : "";
        var nid = node.id != null ? String(node.id) : "";
        h += '<li class="owg-tree-node">';
        if (hasChildren) {
          h += '<button class="owg-tree-toggle" aria-expanded="' + (expandAll ? "true" : "false") +
            '" data-tree-target="' + escAttr(nodeId) + '">' +
            (expandAll ? "\u25BC" : "\u25B6") + "</button>";
        } else {
          h += '<span class="owg-tree-leaf-indent"></span>';
        }
        var labelClass = "owg-tree-label" + (selectable && clickActionId ? " owg-tree-selectable" : "");
        var labelAttrs = ' class="' + escAttr(labelClass) + '"';
        if (selectable && clickActionId) {
          labelAttrs += ' data-tree-action="' + escAttr(clickActionId) + '"';
          if (nid) labelAttrs += ' data-tree-node-id="' + escAttr(nid) + '"';
          labelAttrs += ' data-tree-node-label="' + escAttr(label) + '"';
          labelAttrs += ' role="button" tabindex="0"';
        }
        h += "<span" + labelAttrs + ">" + esc(label) + "</span>";
        if (node.badge != null) {
          var badge = String(node.badge);
          h += '<span class="owg-tree-badge owg-tree-badge-' + safeClass(badge) + '">' + esc(badge) + "</span>";
        }
        if (hasChildren) {
          h += '<div id="' + escAttr(nodeId) + '" class="owg-tree-children' +
            (expandAll ? "" : " owg-tree-children-collapsed") + '">';
          h += renderNodes(node.children, depth + 1);
          h += "</div>";
        }
        h += "</li>";
      }
      h += "</ul>";
      return h;
    }

    return '<div class="owg-tree">' + renderNodes(nodes, 0) + "</div>";
  }

  // ─── Tab/table event binding (called from app.js bindEvents) ────────────────
  OWG.bindSectionEvents = function (root) {
    // Collapsible section titles
    root.querySelectorAll(".section-title-collapsible").forEach(function (title) {
      title.addEventListener("click", function () {
        var targetId = title.getAttribute("data-collapse-target");
        var body = document.getElementById(targetId);
        if (!body) return;
        var collapsed = body.classList.toggle("section-body-collapsed");
        var icon = title.querySelector(".section-toggle");
        if (icon) icon.textContent = collapsed ? "\u25B6" : "\u25BC";
      });
    });

    // Copy-to-clipboard buttons
    root.querySelectorAll(".owg-copy-btn").forEach(function (btn) {
      btn.addEventListener("click", function () {
        var content = btn.getAttribute("data-copy-content");
        var orig = btn.textContent;
        function showFeedback() {
          btn.textContent = "\u2713";
          setTimeout(function () { btn.textContent = orig; }, 1500);
        }
        if (navigator.clipboard && navigator.clipboard.writeText) {
          navigator.clipboard.writeText(content).then(showFeedback).catch(function () {
            var ta = document.createElement("textarea");
            ta.value = content;
            ta.style.cssText = "position:fixed;opacity:0";
            document.body.appendChild(ta);
            ta.select();
            try { document.execCommand("copy"); showFeedback(); } catch (e) { /* ignore */ }
            document.body.removeChild(ta);
          });
        } else {
          var ta = document.createElement("textarea");
          ta.value = content;
          ta.style.cssText = "position:fixed;opacity:0";
          document.body.appendChild(ta);
          ta.select();
          try { document.execCommand("copy"); showFeedback(); } catch (e) { /* ignore */ }
          document.body.removeChild(ta);
        }
      });
    });

    // Table filter inputs
    root.querySelectorAll(".owg-table-filter").forEach(function (input) {
      var ti = input.getAttribute("data-table-filter");
      var table = root.querySelector('.owg-table[data-table-index="' + _esc(ti) + '"]');
      if (table) {
        var allRows = table.querySelectorAll("tbody tr");
        var countEl = root.querySelector('[data-table-count="' + _esc(ti) + '"]');
        if (countEl) countEl.textContent = allRows.length + " rows";
      }
      input.addEventListener("input", function () {
        var q = input.value.trim().toLowerCase();
        var ti2 = input.getAttribute("data-table-filter");
        var table2 = root.querySelector('.owg-table[data-table-index="' + _esc(ti2) + '"]');
        if (!table2) return;
        var rows = table2.querySelectorAll("tbody tr");
        var visible = 0;
        rows.forEach(function (row) {
          var text = row.textContent.toLowerCase();
          var show = !q || text.indexOf(q) !== -1;
          row.style.display = show ? "" : "none";
          if (show) visible++;
        });
        var countEl2 = root.querySelector('[data-table-count="' + _esc(ti2) + '"]');
        if (countEl2) countEl2.textContent = visible + " of " + rows.length + " rows";
      });
    });

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

    // File upload inputs — read as base64 data URIs on change
    root.querySelectorAll('input[type="file"][data-field-key]').forEach(function (input) {
      var fkey = input.getAttribute("data-field-key");
      var maxSize = parseInt(input.getAttribute("data-max-size") || "524288", 10);
      var statusEl = root.querySelector("#" + CSS.escape(input.id) + "-status");

      input.addEventListener("change", function () {
        var files = Array.prototype.slice.call(input.files || []);
        if (!files.length) {
          OWG.formValues[fkey] = null;
          if (statusEl) statusEl.textContent = "No file chosen";
          return;
        }

        // Size check
        var oversized = files.filter(function (f) { return f.size > maxSize; });
        if (oversized.length) {
          var limit = (maxSize / 1024).toFixed(0) + " KB";
          if (statusEl) statusEl.textContent = "\u26A0 File too large (max " + limit + ")";
          OWG.formValues[fkey] = null;
          input.value = "";
          return;
        }

        // Read all files as base64 data URIs
        var pending = files.length;
        var results = new Array(files.length);
        files.forEach(function (file, idx) {
          var reader = new FileReader();
          reader.onload = function (e) {
            results[idx] = {
              name: file.name,
              type: file.type,
              size: file.size,
              data: e.target.result  // base64 data URI
            };
            pending--;
            if (pending === 0) {
              OWG.formValues[fkey] = input.multiple ? results : results[0];
              var names = files.map(function (f) { return f.name; }).join(", ");
              if (statusEl) statusEl.textContent = names;
            }
          };
          reader.onerror = function () {
            OWG.formValues[fkey] = null;
            if (statusEl) statusEl.textContent = "\u26A0 Error reading file";
          };
          reader.readAsDataURL(file);
        });
      });
    });

    // Tree toggle buttons — expand/collapse children
    root.querySelectorAll(".owg-tree-toggle").forEach(function (btn) {
      btn.addEventListener("click", function () {
        var targetId = btn.getAttribute("data-tree-target");
        var target = targetId ? root.querySelector("#" + _esc(targetId)) : null;
        if (!target) return;
        var expanded = btn.getAttribute("aria-expanded") === "true";
        if (expanded) {
          target.classList.add("owg-tree-children-collapsed");
          btn.setAttribute("aria-expanded", "false");
          btn.textContent = "\u25B6";
        } else {
          target.classList.remove("owg-tree-children-collapsed");
          btn.setAttribute("aria-expanded", "true");
          btn.textContent = "\u25BC";
        }
      });
    });

    // Tree selectable node labels — fire action on click
    root.querySelectorAll(".owg-tree-selectable[data-tree-action]").forEach(function (label) {
      label.addEventListener("click", function () {
        var actionId = label.getAttribute("data-tree-action");
        var nodeId = label.getAttribute("data-tree-node-id") || "";
        var nodeLbl = label.getAttribute("data-tree-node-label") || "";
        if (typeof OWG.emitAction === "function") {
          OWG.emitAction(actionId, "action", { nodeId: nodeId, label: nodeLbl }, {});
        }
      });
      label.addEventListener("keydown", function (e) {
        if (e.key === "Enter" || e.key === " ") {
          e.preventDefault();
          label.click();
        }
      });
    });
  };

})(window.OWG = window.OWG || {});
