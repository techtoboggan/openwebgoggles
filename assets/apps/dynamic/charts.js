"use strict";
// Data-driven SVG chart renderer for OpenWebGoggles.
// Generates safe SVG from validated numeric/string data.
// ALL text goes through OWG.esc(), ALL attributes through OWG.escAttr().
// No raw SVG from agents is ever inserted — defense against XSS.
//
// Supported chart types: bar, line, area, pie, donut, sparkline.
// Depends on: utils.js (loaded first)

(function (OWG) {
  var esc = OWG.esc;
  var escAttr = OWG.escAttr;

  // ─── Theme color aliases → CSS variable mapping ────────────────────────────
  var THEME_COLORS = {
    blue: "var(--blue)", green: "var(--green)", red: "var(--red)",
    yellow: "var(--yellow)", purple: "#a371f7", orange: "#d29922",
    cyan: "#76e3ea", pink: "#db61a2"
  };
  // Default palette used when no color is specified per dataset
  var DEFAULT_PALETTE = ["blue", "green", "red", "yellow", "purple", "orange", "cyan", "pink"];

  function resolveColor(c, fallbackIdx) {
    if (!c) {
      var key = DEFAULT_PALETTE[fallbackIdx % DEFAULT_PALETTE.length];
      return THEME_COLORS[key];
    }
    if (THEME_COLORS[c]) return THEME_COLORS[c];
    // Must be a hex color (pre-validated by SecurityGate)
    return c;
  }

  // ─── Convert columns/rows to internal labels/datasets format ──────────────
  // Allows chart sections to use the same {columns, rows} format as tables.
  // First column becomes labels, remaining columns become datasets.
  function columnsRowsToData(sec) {
    var cols = sec.columns || [];
    var rows = sec.rows || [];
    if (!cols.length || !rows.length) return {};

    var labelKey = cols[0].key;
    var labels = rows.map(function (r) { return r[labelKey] != null ? String(r[labelKey]) : ""; });

    var datasets = [];
    for (var ci = 1; ci < cols.length; ci++) {
      var col = cols[ci];
      var values = rows.map(function (r) { return r[col.key] != null ? Number(r[col.key]) || 0 : 0; });
      datasets.push({ label: col.label || col.key, values: values });
    }

    // For pie/donut: merge all value columns into a single dataset with separate colors
    var ct = sec.chartType || "bar";
    if ((ct === "pie" || ct === "donut") && datasets.length === 1) {
      datasets[0].colors = [];
    }

    return { labels: labels, datasets: datasets };
  }

  // ─── Chart dispatcher ──────────────────────────────────────────────────────
  OWG.renderChart = function (sec) {
    var ct = sec.chartType || "bar";
    // Support both {data: {labels, datasets}} and {columns, rows} formats
    var data = sec.data || (sec.columns ? columnsRowsToData(sec) : {});
    var opts = sec.options || {};
    var w = Math.max(50, Math.min(2000, opts.width || 500));
    var h = Math.max(50, Math.min(1500, opts.height || 300));
    var html = '<div class="owg-chart-container">';

    switch (ct) {
      case "bar":       html += renderBarChart(data, opts, w, h);       break;
      case "line":      html += renderLineChart(data, opts, w, h, false); break;
      case "area":      html += renderLineChart(data, opts, w, h, true);  break;
      case "pie":       html += renderPieChart(data, opts, w, h, false);  break;
      case "donut":     html += renderPieChart(data, opts, w, h, true);   break;
      case "sparkline": html += renderSparklineChart(data, opts, w, h);   break;
      default:          html += renderBarChart(data, opts, w, h);       break;
    }

    // Legend
    if (opts.showLegend !== false && ct !== "sparkline") {
      html += renderLegend(data, ct);
    }

    html += "</div>";
    return html;
  };

  // ─── Layout constants ──────────────────────────────────────────────────────
  var PAD = { top: 20, right: 20, bottom: 40, left: 50 };

  function num(v) { return Number(v) || 0; }
  function fixed(v) { return Number(v).toFixed(2); }

  // ─── Bar chart ─────────────────────────────────────────────────────────────
  function renderBarChart(data, opts, w, h) {
    var labels = data.labels || [];
    var datasets = data.datasets || [];
    if (!labels.length || !datasets.length) return "";

    var plotW = w - PAD.left - PAD.right;
    var plotH = h - PAD.top - PAD.bottom;
    var stacked = !!opts.stacked;

    // Compute value range
    var maxVal = 0;
    if (stacked) {
      for (var li = 0; li < labels.length; li++) {
        var sum = 0;
        for (var di = 0; di < datasets.length; di++) {
          sum += Math.max(0, num(datasets[di].values[li]));
        }
        if (sum > maxVal) maxVal = sum;
      }
    } else {
      datasets.forEach(function (ds) {
        (ds.values || []).forEach(function (v) { if (num(v) > maxVal) maxVal = num(v); });
      });
    }
    if (maxVal === 0) maxVal = 1;

    var svg = '<svg class="owg-chart" viewBox="0 0 ' + w + " " + h +
      '" width="' + w + '" height="' + h + '" xmlns="http://www.w3.org/2000/svg">';

    // Grid lines
    if (opts.showGrid !== false) {
      svg += '<g class="chart-grid">';
      for (var gi = 0; gi <= 4; gi++) {
        var gy = PAD.top + plotH - (gi / 4) * plotH;
        svg += '<line x1="' + PAD.left + '" y1="' + fixed(gy) + '" x2="' + (w - PAD.right) + '" y2="' + fixed(gy) + '"/>';
      }
      svg += "</g>";
    }

    // Y-axis labels
    svg += '<g class="chart-axis">';
    for (var yi = 0; yi <= 4; yi++) {
      var yv = (yi / 4) * maxVal;
      var yy = PAD.top + plotH - (yi / 4) * plotH;
      var label = yv >= 1000 ? (yv / 1000).toFixed(1) + "k" : Math.round(yv).toString();
      svg += '<text x="' + (PAD.left - 6) + '" y="' + fixed(yy + 4) + '" text-anchor="end">' + esc(label) + "</text>";
    }
    svg += "</g>";

    // Bars
    var groupW = plotW / labels.length;
    var barGap = Math.max(2, groupW * 0.1);
    var nds = datasets.length;
    var barW = stacked ? (groupW - barGap * 2) : (groupW - barGap * 2) / nds;

    datasets.forEach(function (ds, di) {
      var color = resolveColor(ds.color, di);
      (ds.values || []).forEach(function (v, vi) {
        var val = num(v);
        var barH = (Math.max(0, val) / maxVal) * plotH;
        var x, y;
        if (stacked) {
          // Compute stacked offset
          var below = 0;
          for (var si = 0; si < di; si++) {
            below += Math.max(0, num(datasets[si].values[vi]));
          }
          x = PAD.left + vi * groupW + barGap;
          y = PAD.top + plotH - ((below + Math.max(0, val)) / maxVal) * plotH;
        } else {
          x = PAD.left + vi * groupW + barGap + di * barW;
          y = PAD.top + plotH - barH;
        }
        svg += '<rect class="chart-bar" x="' + fixed(x) + '" y="' + fixed(y) +
          '" width="' + fixed(barW) + '" height="' + fixed(barH) +
          '" fill="' + escAttr(color) + '"/>';
      });
    });

    // X-axis labels
    labels.forEach(function (lbl, li) {
      var lx = PAD.left + li * groupW + groupW / 2;
      svg += '<text x="' + fixed(lx) + '" y="' + (h - 8) + '" text-anchor="middle">' + esc(lbl) + "</text>";
    });

    svg += "</svg>";
    return svg;
  }

  // ─── Line / Area chart ─────────────────────────────────────────────────────
  function renderLineChart(data, opts, w, h, fill) {
    var labels = data.labels || [];
    var datasets = data.datasets || [];
    if (!labels.length || !datasets.length) return "";

    var plotW = w - PAD.left - PAD.right;
    var plotH = h - PAD.top - PAD.bottom;

    var maxVal = 0, minVal = Infinity;
    datasets.forEach(function (ds) {
      (ds.values || []).forEach(function (v) {
        var n = num(v);
        if (n > maxVal) maxVal = n;
        if (n < minVal) minVal = n;
      });
    });
    if (minVal > 0) minVal = 0; // always include 0
    var range = maxVal - minVal || 1;

    var svg = '<svg class="owg-chart" viewBox="0 0 ' + w + " " + h +
      '" width="' + w + '" height="' + h + '" xmlns="http://www.w3.org/2000/svg">';

    // Grid
    if (opts.showGrid !== false) {
      svg += '<g class="chart-grid">';
      for (var gi = 0; gi <= 4; gi++) {
        var gy = PAD.top + plotH - (gi / 4) * plotH;
        svg += '<line x1="' + PAD.left + '" y1="' + fixed(gy) + '" x2="' + (w - PAD.right) + '" y2="' + fixed(gy) + '"/>';
      }
      svg += "</g>";
    }

    // Y-axis labels
    svg += '<g class="chart-axis">';
    for (var yi = 0; yi <= 4; yi++) {
      var yv = minVal + (yi / 4) * range;
      var yy = PAD.top + plotH - (yi / 4) * plotH;
      var label = Math.abs(yv) >= 1000 ? (yv / 1000).toFixed(1) + "k" : Math.round(yv).toString();
      svg += '<text x="' + (PAD.left - 6) + '" y="' + fixed(yy + 4) + '" text-anchor="end">' + esc(label) + "</text>";
    }
    svg += "</g>";

    // Lines + optional area fill
    datasets.forEach(function (ds, di) {
      var color = resolveColor(ds.color, di);
      var values = ds.values || [];
      var points = [];
      values.forEach(function (v, vi) {
        var x = PAD.left + (vi / Math.max(1, labels.length - 1)) * plotW;
        var y = PAD.top + plotH - ((num(v) - minVal) / range) * plotH;
        points.push(fixed(x) + "," + fixed(y));
      });
      if (!points.length) return;

      if (fill) {
        // Area fill
        var firstX = fixed(PAD.left);
        var lastX = fixed(PAD.left + ((values.length - 1) / Math.max(1, labels.length - 1)) * plotW);
        var baseline = fixed(PAD.top + plotH);
        svg += '<polygon class="chart-area" points="' + firstX + "," + baseline + " " +
          escAttr(points.join(" ")) + " " + lastX + "," + baseline +
          '" fill="' + escAttr(color) + '"/>';
      }

      // Line
      svg += '<polyline class="chart-line" points="' + escAttr(points.join(" ")) +
        '" stroke="' + escAttr(color) + '"/>';

      // Dots
      points.forEach(function (pt) {
        var parts = pt.split(",");
        svg += '<circle class="chart-dot" cx="' + parts[0] + '" cy="' + parts[1] +
          '" fill="' + escAttr(color) + '"/>';
      });
    });

    // X-axis labels
    labels.forEach(function (lbl, li) {
      var lx = PAD.left + (li / Math.max(1, labels.length - 1)) * plotW;
      svg += '<text x="' + fixed(lx) + '" y="' + (h - 8) + '" text-anchor="middle">' + esc(lbl) + "</text>";
    });

    svg += "</svg>";
    return svg;
  }

  // ─── Pie / Donut chart ─────────────────────────────────────────────────────
  function renderPieChart(data, opts, w, h, isDonut) {
    var datasets = data.datasets || [];
    if (!datasets.length || !datasets[0].values) return "";

    var values = datasets[0].values;
    var pieColors = datasets[0].colors || [];
    var labels = data.labels || [];
    var total = 0;
    values.forEach(function (v) { total += Math.max(0, num(v)); });
    if (total === 0) return "";

    var cx = w / 2;
    var cy = h / 2;
    var r = Math.min(cx, cy) - 20;
    var innerR = isDonut ? r * 0.55 : 0;

    var svg = '<svg class="owg-chart" viewBox="0 0 ' + w + " " + h +
      '" width="' + w + '" height="' + h + '" xmlns="http://www.w3.org/2000/svg">';

    var angle = -Math.PI / 2; // start at top
    values.forEach(function (v, vi) {
      var val = Math.max(0, num(v));
      if (val === 0) return;
      var sliceAngle = (val / total) * Math.PI * 2;
      var color = resolveColor(pieColors[vi] || "", vi);

      var x1 = cx + r * Math.cos(angle);
      var y1 = cy + r * Math.sin(angle);
      var x2 = cx + r * Math.cos(angle + sliceAngle);
      var y2 = cy + r * Math.sin(angle + sliceAngle);
      var largeArc = sliceAngle > Math.PI ? 1 : 0;

      var d;
      if (isDonut) {
        var ix1 = cx + innerR * Math.cos(angle);
        var iy1 = cy + innerR * Math.sin(angle);
        var ix2 = cx + innerR * Math.cos(angle + sliceAngle);
        var iy2 = cy + innerR * Math.sin(angle + sliceAngle);
        d = "M " + fixed(x1) + " " + fixed(y1) +
          " A " + r + " " + r + " 0 " + largeArc + " 1 " + fixed(x2) + " " + fixed(y2) +
          " L " + fixed(ix2) + " " + fixed(iy2) +
          " A " + innerR + " " + innerR + " 0 " + largeArc + " 0 " + fixed(ix1) + " " + fixed(iy1) + " Z";
      } else {
        d = "M " + fixed(cx) + " " + fixed(cy) +
          " L " + fixed(x1) + " " + fixed(y1) +
          " A " + r + " " + r + " 0 " + largeArc + " 1 " + fixed(x2) + " " + fixed(y2) + " Z";
      }

      svg += '<path d="' + escAttr(d) + '" fill="' + escAttr(color) + '"/>';

      // Label
      if (labels[vi]) {
        var midAngle = angle + sliceAngle / 2;
        var labelR = isDonut ? (r + innerR) / 2 : r * 0.65;
        var lx = cx + labelR * Math.cos(midAngle);
        var ly = cy + labelR * Math.sin(midAngle);
        svg += '<text class="chart-pie-label" x="' + fixed(lx) + '" y="' + fixed(ly) +
          '" text-anchor="middle" dominant-baseline="central">' + esc(labels[vi]) + "</text>";
      }

      angle += sliceAngle;
    });

    svg += "</svg>";
    return svg;
  }

  // ─── Sparkline chart (minimal, no axes) ────────────────────────────────────
  function renderSparklineChart(data, opts, w, h) {
    var datasets = data.datasets || [];
    if (!datasets.length) return "";
    var values = datasets[0].values || [];
    return OWG.renderSparkline(values, w, h);
  }

  // ─── Legend ────────────────────────────────────────────────────────────────
  function renderLegend(data, chartType) {
    var datasets = data.datasets || [];
    var labels = data.labels || [];
    var isPie = chartType === "pie" || chartType === "donut";

    if (isPie) {
      // Pie: legend items from labels + colors
      if (!labels.length) return "";
      var colors = (datasets[0] && datasets[0].colors) || [];
      var html = '<div class="owg-chart-legend">';
      labels.forEach(function (lbl, li) {
        var color = resolveColor(colors[li] || "", li);
        html += '<div class="owg-chart-legend-item">' +
          '<span class="owg-chart-legend-swatch" style="background:' + escAttr(color) + '"></span>' +
          esc(lbl) + "</div>";
      });
      html += "</div>";
      return html;
    }

    // Bar/line/area: legend items from dataset labels
    if (!datasets.length || (datasets.length === 1 && !datasets[0].label)) return "";
    var html = '<div class="owg-chart-legend">';
    datasets.forEach(function (ds, di) {
      if (!ds.label) return;
      var color = resolveColor(ds.color, di);
      html += '<div class="owg-chart-legend-item">' +
        '<span class="owg-chart-legend-swatch" style="background:' + escAttr(color) + '"></span>' +
        esc(ds.label) + "</div>";
    });
    html += "</div>";
    return html;
  }

})(window.OWG = window.OWG || {});
