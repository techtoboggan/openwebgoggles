"use strict";

(function () {
  var wv = new OpenCodeWebview();
  var findings = [];
  var currentIndex = 0;
  var submitted = false;

  var els = {
    loading:       document.getElementById("loading"),
    main:          document.getElementById("main"),
    progressBadge: document.getElementById("progress-badge"),
    progressBar:   document.getElementById("progress-bar"),
    findingTabs:   document.getElementById("finding-tabs"),
    findingCard:   document.getElementById("finding-card"),
    btnPrev:       document.getElementById("btn-prev"),
    btnNext:       document.getElementById("btn-next"),
    btnFP:         document.getElementById("btn-fp"),
    btnReviewed:   document.getElementById("btn-reviewed"),
    submitBar:     document.getElementById("submit-bar"),
    connDot:       document.getElementById("conn-dot"),
    sessionInfo:   document.getElementById("session-info"),
  };

  // --- Connect ---
  wv.connect()
    .then(function (instance) {
      var manifest = instance.getManifest();
      if (manifest && manifest.session) {
        els.sessionInfo.textContent = "Session: " + manifest.session.id.slice(0, 8);
      }
      els.connDot.classList.add("connected");
      renderState(instance.getState());
    })
    .catch(function (err) {
      els.loading.innerHTML = "<p style='color:#f85149'>Connection failed: " + escHtml(String(err)) + "</p>";
    });

  wv.on("connected", function (data) { renderState(data.state); });
  wv.on("state_updated", function (state) { renderState(state); });
  wv.on("close", function (data) {
    if (els.main) els.main.innerHTML = "<div class='loading-screen'><p style='color:#3fb950'>&#10003; " + escHtml((data && data.message) || "Session closed.") + "</p></div>";
  });

  // --- State rendering ---
  function renderState(state) {
    if (!state || !state.data) return;
    var raw = state.data.findings;
    if (!raw || !raw.length) {
      els.loading.innerHTML = "<p style='color:#8b949e'>Waiting for findings...</p>";
      return;
    }

    // Merge incoming findings with local review state (don't clobber edits)
    if (findings.length === 0) {
      findings = raw.map(function (f) {
        return Object.assign({ _status: "pending", _notes: f.notes || "", _edited: {} }, f);
      });
    } else {
      // Update fields that haven't been locally edited
      raw.forEach(function (f, i) {
        if (!findings[i]) return;
        var edited = findings[i]._edited || {};
        Object.keys(f).forEach(function (k) {
          if (!edited[k]) findings[i][k] = f[k];
        });
      });
    }

    els.loading.classList.add("hidden");
    els.main.classList.remove("hidden");

    renderTabs();
    renderFinding(currentIndex);
    renderProgress();
  }

  function renderProgress() {
    var reviewed = findings.filter(function (f) { return f._status !== "pending"; }).length;
    var total = findings.length;
    var pct = total ? Math.round((reviewed / total) * 100) : 0;
    els.progressBar.style.width = pct + "%";
    els.progressBadge.textContent = reviewed + " / " + total + " reviewed";
    els.progressBadge.className = "badge " + (reviewed === total ? "badge-ok" : "badge-warn");

    if (reviewed === total && !submitted) {
      els.submitBar.classList.remove("hidden");
    } else {
      els.submitBar.classList.add("hidden");
    }
  }

  function renderTabs() {
    var html = "";
    findings.forEach(function (f, i) {
      var cls = "finding-tab";
      if (i === currentIndex) cls += " active";
      if (f._status === "reviewed") cls += " reviewed";
      if (f._status === "false-positive") cls += " false-positive";
      var label = (i + 1) + ". " + severityIcon(f.severity) + " " + escHtml(truncate(f.title, 22));
      html += '<button class="' + cls + '" onclick="goTo(' + i + ')" title="' + escHtml(f.title) + '">' + label + "</button>";
    });
    els.findingTabs.innerHTML = html;
    // Scroll active tab into view
    var activeTab = els.findingTabs.children[currentIndex];
    if (activeTab) activeTab.scrollIntoView({ behavior: "smooth", block: "nearest", inline: "nearest" });
  }

  function renderFinding(index) {
    currentIndex = index;
    var f = findings[index];
    if (!f) return;

    var statusBadge = statusBadgeHtml(f._status);
    var sevClass = "sev-" + (f.severity || "info").toLowerCase();
    var cvssColor = cvssBarColor(f.cvss_score);
    var cvssWidth = f.cvss_score ? Math.round((f.cvss_score / 10) * 100) : 0;

    var html = "";

    // Header
    html += '<div class="finding-header">';
    html += '<div class="finding-title-wrap">';
    html += '<div class="finding-num">Finding ' + (index + 1) + ' of ' + findings.length + '</div>';
    html += '<div class="finding-title">' + escHtml(f.title) + '</div>';
    html += '</div>';
    html += '<div class="finding-status-badges">' + statusBadge + '</div>';
    html += '</div>';

    // Row 1: severity, cvss, cwe, host
    html += '<div class="field-grid">';
    html += severityDropdownField(index, f._edited.severity !== undefined ? f._edited.severity : f.severity);
    html += field("CVSS Score",
      '<div class="cvss-score">' +
      '<span>' + (f.cvss_score != null ? f.cvss_score.toFixed(1) : "—") + '</span>' +
      '<div class="cvss-bar" style="width:80px;background:var(--border)"><div class="cvss-bar" style="width:' + cvssWidth + '%;background:' + cvssColor + '"></div></div>' +
      '</div>');
    html += field("CWE", '<span class="field-value monospace">' + escHtml(f.cwe_id || "—") + '</span>');
    html += editableField(index, "affected_host", "Affected Host", f._edited.affected_host !== undefined ? f._edited.affected_host : f.affected_host);
    html += '</div>';

    // Description
    html += '<div class="field-grid full">';
    html += editableField(index, "description", "Description", f._edited.description !== undefined ? f._edited.description : f.description, true);
    html += '</div>';

    // Evidence
    html += '<div class="field-grid full">';
    html += '<div class="field"><div class="field-label">Evidence</div><div class="evidence-block">' + escHtml(f.evidence || "No evidence provided.") + '</div></div>';
    html += '</div>';

    // Recommendation
    html += '<div class="field-grid full">';
    html += editableField(index, "recommendation", "Recommendation", f._edited.recommendation !== undefined ? f._edited.recommendation : f.recommendation, true);
    html += '</div>';

    // Analyst notes
    html += '<div class="field-grid full">';
    html += editableField(index, "_notes", "Analyst Notes", f._notes, true, "Add notes, context, or caveats...");
    html += '</div>';

    els.findingCard.innerHTML = html;

    // Update footer button states
    els.btnPrev.disabled = index === 0;
    els.btnNext.disabled = index === findings.length - 1;
    els.btnFP.classList.toggle("hidden", f._status === "false-positive");
    els.btnReviewed.classList.toggle("hidden", f._status === "reviewed");
  }

  // --- Field helpers ---
  function field(label, valueHtml) {
    return '<div class="field"><div class="field-label">' + escHtml(label) + '</div><div class="field-value">' + valueHtml + '</div></div>';
  }

  function editableField(index, key, label, value, multiline, placeholder) {
    var id = "field-" + index + "-" + key;
    var ph = placeholder || "";
    if (multiline) {
      return '<div class="field" id="wrap-' + id + '">' +
        '<div class="field-label">' + escHtml(label) + '</div>' +
        '<textarea class="field-value editable" id="' + id + '" rows="3" placeholder="' + escHtml(ph) + '" ' +
        'oninput="saveEdit(' + index + ',\'' + key + '\',this.value)" ' +
        'onfocus="this.parentElement.classList.add(\'editing\')" ' +
        'onblur="this.parentElement.classList.remove(\'editing\')">' +
        escHtml(value || "") + '</textarea></div>';
    }
    return '<div class="field" id="wrap-' + id + '">' +
      '<div class="field-label">' + escHtml(label) + '</div>' +
      '<input class="field-value editable" id="' + id + '" type="text" value="' + escAttr(value || "") + '" placeholder="' + escAttr(ph) + '" ' +
      'oninput="saveEdit(' + index + ',\'' + key + '\',this.value)" ' +
      'onfocus="this.parentElement.classList.add(\'editing\')" ' +
      'onblur="this.parentElement.classList.remove(\'editing\')" />' +
      '</div>';
  }

  function severityDropdownField(index, currentSev) {
    var levels = ["Critical", "High", "Medium", "Low", "Info"];
    var opts = levels.map(function (s) {
      var sel = s === currentSev ? " selected" : "";
      return '<option value="' + s + '"' + sel + '>' + s + '</option>';
    }).join("");
    var sevClass = "sev-" + (currentSev || "info").toLowerCase();
    return '<div class="field editing-select">' +
      '<div class="field-label">Severity</div>' +
      '<select class="field-value sev-select ' + sevClass + '" ' +
      'onchange="saveEdit(' + index + ',\'severity\',this.value);this.className=\'field-value sev-select sev-\'+this.value.toLowerCase()">' +
      opts + '</select></div>';
  }

  function statusBadgeHtml(status) {
    if (status === "reviewed") return '<span class="status-badge status-reviewed">&#10003; Reviewed</span>';
    if (status === "false-positive") return '<span class="status-badge status-false-positive">False Positive</span>';
    return '<span class="status-badge status-pending">Pending</span>';
  }

  function severityIcon(sev) {
    var s = (sev || "").toLowerCase();
    if (s === "critical") return "&#9888;";
    if (s === "high") return "&#9679;";
    if (s === "medium") return "&#9675;";
    if (s === "low") return "&#9711;";
    return "&#8226;";
  }

  function cvssBarColor(score) {
    if (!score) return "var(--text3)";
    if (score >= 9) return "#ff4444";
    if (score >= 7) return "var(--red)";
    if (score >= 4) return "var(--yellow)";
    return "var(--blue)";
  }

  // --- Actions ---
  window.saveEdit = function (index, key, value) {
    if (!findings[index]) return;
    findings[index]._edited = findings[index]._edited || {};
    findings[index]._edited[key] = value;
    if (key === "_notes") findings[index]._notes = value;
    else findings[index][key] = value;
  };

  window.goTo = function (index) {
    currentIndex = index;
    renderTabs();
    renderFinding(index);
  };

  window.navPrev = function () {
    if (currentIndex > 0) window.goTo(currentIndex - 1);
  };

  window.navNext = function () {
    if (currentIndex < findings.length - 1) window.goTo(currentIndex + 1);
  };

  window.markFalsePositive = function () {
    findings[currentIndex]._status = "false-positive";
    renderTabs();
    renderFinding(currentIndex);
    renderProgress();
    // Auto-advance to next pending
    autoAdvance();
  };

  window.markReviewed = function () {
    findings[currentIndex]._status = "reviewed";
    renderTabs();
    renderFinding(currentIndex);
    renderProgress();
    autoAdvance();
  };

  function autoAdvance() {
    // Find next pending finding
    for (var i = currentIndex + 1; i < findings.length; i++) {
      if (findings[i]._status === "pending") { window.goTo(i); return; }
    }
    // Wrap around from start
    for (var j = 0; j < currentIndex; j++) {
      if (findings[j]._status === "pending") { window.goTo(j); return; }
    }
    // All done — stay on current
  }

  window.scrollTabs = function (dir) {
    var tabs = els.findingTabs;
    tabs.scrollBy({ left: dir * 200, behavior: "smooth" });
  };

  window.submitReport = function () {
    if (submitted) return;
    submitted = true;
    els.submitBar.classList.add("hidden");

    var report = findings.map(function (f) {
      return {
        id: f.id,
        title: f.title,
        severity: f.severity,
        cvss_score: f.cvss_score,
        cwe_id: f.cwe_id,
        affected_host: f.affected_host,
        description: f.description,
        recommendation: f.recommendation,
        evidence: f.evidence,
        status: f._status,
        notes: f._notes,
        edited_fields: Object.keys(f._edited || {})
      };
    });

    wv.sendAction("submit_report", "submit", report).then(function () {
      els.findingCard.innerHTML =
        '<div class="loading-screen"><div style="text-align:center">' +
        '<p style="color:var(--green);font-size:18px;margin-bottom:8px">&#10003; Report Submitted</p>' +
        '<p style="color:var(--text2)">Waiting for agent to process...</p>' +
        '</div></div>';
    });
  };

  // --- Utilities ---
  function escHtml(s) {
    return String(s || "")
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;");
  }

  function escAttr(s) {
    return String(s || "").replace(/"/g, "&quot;").replace(/'/g, "&#39;");
  }

  function truncate(s, n) {
    s = String(s || "");
    return s.length > n ? s.slice(0, n - 1) + "…" : s;
  }
})();
