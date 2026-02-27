"use strict";

/**
 * Security Assessment QA — OpenWebGoggles Example App
 *
 * Uses addEventListener (CSP-safe) instead of inline event handlers.
 */
(function () {
  var wv = new OpenWebGoggles();
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
    submitBtn:     document.getElementById("btn-submit"),
    tabsLeft:      document.getElementById("tabs-left"),
    tabsRight:     document.getElementById("tabs-right"),
    connDot:       document.getElementById("conn-dot"),
    sessionInfo:   document.getElementById("session-info"),
  };

  // --- Bind static button events (CSP-safe, no inline handlers) ---
  if (els.tabsLeft)   els.tabsLeft.addEventListener("click", function () { scrollTabs(-1); });
  if (els.tabsRight)  els.tabsRight.addEventListener("click", function () { scrollTabs(1); });
  if (els.btnPrev)    els.btnPrev.addEventListener("click", function () { navPrev(); });
  if (els.btnNext)    els.btnNext.addEventListener("click", function () { navNext(); });
  if (els.btnFP)      els.btnFP.addEventListener("click", function () { markFalsePositive(); });
  if (els.btnReviewed) els.btnReviewed.addEventListener("click", function () { markReviewed(); });
  if (els.submitBtn)  els.submitBtn.addEventListener("click", function () { submitReport(); });

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
      els.loading.textContent = "";
      var p = document.createElement("p");
      p.style.color = "#f85149";
      p.textContent = "Connection failed: " + String(err);
      els.loading.appendChild(p);
    });

  wv.on("connected", function (data) { renderState(data.state); });
  wv.on("state_updated", function (state) { renderState(state); });
  wv.on("close", function (data) {
    if (els.main) {
      els.main.textContent = "";
      var wrap = document.createElement("div");
      wrap.className = "loading-screen";
      var p = document.createElement("p");
      p.style.color = "#3fb950";
      p.innerHTML = "&#10003; " + escHtml((data && data.message) || "Session closed.");
      wrap.appendChild(p);
      els.main.appendChild(wrap);
    }
  });

  // --- State rendering ---
  function renderState(state) {
    if (!state || !state.data) return;
    var raw = state.data.findings;
    if (!raw || !raw.length) {
      els.loading.textContent = "";
      var p = document.createElement("p");
      p.style.color = "#8b949e";
      p.textContent = "Waiting for findings...";
      els.loading.appendChild(p);
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
    els.findingTabs.textContent = "";

    findings.forEach(function (f, i) {
      var btn = document.createElement("button");
      var cls = "finding-tab";
      if (i === currentIndex) cls += " active";
      if (f._status === "reviewed") cls += " reviewed";
      if (f._status === "false-positive") cls += " false-positive";
      btn.className = cls;
      btn.title = f.title || "";
      btn.setAttribute("data-tab-index", i);
      btn.innerHTML = (i + 1) + ". " + severityIcon(f.severity) + " " + escHtml(truncate(f.title, 22));
      els.findingTabs.appendChild(btn);
    });

    // Bind tab click events
    els.findingTabs.querySelectorAll("[data-tab-index]").forEach(function (btn) {
      btn.addEventListener("click", function () {
        var idx = parseInt(btn.getAttribute("data-tab-index"), 10);
        goTo(idx);
      });
    });

    // Scroll active tab into view
    var activeTab = els.findingTabs.children[currentIndex];
    if (activeTab) activeTab.scrollIntoView({ behavior: "smooth", block: "nearest", inline: "nearest" });
  }

  function renderFinding(index) {
    currentIndex = index;
    var f = findings[index];
    if (!f) return;

    els.findingCard.textContent = "";

    // Header
    var headerEl = document.createElement("div");
    headerEl.className = "finding-header";

    var titleWrap = document.createElement("div");
    titleWrap.className = "finding-title-wrap";
    var findingNum = document.createElement("div");
    findingNum.className = "finding-num";
    findingNum.textContent = "Finding " + (index + 1) + " of " + findings.length;
    var findingTitle = document.createElement("div");
    findingTitle.className = "finding-title";
    findingTitle.textContent = f.title;
    titleWrap.appendChild(findingNum);
    titleWrap.appendChild(findingTitle);

    var statusBadges = document.createElement("div");
    statusBadges.className = "finding-status-badges";
    statusBadges.appendChild(createStatusBadge(f._status));

    headerEl.appendChild(titleWrap);
    headerEl.appendChild(statusBadges);
    els.findingCard.appendChild(headerEl);

    // Row 1: severity, cvss, cwe, host
    var grid1 = document.createElement("div");
    grid1.className = "field-grid";
    grid1.appendChild(createSeverityDropdown(index, f._edited.severity !== undefined ? f._edited.severity : f.severity));
    grid1.appendChild(createCvssField(f.cvss_score));
    grid1.appendChild(createStaticField("CWE", f.cwe_id || "\u2014", true));
    grid1.appendChild(createEditableField(index, "affected_host", "Affected Host", f._edited.affected_host !== undefined ? f._edited.affected_host : f.affected_host));
    els.findingCard.appendChild(grid1);

    // Description
    var grid2 = document.createElement("div");
    grid2.className = "field-grid full";
    grid2.appendChild(createEditableField(index, "description", "Description", f._edited.description !== undefined ? f._edited.description : f.description, true));
    els.findingCard.appendChild(grid2);

    // Evidence
    var grid3 = document.createElement("div");
    grid3.className = "field-grid full";
    var evidenceField = document.createElement("div");
    evidenceField.className = "field";
    var evidenceLabel = document.createElement("div");
    evidenceLabel.className = "field-label";
    evidenceLabel.textContent = "Evidence";
    var evidenceBlock = document.createElement("div");
    evidenceBlock.className = "evidence-block";
    evidenceBlock.textContent = f.evidence || "No evidence provided.";
    evidenceField.appendChild(evidenceLabel);
    evidenceField.appendChild(evidenceBlock);
    grid3.appendChild(evidenceField);
    els.findingCard.appendChild(grid3);

    // Recommendation
    var grid4 = document.createElement("div");
    grid4.className = "field-grid full";
    grid4.appendChild(createEditableField(index, "recommendation", "Recommendation", f._edited.recommendation !== undefined ? f._edited.recommendation : f.recommendation, true));
    els.findingCard.appendChild(grid4);

    // Analyst notes
    var grid5 = document.createElement("div");
    grid5.className = "field-grid full";
    grid5.appendChild(createEditableField(index, "_notes", "Analyst Notes", f._notes, true, "Add notes, context, or caveats..."));
    els.findingCard.appendChild(grid5);

    // Update footer button states
    els.btnPrev.disabled = index === 0;
    els.btnNext.disabled = index === findings.length - 1;
    els.btnFP.classList.toggle("hidden", f._status === "false-positive");
    els.btnReviewed.classList.toggle("hidden", f._status === "reviewed");
  }

  // --- DOM field builders (CSP-safe, no inline handlers) ---

  function createStaticField(label, value, mono) {
    var wrapper = document.createElement("div");
    wrapper.className = "field";
    var lbl = document.createElement("div");
    lbl.className = "field-label";
    lbl.textContent = label;
    var val = document.createElement("span");
    val.className = "field-value" + (mono ? " monospace" : "");
    val.textContent = value;
    wrapper.appendChild(lbl);
    wrapper.appendChild(val);
    return wrapper;
  }

  function createCvssField(score) {
    var wrapper = document.createElement("div");
    wrapper.className = "field";
    var lbl = document.createElement("div");
    lbl.className = "field-label";
    lbl.textContent = "CVSS Score";
    var val = document.createElement("div");
    val.className = "field-value cvss-score";

    var scoreSpan = document.createElement("span");
    scoreSpan.textContent = score != null ? score.toFixed(1) : "\u2014";
    val.appendChild(scoreSpan);

    var barOuter = document.createElement("div");
    barOuter.className = "cvss-bar";
    barOuter.style.width = "80px";
    barOuter.style.background = "var(--border)";
    var barInner = document.createElement("div");
    barInner.className = "cvss-bar";
    var pct = score ? Math.round((score / 10) * 100) : 0;
    barInner.style.width = pct + "%";
    barInner.style.background = cvssBarColor(score);
    barOuter.appendChild(barInner);
    val.appendChild(barOuter);

    wrapper.appendChild(lbl);
    wrapper.appendChild(val);
    return wrapper;
  }

  function createEditableField(index, key, label, value, multiline, placeholder) {
    var wrapper = document.createElement("div");
    wrapper.className = "field";
    wrapper.id = "wrap-field-" + index + "-" + key;

    var lbl = document.createElement("div");
    lbl.className = "field-label";
    lbl.textContent = label;
    wrapper.appendChild(lbl);

    var input;
    if (multiline) {
      input = document.createElement("textarea");
      input.className = "field-value editable";
      input.rows = 3;
      input.placeholder = placeholder || "";
      input.textContent = value || "";
    } else {
      input = document.createElement("input");
      input.className = "field-value editable";
      input.type = "text";
      input.value = value || "";
      input.placeholder = placeholder || "";
    }

    input.addEventListener("input", function () {
      saveEdit(index, key, input.value);
    });
    input.addEventListener("focus", function () {
      wrapper.classList.add("editing");
    });
    input.addEventListener("blur", function () {
      wrapper.classList.remove("editing");
    });

    wrapper.appendChild(input);
    return wrapper;
  }

  function createSeverityDropdown(index, currentSev) {
    var levels = ["Critical", "High", "Medium", "Low", "Info"];
    var wrapper = document.createElement("div");
    wrapper.className = "field editing-select";

    var lbl = document.createElement("div");
    lbl.className = "field-label";
    lbl.textContent = "Severity";
    wrapper.appendChild(lbl);

    var sevClass = "sev-" + (currentSev || "info").toLowerCase();
    var select = document.createElement("select");
    select.className = "field-value sev-select " + sevClass;

    levels.forEach(function (s) {
      var opt = document.createElement("option");
      opt.value = s;
      opt.textContent = s;
      if (s === currentSev) opt.selected = true;
      select.appendChild(opt);
    });

    select.addEventListener("change", function () {
      saveEdit(index, "severity", select.value);
      select.className = "field-value sev-select sev-" + select.value.toLowerCase();
    });

    wrapper.appendChild(select);
    return wrapper;
  }

  function createStatusBadge(status) {
    var span = document.createElement("span");
    if (status === "reviewed") {
      span.className = "status-badge status-reviewed";
      span.innerHTML = "&#10003; Reviewed";
    } else if (status === "false-positive") {
      span.className = "status-badge status-false-positive";
      span.textContent = "False Positive";
    } else {
      span.className = "status-badge status-pending";
      span.textContent = "Pending";
    }
    return span;
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

  // --- Actions (all local, no window.* exports) ---

  function saveEdit(index, key, value) {
    if (!findings[index]) return;
    findings[index]._edited = findings[index]._edited || {};
    findings[index]._edited[key] = value;
    if (key === "_notes") findings[index]._notes = value;
    else findings[index][key] = value;
  }

  function goTo(index) {
    currentIndex = index;
    renderTabs();
    renderFinding(index);
  }

  function navPrev() {
    if (currentIndex > 0) goTo(currentIndex - 1);
  }

  function navNext() {
    if (currentIndex < findings.length - 1) goTo(currentIndex + 1);
  }

  function markFalsePositive() {
    findings[currentIndex]._status = "false-positive";
    renderTabs();
    renderFinding(currentIndex);
    renderProgress();
    autoAdvance();
  }

  function markReviewed() {
    findings[currentIndex]._status = "reviewed";
    renderTabs();
    renderFinding(currentIndex);
    renderProgress();
    autoAdvance();
  }

  function autoAdvance() {
    // Find next pending finding
    for (var i = currentIndex + 1; i < findings.length; i++) {
      if (findings[i]._status === "pending") { goTo(i); return; }
    }
    // Wrap around from start
    for (var j = 0; j < currentIndex; j++) {
      if (findings[j]._status === "pending") { goTo(j); return; }
    }
    // All done — stay on current
  }

  function scrollTabs(dir) {
    var tabs = els.findingTabs;
    tabs.scrollBy({ left: dir * 200, behavior: "smooth" });
  }

  function submitReport() {
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
      els.findingCard.textContent = "";
      var wrap = document.createElement("div");
      wrap.className = "loading-screen";
      var inner = document.createElement("div");
      inner.style.textAlign = "center";
      var p1 = document.createElement("p");
      p1.style.color = "var(--green)";
      p1.style.fontSize = "18px";
      p1.style.marginBottom = "8px";
      p1.innerHTML = "&#10003; Report Submitted";
      var p2 = document.createElement("p");
      p2.style.color = "var(--text2)";
      p2.textContent = "Waiting for agent to process...";
      inner.appendChild(p1);
      inner.appendChild(p2);
      wrap.appendChild(inner);
      els.findingCard.appendChild(wrap);
    });
  }

  // --- Utilities ---
  function escHtml(s) {
    return String(s || "")
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;");
  }

  function truncate(s, n) {
    s = String(s || "");
    return s.length > n ? s.slice(0, n - 1) + "\u2026" : s;
  }
})();
