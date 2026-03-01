"use strict";

/**
 * Item Triage — OpenWebGoggles Example App
 *
 * A generic step-by-step review interface for triaging lists of items.
 * Works for dependency updates, PR reviews, config changes, task
 * prioritization — any list where each item needs an individual decision.
 *
 * Uses addEventListener (CSP-safe) instead of inline event handlers.
 *
 * Expected state shape:
 *   {
 *     data: {
 *       items: [
 *         {
 *           id: "unique-id",
 *           title: "Item title",
 *           category: "Category label",
 *           priority: "high" | "medium" | "low" | "none",
 *           description: "Longer description...",
 *           details: "Technical details, evidence, context...",
 *           impact: "What happens if we act / don't act",
 *           recommendation: "Suggested action",
 *           notes: ""  // pre-filled reviewer notes (optional)
 *         }
 *       ]
 *     }
 *   }
 */
(function () {
  var wv = new OpenWebGoggles();
  var items = [];
  var currentIndex = 0;
  var submitted = false;

  var els = {
    loading:       document.getElementById("loading"),
    main:          document.getElementById("main"),
    progressBadge: document.getElementById("progress-badge"),
    progressBar:   document.getElementById("progress-bar"),
    itemTabs:      document.getElementById("item-tabs"),
    itemCard:      document.getElementById("item-card"),
    btnPrev:       document.getElementById("btn-prev"),
    btnNext:       document.getElementById("btn-next"),
    btnSkip:       document.getElementById("btn-skip"),
    btnReviewed:   document.getElementById("btn-reviewed"),
    submitBar:     document.getElementById("submit-bar"),
    submitBtn:     document.getElementById("btn-submit"),
    tabsLeft:      document.getElementById("tabs-left"),
    tabsRight:     document.getElementById("tabs-right"),
    connDot:       document.getElementById("conn-dot"),
    sessionInfo:   document.getElementById("session-info"),
  };

  // --- Bind static button events (CSP-safe, no inline handlers) ---
  if (els.tabsLeft)    els.tabsLeft.addEventListener("click", function () { scrollTabs(-1); });
  if (els.tabsRight)   els.tabsRight.addEventListener("click", function () { scrollTabs(1); });
  if (els.btnPrev)     els.btnPrev.addEventListener("click", function () { navPrev(); });
  if (els.btnNext)     els.btnNext.addEventListener("click", function () { navNext(); });
  if (els.btnSkip)     els.btnSkip.addEventListener("click", function () { markSkipped(); });
  if (els.btnReviewed) els.btnReviewed.addEventListener("click", function () { markReviewed(); });
  if (els.submitBtn)   els.submitBtn.addEventListener("click", function () { submitDecisions(); });

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
    var raw = state.data.items;
    if (!raw || !raw.length) {
      els.loading.textContent = "";
      var p = document.createElement("p");
      p.style.color = "#8b949e";
      p.textContent = "Waiting for items...";
      els.loading.appendChild(p);
      return;
    }

    // Merge incoming items with local review state (don't clobber edits)
    if (items.length === 0) {
      items = raw.map(function (item) {
        return Object.assign({ _status: "pending", _notes: item.notes || "", _edited: {} }, item);
      });
    } else {
      // Update fields that haven't been locally edited
      raw.forEach(function (item, i) {
        if (!items[i]) return;
        var edited = items[i]._edited || {};
        Object.keys(item).forEach(function (k) {
          if (!edited[k]) items[i][k] = item[k];
        });
      });
    }

    els.loading.classList.add("hidden");
    els.main.classList.remove("hidden");

    renderTabs();
    renderItem(currentIndex);
    renderProgress();
  }

  function renderProgress() {
    var reviewed = items.filter(function (item) { return item._status !== "pending"; }).length;
    var total = items.length;
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
    els.itemTabs.textContent = "";

    items.forEach(function (item, i) {
      var btn = document.createElement("button");
      var cls = "item-tab";
      if (i === currentIndex) cls += " active";
      if (item._status === "reviewed") cls += " reviewed";
      if (item._status === "skipped") cls += " skipped";
      btn.className = cls;
      btn.title = item.title || "";
      btn.setAttribute("data-tab-index", i);
      btn.innerHTML = (i + 1) + ". " + priorityIcon(item.priority) + " " + escHtml(truncate(item.title, 22));
      els.itemTabs.appendChild(btn);
    });

    // Bind tab click events
    els.itemTabs.querySelectorAll("[data-tab-index]").forEach(function (btn) {
      btn.addEventListener("click", function () {
        var idx = parseInt(btn.getAttribute("data-tab-index"), 10);
        goTo(idx);
      });
    });

    // Scroll active tab into view
    var activeTab = els.itemTabs.children[currentIndex];
    if (activeTab) activeTab.scrollIntoView({ behavior: "smooth", block: "nearest", inline: "nearest" });
  }

  function renderItem(index) {
    currentIndex = index;
    var item = items[index];
    if (!item) return;

    els.itemCard.textContent = "";

    // Header
    var headerEl = document.createElement("div");
    headerEl.className = "item-header";

    var titleWrap = document.createElement("div");
    titleWrap.className = "item-title-wrap";
    var itemNum = document.createElement("div");
    itemNum.className = "item-num";
    itemNum.textContent = "Item " + (index + 1) + " of " + items.length;
    var itemTitle = document.createElement("div");
    itemTitle.className = "item-title";
    itemTitle.textContent = item.title;
    titleWrap.appendChild(itemNum);
    titleWrap.appendChild(itemTitle);

    var statusBadges = document.createElement("div");
    statusBadges.className = "item-status-badges";
    statusBadges.appendChild(createStatusBadge(item._status));

    headerEl.appendChild(titleWrap);
    headerEl.appendChild(statusBadges);
    els.itemCard.appendChild(headerEl);

    // Row 1: priority, category, impact
    var grid1 = document.createElement("div");
    grid1.className = "field-grid";
    grid1.appendChild(createPriorityDropdown(index, item._edited.priority !== undefined ? item._edited.priority : item.priority));
    grid1.appendChild(createEditableField(index, "category", "Category", item._edited.category !== undefined ? item._edited.category : item.category));
    grid1.appendChild(createEditableField(index, "impact", "Impact", item._edited.impact !== undefined ? item._edited.impact : item.impact));
    els.itemCard.appendChild(grid1);

    // Description
    var grid2 = document.createElement("div");
    grid2.className = "field-grid full";
    grid2.appendChild(createEditableField(index, "description", "Description", item._edited.description !== undefined ? item._edited.description : item.description, true));
    els.itemCard.appendChild(grid2);

    // Details
    if (item.details) {
      var grid3 = document.createElement("div");
      grid3.className = "field-grid full";
      var detailsField = document.createElement("div");
      detailsField.className = "field";
      var detailsLabel = document.createElement("div");
      detailsLabel.className = "field-label";
      detailsLabel.textContent = "Details";
      var detailsBlock = document.createElement("div");
      detailsBlock.className = "details-block";
      detailsBlock.textContent = item.details;
      detailsField.appendChild(detailsLabel);
      detailsField.appendChild(detailsBlock);
      grid3.appendChild(detailsField);
      els.itemCard.appendChild(grid3);
    }

    // Recommendation
    var grid4 = document.createElement("div");
    grid4.className = "field-grid full";
    grid4.appendChild(createEditableField(index, "recommendation", "Recommendation", item._edited.recommendation !== undefined ? item._edited.recommendation : item.recommendation, true));
    els.itemCard.appendChild(grid4);

    // Reviewer notes
    var grid5 = document.createElement("div");
    grid5.className = "field-grid full";
    grid5.appendChild(createEditableField(index, "_notes", "Reviewer Notes", item._notes, true, "Add notes, context, or caveats..."));
    els.itemCard.appendChild(grid5);

    // Update footer button states
    els.btnPrev.disabled = index === 0;
    els.btnNext.disabled = index === items.length - 1;
    els.btnSkip.classList.toggle("hidden", item._status === "skipped");
    els.btnReviewed.classList.toggle("hidden", item._status === "reviewed");
  }

  // --- DOM field builders (CSP-safe, no inline handlers) ---

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

  function createPriorityDropdown(index, currentPriority) {
    var levels = ["High", "Medium", "Low", "None"];
    var wrapper = document.createElement("div");
    wrapper.className = "field editing-select";

    var lbl = document.createElement("div");
    lbl.className = "field-label";
    lbl.textContent = "Priority";
    wrapper.appendChild(lbl);

    var prClass = "pri-" + (currentPriority || "none").toLowerCase();
    var select = document.createElement("select");
    select.className = "field-value pri-select " + prClass;

    levels.forEach(function (s) {
      var opt = document.createElement("option");
      opt.value = s;
      opt.textContent = s;
      if (s.toLowerCase() === (currentPriority || "").toLowerCase()) opt.selected = true;
      select.appendChild(opt);
    });

    select.addEventListener("change", function () {
      saveEdit(index, "priority", select.value);
      select.className = "field-value pri-select pri-" + select.value.toLowerCase();
    });

    wrapper.appendChild(select);
    return wrapper;
  }

  function createStatusBadge(status) {
    var span = document.createElement("span");
    if (status === "reviewed") {
      span.className = "status-badge status-reviewed";
      span.innerHTML = "&#10003; Reviewed";
    } else if (status === "skipped") {
      span.className = "status-badge status-skipped";
      span.textContent = "Skipped";
    } else {
      span.className = "status-badge status-pending";
      span.textContent = "Pending";
    }
    return span;
  }

  function priorityIcon(pri) {
    var s = (pri || "").toLowerCase();
    if (s === "high") return "&#9650;";
    if (s === "medium") return "&#9679;";
    if (s === "low") return "&#9660;";
    return "&#8226;";
  }

  // --- Actions (all local, no window.* exports) ---

  function saveEdit(index, key, value) {
    if (!items[index]) return;
    items[index]._edited = items[index]._edited || {};
    items[index]._edited[key] = value;
    if (key === "_notes") items[index]._notes = value;
    else items[index][key] = value;
  }

  function goTo(index) {
    currentIndex = index;
    renderTabs();
    renderItem(index);
  }

  function navPrev() {
    if (currentIndex > 0) goTo(currentIndex - 1);
  }

  function navNext() {
    if (currentIndex < items.length - 1) goTo(currentIndex + 1);
  }

  function markSkipped() {
    items[currentIndex]._status = "skipped";
    renderTabs();
    renderItem(currentIndex);
    renderProgress();
    autoAdvance();
  }

  function markReviewed() {
    items[currentIndex]._status = "reviewed";
    renderTabs();
    renderItem(currentIndex);
    renderProgress();
    autoAdvance();
  }

  function autoAdvance() {
    // Find next pending item
    for (var i = currentIndex + 1; i < items.length; i++) {
      if (items[i]._status === "pending") { goTo(i); return; }
    }
    // Wrap around from start
    for (var j = 0; j < currentIndex; j++) {
      if (items[j]._status === "pending") { goTo(j); return; }
    }
    // All done — stay on current
  }

  function scrollTabs(dir) {
    var tabs = els.itemTabs;
    tabs.scrollBy({ left: dir * 200, behavior: "smooth" });
  }

  function submitDecisions() {
    if (submitted) return;
    submitted = true;
    els.submitBar.classList.add("hidden");

    var report = items.map(function (item) {
      return {
        id: item.id,
        title: item.title,
        category: item.category,
        priority: item.priority,
        description: item.description,
        recommendation: item.recommendation,
        status: item._status,
        notes: item._notes,
        edited_fields: Object.keys(item._edited || {})
      };
    });

    wv.sendAction("submit_decisions", "submit", report).then(function () {
      els.itemCard.textContent = "";
      var wrap = document.createElement("div");
      wrap.className = "loading-screen";
      var inner = document.createElement("div");
      inner.style.textAlign = "center";
      var p1 = document.createElement("p");
      p1.style.color = "var(--green)";
      p1.style.fontSize = "18px";
      p1.style.marginBottom = "8px";
      p1.innerHTML = "&#10003; Decisions Submitted";
      var p2 = document.createElement("p");
      p2.style.color = "var(--text2)";
      p2.textContent = "Waiting for agent to process...";
      inner.appendChild(p1);
      inner.appendChild(p2);
      wrap.appendChild(inner);
      els.itemCard.appendChild(wrap);
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
