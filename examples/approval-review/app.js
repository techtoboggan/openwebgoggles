/**
 * Approval Review — OpenWebGoggles Example App
 *
 * A rich code review UI for approving/rejecting proposed changes.
 * Renders diffs, file summaries, and provides approve/reject/feedback actions.
 *
 * Uses addEventListener (CSP-safe) instead of inline event handlers.
 */
(function () {
  "use strict";

  var wv = new OpenWebGoggles();

  var els = {
    loading: document.getElementById("loading"),
    content: document.getElementById("content"),
    completed: document.getElementById("completed"),
    completedMessage: document.getElementById("completed-message"),
    statusBadge: document.getElementById("status-badge"),
    indicator: document.getElementById("connection-indicator"),
    sessionInfo: document.getElementById("session-info"),
    appTitle: document.getElementById("app-title"),
    messageArea: document.getElementById("message-area"),
    filesArea: document.getElementById("files-area"),
    summaryArea: document.getElementById("summary-area"),
    actionsArea: document.getElementById("actions-area"),
  };

  var responded = false;

  // --- Connect ---

  wv.connect()
    .then(function () {
      els.loading.classList.add("hidden");
      els.content.classList.remove("hidden");
      els.indicator.classList.remove("disconnected");
      els.indicator.classList.add("connected");

      // Show session info
      var manifest = wv.getManifest();
      if (manifest && manifest.session) {
        els.sessionInfo.textContent = "Session: " + manifest.session.id.slice(0, 8);
      }

      var state = wv.getState();
      if (state) renderState(state);
    })
    .catch(function (err) {
      els.loading.textContent = "";
      var p = document.createElement("p");
      p.className = "error";
      p.textContent = "Failed to connect: " + err.message;
      els.loading.appendChild(p);
    });

  wv.onStateUpdate(function (state) {
    renderState(state);
  });

  wv.on("disconnected", function () {
    els.indicator.classList.remove("connected");
    els.indicator.classList.add("disconnected");
  });

  // --- Render ---

  function renderState(state) {
    els.statusBadge.textContent = state.status || "unknown";
    els.statusBadge.className = "badge status-" + (state.status || "unknown");

    if (state.title) els.appTitle.textContent = state.title;

    if (state.status === "completed") {
      els.content.classList.add("hidden");
      els.completed.classList.remove("hidden");
      els.completedMessage.textContent = state.message || "Workflow completed.";
      return;
    }

    if (state.status === "processing") {
      els.actionsArea.textContent = "";
      var p = document.createElement("p");
      p.className = "muted";
      p.textContent = "Agent is processing your response...";
      els.actionsArea.appendChild(p);
      return;
    }

    renderMessage(state.message);
    renderFiles(state.data || {});
    renderSummary(state.data || {});
    if (!responded) {
      renderActions(state.actions_requested || []);
    }
  }

  function renderMessage(message) {
    els.messageArea.textContent = "";
    if (message) {
      var div = document.createElement("div");
      div.className = "message";
      div.textContent = message;
      els.messageArea.appendChild(div);
    }
  }

  function renderFiles(data) {
    var files = data.files_changed || data.files || [];
    if (files.length === 0) {
      els.filesArea.textContent = "";
      return;
    }

    var container = document.createElement("div");
    container.className = "files-list";

    files.forEach(function (file, index) {
      var card = document.createElement("div");
      card.className = "file-card";

      // File header (clickable to toggle diff)
      var header = document.createElement("div");
      header.className = "file-header";
      header.setAttribute("data-file-index", index);

      var icon = document.createElement("span");
      icon.className = "file-icon";
      icon.innerHTML = "&#128196;";
      header.appendChild(icon);

      var path = document.createElement("span");
      path.className = "file-path";
      path.textContent = file.path || file.name || "unknown";
      header.appendChild(path);

      if (file.summary) {
        var summary = document.createElement("span");
        summary.className = "file-summary";
        summary.textContent = file.summary;
        header.appendChild(summary);
      }

      var toggle = document.createElement("span");
      toggle.className = "file-toggle";
      toggle.id = "toggle-" + index;
      toggle.innerHTML = "&#9660;";
      header.appendChild(toggle);

      card.appendChild(header);

      // Diff content
      if (file.diff) {
        var diffEl = document.createElement("div");
        diffEl.className = "file-diff";
        diffEl.id = "diff-" + index;
        diffEl.appendChild(buildDiffView(file.diff));
        card.appendChild(diffEl);
      } else if (file.content) {
        var diffEl2 = document.createElement("div");
        diffEl2.className = "file-diff";
        diffEl2.id = "diff-" + index;
        var pre = document.createElement("pre");
        pre.className = "diff-content";
        pre.textContent = file.content;
        diffEl2.appendChild(pre);
        card.appendChild(diffEl2);
      }

      container.appendChild(card);
    });

    els.filesArea.textContent = "";
    els.filesArea.appendChild(container);
    bindFileEvents();
  }

  function buildDiffView(diffText) {
    var lines = diffText.split("\n");
    var view = document.createElement("div");
    view.className = "diff-view";

    lines.forEach(function (line) {
      var el = document.createElement("div");
      var cls = "diff-line";
      if (line.startsWith("+") && !line.startsWith("+++")) cls += " diff-add";
      else if (line.startsWith("-") && !line.startsWith("---")) cls += " diff-remove";
      else if (line.startsWith("@@")) cls += " diff-hunk";
      else if (line.startsWith("diff ") || line.startsWith("index ")) cls += " diff-meta";
      el.className = cls;
      el.textContent = line;
      view.appendChild(el);
    });

    return view;
  }

  function renderSummary(data) {
    var parts = [];
    if (data.total_files !== undefined) parts.push(data.total_files + " files");
    if (data.total_lines_added !== undefined) parts.push("+" + data.total_lines_added);
    if (data.total_lines_removed !== undefined) parts.push("-" + data.total_lines_removed);

    els.summaryArea.textContent = "";
    if (parts.length > 0) {
      var bar = document.createElement("div");
      bar.className = "summary-bar";
      var stats = document.createElement("span");
      stats.className = "summary-stats";
      stats.textContent = parts.join(" \u00B7 ");
      bar.appendChild(stats);
      els.summaryArea.appendChild(bar);
    }
  }

  function renderActions(actions) {
    els.actionsArea.textContent = "";
    if (actions.length === 0) {
      var msg = document.createElement("p");
      msg.className = "muted";
      msg.textContent = "Waiting for agent to request actions...";
      els.actionsArea.appendChild(msg);
      return;
    }

    var container = document.createElement("div");
    container.className = "actions-container";

    // Feedback input (check if there's an input-type action)
    var inputAction = actions.find(function (a) { return a.type === "input"; });
    if (inputAction) {
      var group = document.createElement("div");
      group.className = "feedback-group";
      var label = document.createElement("label");
      label.setAttribute("for", "feedback-input");
      label.textContent = inputAction.label;
      var textarea = document.createElement("textarea");
      textarea.id = "feedback-input";
      textarea.rows = 3;
      textarea.placeholder = inputAction.description || "Type your feedback...";
      group.appendChild(label);
      group.appendChild(textarea);
      container.appendChild(group);
    }

    // Action buttons
    var bar = document.createElement("div");
    bar.className = "actions-bar";

    actions.forEach(function (action) {
      if (action.type === "input") return; // Already rendered as textarea

      var btn = document.createElement("button");
      var btnClass = "btn";
      if (action.type === "approve") btnClass += " btn-approve";
      else if (action.type === "reject") btnClass += " btn-reject";
      else btnClass += " btn-default";
      btn.className = btnClass;
      btn.title = action.description || "";
      btn.textContent = action.label;
      btn.setAttribute("data-action-id", action.id);
      btn.setAttribute("data-action-type", action.type);
      bar.appendChild(btn);
    });

    container.appendChild(bar);
    els.actionsArea.appendChild(container);
    bindActionEvents();
  }

  // --- Event binding (CSP-safe) ---

  function bindFileEvents() {
    els.filesArea.querySelectorAll("[data-file-index]").forEach(function (header) {
      header.addEventListener("click", function () {
        var index = parseInt(header.getAttribute("data-file-index"), 10);
        toggleFile(index);
      });
    });
  }

  function bindActionEvents() {
    els.actionsArea.querySelectorAll("[data-action-id]").forEach(function (btn) {
      btn.addEventListener("click", function () {
        var actionId = btn.getAttribute("data-action-id");
        var actionType = btn.getAttribute("data-action-type");
        handleAction(actionId, actionType);
      });
    });
  }

  // --- Action handlers ---

  function handleAction(actionId, type) {
    if (responded) return;
    responded = true;

    var value = type === "approve" || type === "confirm" ? true : false;
    var promises = [wv.sendAction(actionId, type, value)];

    // Also send feedback if there's an input action with text
    var feedbackInput = document.getElementById("feedback-input");
    if (feedbackInput && feedbackInput.value.trim()) {
      var inputAction = (wv.getRequestedActions() || []).find(function (a) {
        return a.type === "input";
      });
      if (inputAction) {
        promises.push(wv.submitInput(inputAction.id, feedbackInput.value.trim()));
      }
    }

    Promise.all(promises).then(function () {
      els.actionsArea.textContent = "";
      var div = document.createElement("div");
      div.className = "response-sent";
      var label = type === "approve" ? "Approved" : type === "reject" ? "Rejected" : "Response sent";
      div.innerHTML = '<span class="check-small">&#10003;</span> ' + escapeHtml(label) + " \u2014 waiting for agent...";
      els.actionsArea.appendChild(div);
    });
  }

  function toggleFile(index) {
    var diff = document.getElementById("diff-" + index);
    var toggle = document.getElementById("toggle-" + index);
    if (diff) {
      var isHidden = diff.style.display === "none";
      diff.style.display = isHidden ? "block" : "none";
      toggle.innerHTML = isHidden ? "&#9660;" : "&#9654;";
    }
  }

  function escapeHtml(str) {
    var div = document.createElement("div");
    div.textContent = str;
    return div.innerHTML;
  }
})();
