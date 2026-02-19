/**
 * Approval Review — OpenCode Webview Example App
 *
 * A rich code review UI for approving/rejecting proposed changes.
 * Renders diffs, file summaries, and provides approve/reject/feedback actions.
 */
(function () {
  "use strict";

  var wv = new OpenCodeWebview();

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
      els.loading.innerHTML = '<p class="error">Failed to connect: ' + err.message + "</p>";
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
      els.actionsArea.innerHTML = '<p class="muted">Agent is processing your response...</p>';
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
    if (message) {
      els.messageArea.innerHTML = '<div class="message">' + escapeHtml(message) + "</div>";
    } else {
      els.messageArea.innerHTML = "";
    }
  }

  function renderFiles(data) {
    var files = data.files_changed || data.files || [];
    if (files.length === 0) {
      els.filesArea.innerHTML = "";
      return;
    }

    var html = '<div class="files-list">';
    files.forEach(function (file, index) {
      html += '<div class="file-card">';
      html += '<div class="file-header" onclick="toggleFile(' + index + ')">';
      html += '<span class="file-icon">&#128196;</span>';
      html += '<span class="file-path">' + escapeHtml(file.path || file.name || "unknown") + "</span>";
      if (file.summary) {
        html += '<span class="file-summary">' + escapeHtml(file.summary) + "</span>";
      }
      html += '<span class="file-toggle" id="toggle-' + index + '">&#9660;</span>';
      html += "</div>";

      if (file.diff) {
        html += '<div class="file-diff" id="diff-' + index + '">';
        html += renderDiff(file.diff);
        html += "</div>";
      } else if (file.content) {
        html += '<div class="file-diff" id="diff-' + index + '">';
        html += '<pre class="diff-content">' + escapeHtml(file.content) + "</pre>";
        html += "</div>";
      }

      html += "</div>";
    });
    html += "</div>";
    els.filesArea.innerHTML = html;
  }

  function renderDiff(diffText) {
    var lines = diffText.split("\n");
    var html = '<div class="diff-view">';
    lines.forEach(function (line) {
      var cls = "diff-line";
      if (line.startsWith("+") && !line.startsWith("+++")) cls += " diff-add";
      else if (line.startsWith("-") && !line.startsWith("---")) cls += " diff-remove";
      else if (line.startsWith("@@")) cls += " diff-hunk";
      else if (line.startsWith("diff ") || line.startsWith("index ")) cls += " diff-meta";
      html += '<div class="' + cls + '">' + escapeHtml(line) + "</div>";
    });
    html += "</div>";
    return html;
  }

  function renderSummary(data) {
    var parts = [];
    if (data.total_files !== undefined) parts.push(data.total_files + " files");
    if (data.total_lines_added !== undefined) parts.push("+" + data.total_lines_added);
    if (data.total_lines_removed !== undefined) parts.push("-" + data.total_lines_removed);

    if (parts.length > 0) {
      els.summaryArea.innerHTML =
        '<div class="summary-bar">' +
        '<span class="summary-stats">' + parts.join(" &middot; ") + "</span>" +
        "</div>";
    } else {
      els.summaryArea.innerHTML = "";
    }
  }

  function renderActions(actions) {
    if (actions.length === 0) {
      els.actionsArea.innerHTML = '<p class="muted">Waiting for agent to request actions...</p>';
      return;
    }

    var html = '<div class="actions-container">';

    // Feedback input (check if there's an input-type action)
    var inputAction = actions.find(function (a) { return a.type === "input"; });
    if (inputAction) {
      html +=
        '<div class="feedback-group">' +
        '<label for="feedback-input">' + escapeHtml(inputAction.label) + "</label>" +
        '<textarea id="feedback-input" rows="3" placeholder="' +
        escapeHtml(inputAction.description || "Type your feedback...") +
        '"></textarea>' +
        "</div>";
    }

    // Action buttons
    html += '<div class="actions-bar">';
    actions.forEach(function (action) {
      if (action.type === "input") return; // Already rendered as textarea

      var btnClass = "btn";
      if (action.type === "approve") btnClass += " btn-approve";
      else if (action.type === "reject") btnClass += " btn-reject";
      else btnClass += " btn-default";

      var btnTitle = escapeHtml(action.description || "");
      var btnLabel = escapeHtml(action.label);
      html += '<button class="' + btnClass + '" onclick="handleAction(\'' + action.id + "','" + action.type + '\')" title="' + btnTitle + '">' + btnLabel + "</button>";
    });
    html += "</div></div>";
    els.actionsArea.innerHTML = html;
  }

  // --- Action handlers ---

  window.handleAction = function (actionId, type) {
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
      els.actionsArea.innerHTML =
        '<div class="response-sent">' +
        '<span class="check-small">&#10003;</span> ' +
        (type === "approve" ? "Approved" : type === "reject" ? "Rejected" : "Response sent") +
        " — waiting for agent..." +
        "</div>";
    });
  };

  window.toggleFile = function (index) {
    var diff = document.getElementById("diff-" + index);
    var toggle = document.getElementById("toggle-" + index);
    if (diff) {
      var isHidden = diff.style.display === "none";
      diff.style.display = isHidden ? "block" : "none";
      toggle.innerHTML = isHidden ? "&#9660;" : "&#9654;";
    }
  };

  function escapeHtml(str) {
    var div = document.createElement("div");
    div.textContent = str;
    return div.innerHTML;
  }
})();
