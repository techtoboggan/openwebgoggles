/**
 * {{APP_NAME}} — OpenCode Webview App
 *
 * This is a template app. Customize the render functions below to build your UI.
 */
(function () {
  "use strict";

  var wv = new OpenCodeWebview();

  var els = {
    loading: document.getElementById("loading"),
    content: document.getElementById("content"),
    statusBadge: document.getElementById("status-badge"),
    indicator: document.getElementById("connection-indicator"),
    appTitle: document.getElementById("app-title"),
    messageArea: document.getElementById("message-area"),
    dataArea: document.getElementById("data-area"),
    actionsArea: document.getElementById("actions-area"),
  };

  // --- Connect to agent ---

  wv.connect()
    .then(function () {
      els.loading.classList.add("hidden");
      els.content.classList.remove("hidden");
      els.indicator.classList.remove("disconnected");
      els.indicator.classList.add("connected");

      // Render initial state
      var state = wv.getState();
      if (state) renderState(state);
    })
    .catch(function (err) {
      els.loading.innerHTML =
        '<p class="error">Failed to connect: ' + err.message + "</p>";
    });

  // --- Listen for state updates ---

  wv.onStateUpdate(function (state) {
    renderState(state);
  });

  wv.on("disconnected", function () {
    els.indicator.classList.remove("connected");
    els.indicator.classList.add("disconnected");
  });

  // --- Render functions (customize these) ---

  function renderState(state) {
    // Update status badge
    els.statusBadge.textContent = state.status || "unknown";
    els.statusBadge.className = "badge status-" + (state.status || "unknown");

    // Update title
    if (state.title) {
      els.appTitle.textContent = state.title;
    }

    // Render message
    if (state.message) {
      els.messageArea.innerHTML = '<p class="message">' + escapeHtml(state.message) + "</p>";
    } else {
      els.messageArea.innerHTML = "";
    }

    // Render data (customize this for your app)
    renderData(state.data || {});

    // Render action buttons
    renderActions(state.actions_requested || []);
  }

  function renderData(data) {
    // Default: show raw JSON. Override this for your custom UI.
    if (Object.keys(data).length === 0) {
      els.dataArea.innerHTML = '<p class="muted">No data from agent yet.</p>';
      return;
    }
    els.dataArea.innerHTML =
      '<pre class="data-display">' + escapeHtml(JSON.stringify(data, null, 2)) + "</pre>";
  }

  function renderActions(actions) {
    if (actions.length === 0) {
      els.actionsArea.innerHTML = "";
      return;
    }

    var html = '<div class="actions-bar">';
    actions.forEach(function (action) {
      var btnClass = "btn";
      if (action.type === "approve") btnClass += " btn-approve";
      else if (action.type === "reject") btnClass += " btn-reject";
      else btnClass += " btn-default";

      if (action.type === "input") {
        html +=
          '<div class="input-group">' +
          '<label for="input-' + action.id + '">' + escapeHtml(action.label) + "</label>" +
          '<input type="text" id="input-' + action.id + '" placeholder="' +
          escapeHtml(action.description || "") + '">' +
          '<button class="btn btn-default" onclick="submitInput(\'' +
          action.id + "')\">" + "Submit</button>" +
          "</div>";
      } else {
        html +=
          '<button class="' + btnClass + '" onclick="handleAction(\'' +
          action.id + "', '" + action.type + "')\">" +
          escapeHtml(action.label) + "</button>";
      }
    });
    html += "</div>";
    els.actionsArea.innerHTML = html;
  }

  // --- Action handlers (exposed globally for onclick) ---

  window.handleAction = function (actionId, type) {
    var value = type === "approve" || type === "confirm" ? true : false;
    wv.sendAction(actionId, type, value).then(function () {
      // Disable buttons after action
      var buttons = els.actionsArea.querySelectorAll("button");
      buttons.forEach(function (btn) {
        btn.disabled = true;
      });
      els.actionsArea.innerHTML +=
        '<p class="muted">Response sent. Waiting for agent...</p>';
    });
  };

  window.submitInput = function (actionId) {
    var input = document.getElementById("input-" + actionId);
    if (!input) return;
    var value = input.value.trim();
    if (!value) return;
    wv.submitInput(actionId, value).then(function () {
      input.disabled = true;
    });
  };

  // --- Helpers ---

  function escapeHtml(str) {
    var div = document.createElement("div");
    div.textContent = str;
    return div.innerHTML;
  }
})();
