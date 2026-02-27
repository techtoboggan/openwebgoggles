/**
 * {{APP_NAME}} — OpenWebGoggles App
 *
 * This is a template app. Customize the render functions below to build your UI.
 */
(function () {
  "use strict";

  var wv = new OpenWebGoggles();

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
      els.loading.textContent = "";
      var p = document.createElement("p");
      p.className = "error";
      p.textContent = "Failed to connect: " + err.message;
      els.loading.appendChild(p);
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

    // Render message (DOM API — no innerHTML)
    els.messageArea.textContent = "";
    if (state.message) {
      var p = document.createElement("p");
      p.className = "message";
      p.textContent = state.message;
      els.messageArea.appendChild(p);
    }

    // Render data (customize this for your app)
    renderData(state.data || {});

    // Render action buttons
    renderActions(state.actions_requested || []);
  }

  function renderData(data) {
    // Default: show raw JSON. Override this for your custom UI. (DOM API — no innerHTML)
    els.dataArea.textContent = "";
    if (Object.keys(data).length === 0) {
      var p = document.createElement("p");
      p.className = "muted";
      p.textContent = "No data from agent yet.";
      els.dataArea.appendChild(p);
      return;
    }
    var pre = document.createElement("pre");
    pre.className = "data-display";
    pre.textContent = JSON.stringify(data, null, 2);
    els.dataArea.appendChild(pre);
  }

  function renderActions(actions) {
    els.actionsArea.textContent = "";
    if (actions.length === 0) return;

    var bar = document.createElement("div");
    bar.className = "actions-bar";

    actions.forEach(function (action) {
      if (action.type === "input") {
        var group = document.createElement("div");
        group.className = "input-group";
        var label = document.createElement("label");
        label.setAttribute("for", "input-" + action.id);
        label.textContent = action.label;
        var input = document.createElement("input");
        input.type = "text";
        input.id = "input-" + action.id;
        input.placeholder = action.description || "";
        var btn = document.createElement("button");
        btn.className = "btn btn-default";
        btn.textContent = "Submit";
        btn.addEventListener("click", (function (aid) {
          return function () {
            var inp = document.getElementById("input-" + aid);
            if (!inp) return;
            var val = inp.value.trim();
            if (!val) return;
            wv.submitInput(aid, val).then(function () { inp.disabled = true; });
          };
        })(action.id));
        group.appendChild(label);
        group.appendChild(input);
        group.appendChild(btn);
        bar.appendChild(group);
      } else {
        var btnClass = "btn";
        if (action.type === "approve") btnClass += " btn-approve";
        else if (action.type === "reject") btnClass += " btn-reject";
        else btnClass += " btn-default";
        var actionBtn = document.createElement("button");
        actionBtn.className = btnClass;
        actionBtn.textContent = action.label;
        actionBtn.addEventListener("click", (function (aid, atype) {
          return function () {
            var value = atype === "approve" || atype === "confirm" ? true : false;
            wv.sendAction(aid, atype, value).then(function () {
              var buttons = els.actionsArea.querySelectorAll("button");
              buttons.forEach(function (b) { b.disabled = true; });
              var p = document.createElement("p");
              p.className = "muted";
              p.textContent = "Response sent. Waiting for agent...";
              els.actionsArea.appendChild(p);
            });
          };
        })(action.id, action.type));
        bar.appendChild(actionBtn);
      }
    });

    els.actionsArea.appendChild(bar);
  }

  // --- Helpers ---

  function escapeHtml(str) {
    var div = document.createElement("div");
    div.textContent = str;
    return div.innerHTML;
  }

  function escAttr(str) {
    return String(str == null ? "" : str)
      .replace(/&/g, "&amp;")
      .replace(/'/g, "&#39;")
      .replace(/"/g, "&quot;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;");
  }
})();
