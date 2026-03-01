"use strict";
// Client-side conditional field behaviors.
// Evaluates show/hide/enable/disable rules based on form field values.

(function (OWG) {
  var rules = [];

  // ─── Initialize behaviors from state ────────────────────────────────────────
  OWG.initBehaviors = function (state) {
    rules = (state && state.behaviors) || [];
    if (rules.length) OWG.evaluateBehaviors();
  };

  // ─── Evaluate all behavior rules ────────────────────────────────────────────
  // Called on every form value change and once on init.
  OWG.evaluateBehaviors = function () {
    if (!rules.length) return;
    var fv = OWG.formValues || {};

    rules.forEach(function (rule) {
      var when = rule.when || {};
      var fieldKey = when.field;
      var value = fv[fieldKey];
      var met = checkCondition(when, value);

      if (Array.isArray(rule.show)) applyVisibility(rule.show, met);
      if (Array.isArray(rule.hide)) applyVisibility(rule.hide, !met);
      if (Array.isArray(rule.enable)) applyInteractivity(rule.enable, met);
      if (Array.isArray(rule.disable)) applyInteractivity(rule.disable, !met);
    });
  };

  // ─── Condition evaluator ────────────────────────────────────────────────────
  function checkCondition(when, value) {
    if ("equals" in when) return value === when.equals;
    if ("notEquals" in when) return value !== when.notEquals;
    if ("in" in when) return Array.isArray(when["in"]) && when["in"].indexOf(value) !== -1;
    if ("notIn" in when) return !Array.isArray(when.notIn) || when.notIn.indexOf(value) === -1;
    if ("checked" in when) return !!value === !!when.checked;
    if ("unchecked" in when) return !value;
    if ("empty" in when) return value === "" || value === undefined || value === null;
    if ("notEmpty" in when) return value !== "" && value !== undefined && value !== null;
    if ("matches" in when) {
      if (typeof value !== "string") return false;
      // Defense-in-depth: skip regex on oversized patterns/values to prevent ReDoS
      if (when.matches.length > 500 || value.length > 10000) return false;
      // Check for nested quantifiers that cause catastrophic backtracking
      if (/(\+|\*|\{)\s*\)\s*(\+|\*|\{)/.test(when.matches)) return false;
      try { return new RegExp(when.matches).test(value); } catch (e) { return false; }
    }
    return false;
  }

  // ─── Selector-safe query helper (prevents CSS selector injection) ───────────
  function safeQuery(attr, value) {
    // Use CSS.escape() when available to prevent selector injection via crafted keys
    var escaped = (typeof CSS !== "undefined" && CSS.escape) ? CSS.escape(value) : value.replace(/["\\]/g, "\\$&");
    return document.querySelector("[" + attr + '="' + escaped + '"]');
  }

  // ─── Apply visibility to fields by key ──────────────────────────────────────
  function applyVisibility(keys, visible) {
    keys.forEach(function (key) {
      var el = safeQuery("data-field-key", key);
      if (el) {
        var field = el.closest(".field");
        if (field) field.style.display = visible ? "" : "none";
        return;
      }
      // Also check sections by id
      var sec = safeQuery("data-section-id", key);
      if (sec) sec.style.display = visible ? "" : "none";
    });
  }

  // ─── Apply interactivity to action buttons by id ────────────────────────────
  function applyInteractivity(ids, enabled) {
    ids.forEach(function (id) {
      var btn = safeQuery("data-action-id", id);
      if (btn) btn.disabled = !enabled;
    });
  }

})(window.OWG = window.OWG || {});
