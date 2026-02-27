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

      if (rule.show) applyVisibility(rule.show, met);
      if (rule.hide) applyVisibility(rule.hide, !met);
      if (rule.enable) applyInteractivity(rule.enable, met);
      if (rule.disable) applyInteractivity(rule.disable, !met);
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
      try { return new RegExp(when.matches).test(value); } catch (e) { return false; }
    }
    return false;
  }

  // ─── Apply visibility to fields by key ──────────────────────────────────────
  function applyVisibility(keys, visible) {
    keys.forEach(function (key) {
      var el = document.querySelector('[data-field-key="' + key + '"]');
      if (el) {
        var field = el.closest(".field");
        if (field) field.style.display = visible ? "" : "none";
        return;
      }
      // Also check sections by id
      var sec = document.querySelector('[data-section-id="' + key + '"]');
      if (sec) sec.style.display = visible ? "" : "none";
    });
  }

  // ─── Apply interactivity to action buttons by id ────────────────────────────
  function applyInteractivity(ids, enabled) {
    ids.forEach(function (id) {
      var btn = document.querySelector('[data-action-id="' + id + '"]');
      if (btn) btn.disabled = !enabled;
    });
  }

})(window.OWG = window.OWG || {});
