"use strict";
// Client-side field validation engine.
// Validates required fields, patterns, min/max, lengths.

(function (OWG) {
  var validationErrors = {};

  // ─── Validate a single field value against its config ───────────────────────
  OWG.validateField = function (key, value, config) {
    if (!config) return null;

    // Required check
    if (config.required) {
      if (value === undefined || value === null || value === "" || value === false) {
        return config.errorMessage || "This field is required";
      }
    }

    // Skip further validation on empty optional fields
    if (value === undefined || value === null || value === "") return null;

    // Pattern (regex) — only for string values
    // Defense-in-depth: skip regex on oversized patterns/values to prevent ReDoS
    if (config.pattern && typeof value === "string") {
      if (config.pattern.length <= 500 && value.length <= 10000) {
        try {
          var re = new RegExp(config.pattern);
          if (!re.test(value)) {
            return config.errorMessage || "Invalid format";
          }
        } catch (e) {
          // Invalid regex — skip validation
        }
      }
    }

    // Min/max length — only for string values
    if (config.minLength && typeof value === "string" && value.length < config.minLength) {
      return config.errorMessage || "Too short (min " + config.minLength + " characters)";
    }
    if (config.maxLength && typeof value === "string" && value.length > config.maxLength) {
      return config.errorMessage || "Too long (max " + config.maxLength + " characters)";
    }

    // Min/max — only for number values
    if (config.min !== undefined && config.min !== null && typeof value === "number" && value < config.min) {
      return config.errorMessage || "Must be at least " + config.min;
    }
    if (config.max !== undefined && config.max !== null && typeof value === "number" && value > config.max) {
      return config.errorMessage || "Must be at most " + config.max;
    }

    return null; // valid
  };

  // ─── Validate all required fields ───────────────────────────────────────────
  OWG.validateAllRequired = function () {
    var validators = OWG.fieldValidators || {};
    var errors = {};
    var hasErrors = false;

    for (var key in validators) {
      if (!validators.hasOwnProperty(key)) continue;
      var error = OWG.validateField(key, OWG.formValues[key], validators[key]);
      if (error) {
        errors[key] = error;
        hasErrors = true;
      }
    }

    validationErrors = errors;
    return hasErrors ? errors : null;
  };

  // ─── Show/clear validation error for a specific field ───────────────────────
  OWG.showFieldError = function (key, message) {
    validationErrors[key] = message;
    var errorEl = document.querySelector('[data-error-for="' + key + '"]');
    if (errorEl) {
      errorEl.textContent = message || "";
    }
    // Add invalid class to parent field container
    var fieldEl = document.querySelector('[data-field-key="' + key + '"]');
    if (fieldEl) {
      var container = fieldEl.closest(".field");
      if (container) container.classList.toggle("field-invalid", !!message);
    }
  };

  OWG.clearFieldError = function (key) {
    delete validationErrors[key];
    var errorEl = document.querySelector('[data-error-for="' + key + '"]');
    if (errorEl) errorEl.textContent = "";
    var fieldEl = document.querySelector('[data-field-key="' + key + '"]');
    if (fieldEl) {
      var container = fieldEl.closest(".field");
      if (container) container.classList.remove("field-invalid");
    }
  };

  // ─── Show all validation errors (after submit attempt) ──────────────────────
  OWG.showAllErrors = function (errors) {
    for (var key in errors) {
      if (errors.hasOwnProperty(key)) {
        OWG.showFieldError(key, errors[key]);
      }
    }
    // Scroll to first error
    var firstError = document.querySelector(".field-invalid");
    if (firstError) firstError.scrollIntoView({ behavior: "smooth", block: "center" });
  };

  // ─── Check if there are currently any validation errors ─────────────────────
  OWG.hasValidationErrors = function () {
    for (var key in validationErrors) {
      if (validationErrors.hasOwnProperty(key)) return true;
    }
    return false;
  };

  OWG.getValidationErrors = function () {
    return validationErrors;
  };

  // ─── Bind validation to form fields (called from app.js bindEvents) ─────────
  OWG.bindValidation = function (root) {
    root.querySelectorAll("[data-field-key]").forEach(function (el) {
      var key = el.getAttribute("data-field-key");
      var config = OWG.fieldValidators[key];
      if (!config) return;

      // Validate on blur
      el.addEventListener("blur", function () {
        var error = OWG.validateField(key, OWG.formValues[key], config);
        if (error) {
          OWG.showFieldError(key, error);
        } else {
          OWG.clearFieldError(key);
        }
      });

      // Clear error on input if now valid
      var event = el.tagName === "SELECT" ? "change" : "input";
      el.addEventListener(event, function () {
        if (validationErrors[key]) {
          var error = OWG.validateField(key, OWG.formValues[key], config);
          if (!error) OWG.clearFieldError(key);
        }
      });
    });
  };

})(window.OWG = window.OWG || {});
