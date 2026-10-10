/* Integrity site — one small script, no dependencies.
   Responsibilities: the contact form, the language switch, and a couple of
   progressive enhancements. Everything degrades gracefully without JS: the
   mailto links already work and the pages are fully readable. */

(function () {
  "use strict";

  /* ------------------------------------------------------------------ *
   * Replace these two values before publishing. See web/README.md.
   * ------------------------------------------------------------------ */

  // Temporary contact address. Replace with the professional domain address.
  var CONTACT_EMAIL = "bamontejano@yahoo.es";

  // Leave empty to keep the no-backend behaviour (validated mailto fallback).
  // Set it to your form endpoint URL to POST JSON instead. Both paths validate
  // the same way; the endpoint path is the one that captures leads reliably.
  var FORM_ENDPOINT = "";

  /* ------------------------------------------------------------------ */

  var MESSAGES = {
    es: {
      required: "Este campo es obligatorio.",
      email: "Revisa la dirección de correo.",
      consent: "Necesitamos tu consentimiento para responder.",
      mailtoOpened: "Se ha abierto tu cliente de correo con los datos ya rellenos.",
      copied: "Resumen copiado. Pégalo en un correo a ",
      copyFailed: "No se pudo copiar. Copia los datos manualmente.",
      sending: "Enviando…",
      sent: "Solicitud recibida. Respondemos en dos días laborables.",
      endpointError: "No se pudo enviar. Escríbenos directamente a ",
      fallback: "Si no se abre tu correo, copia el resumen y envíalo manualmente."
    },
    en: {
      required: "This field is required.",
      email: "Please check the email address.",
      consent: "We need your consent in order to reply.",
      mailtoOpened: "Your mail client has opened with the details filled in.",
      copied: "Summary copied. Paste it into an email to ",
      copyFailed: "Could not copy. Please copy the details manually.",
      sending: "Sending…",
      sent: "Request received. We reply within two working days.",
      endpointError: "Sending failed. Write to us directly at ",
      fallback: "If your mail client does not open, copy the summary and send it manually."
    }
  };

  function lang() {
    var value = document.documentElement.getAttribute("data-lang");
    return value === "en" ? "en" : "es";
  }

  function t(key) {
    return (MESSAGES[lang()] || MESSAGES.es)[key];
  }

  /* ---------- Language ---------- */

  function setupLanguage() {
    var storageKey = "integrity.lang";
    var alt = document.documentElement.getAttribute("data-lang-alt");

    // Remember the choice only when the visitor actually clicks the switch.
    document.querySelectorAll("[data-lang-switch]").forEach(function (link) {
      link.addEventListener("click", function () {
        try {
          localStorage.setItem(storageKey, link.getAttribute("data-lang-switch"));
        } catch (error) {
          /* private mode: the switch still works, it just is not remembered */
        }
      });
    });

    // On the home page only, honour a previous explicit choice.
    if (document.documentElement.getAttribute("data-lang-redirect") !== "true" || !alt) {
      return;
    }
    var stored = null;
    try {
      stored = localStorage.getItem(storageKey);
    } catch (error) {
      stored = null;
    }
    if (stored && stored !== lang() && stored === alt.replace(/^\/|\/$/g, "")) {
      window.location.replace(alt);
    }
  }

  /* ---------- Helpers ---------- */

  function labelFor(field) {
    var wrapper = field.closest(".field") || field.closest(".consent");
    var label = wrapper ? wrapper.querySelector("label") : null;
    return label ? label.textContent.replace(/\s+/g, " ").trim() : field.name;
  }

  function setError(field, message) {
    var wrapper = field.closest(".field") || field.closest(".consent");
    var slot = wrapper ? wrapper.querySelector(".field-error") : null;
    if (slot) {
      slot.textContent = message || "";
    }
    if (message) {
      field.setAttribute("aria-invalid", "true");
    } else {
      field.removeAttribute("aria-invalid");
    }
  }

  function validate(form) {
    var firstInvalid = null;
    form.querySelectorAll("input, select, textarea").forEach(function (field) {
      if (field.type === "hidden" || field.disabled) {
        return;
      }
      var value = (field.value || "").trim();
      var error = "";
      if (field.required && field.type === "checkbox" && !field.checked) {
        error = t("consent");
      } else if (field.required && !value) {
        error = t("required");
      } else if (field.type === "email" && value && !/^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(value)) {
        error = t("email");
      }
      setError(field, error);
      if (error && !firstInvalid) {
        firstInvalid = field;
      }
    });
    return firstInvalid;
  }

  function collect(form) {
    var data = {};
    form.querySelectorAll("input, select, textarea").forEach(function (field) {
      if (field.type === "checkbox") {
        data[field.name] = field.checked ? field.value : "";
      } else {
        data[field.name] = (field.value || "").trim();
      }
    });
    data.page = window.location.pathname;
    data.submitted_at = new Date().toISOString();
    return data;
  }

  function summary(data) {
    var lines = [];
    Object.keys(data).forEach(function (key) {
      if (key === "consent" || key.indexOf("page") === 0 || !data[key]) {
        return;
      }
      lines.push(key + ": " + data[key]);
    });
    return lines.join("\n");
  }

  function subject(data) {
    var who = data.organizacion || data.nombre || "consulta";
    return lang() === "en"
      ? "Integrity enquiry — " + who
      : "Consulta Integrity — " + who;
  }

  function saveLocally(data) {
    try {
      var key = "integrity.leads";
      var stored = JSON.parse(localStorage.getItem(key) || "[]");
      stored.push(data);
      localStorage.setItem(key, JSON.stringify(stored.slice(-25)));
    } catch (error) {
      /* nothing essential depends on this */
    }
  }

  function copyText(text, status) {
    function done() {
      status.className = "form-status ok";
      status.textContent = t("copied") + CONTACT_EMAIL;
    }
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(text).then(done, function () {
        status.className = "form-status error";
        status.textContent = t("copyFailed");
      });
      return;
    }
    var helper = document.createElement("textarea");
    helper.value = text;
    helper.setAttribute("readonly", "readonly");
    helper.style.position = "absolute";
    helper.style.left = "-9999px";
    document.body.appendChild(helper);
    helper.select();
    try {
      document.execCommand("copy");
      done();
    } catch (error) {
      status.className = "form-status error";
      status.textContent = t("copyFailed");
    }
    document.body.removeChild(helper);
  }

  function setupForm() {
    var form = document.querySelector("[data-contact-form]");
    if (!form) {
      return;
    }
    var status = form.querySelector("[data-form-status]");
    var copyButton = form.querySelector("[data-copy-summary]");
    var submit = form.querySelector("[type=submit]");
    var lastData = null;

    // The two entry routes pre-select the matching profile.
    document.querySelectorAll("[data-fill-perfil]").forEach(function (link) {
      link.addEventListener("click", function () {
        var select = form.querySelector("[name=perfil]");
        if (select) {
          select.value = link.getAttribute("data-fill-perfil");
        }
      });
    });

    if (copyButton) {
      copyButton.addEventListener("click", function () {
        if (lastData) {
          copyText(summary(lastData), status);
        }
      });
    }

    form.addEventListener("submit", function (event) {
      event.preventDefault();
      var invalid = validate(form);
      if (invalid) {
        status.className = "form-status error";
        status.textContent = t("required");
        invalid.focus();
        return;
      }

      var data = collect(form);
      lastData = data;
      saveLocally(data);

      if (!FORM_ENDPOINT) {
        var url =
          "mailto:" +
          CONTACT_EMAIL +
          "?subject=" +
          encodeURIComponent(subject(data)) +
          "&body=" +
          encodeURIComponent(summary(data) + "\n");
        status.className = "form-status ok";
        status.textContent = t("mailtoOpened") + " " + t("fallback");
        // Webmail users have no mail handler: offer the copy path as a real fallback.
        if (copyButton) {
          copyButton.hidden = false;
        }
        window.location.href = url;
        return;
      }

      if (submit) {
        submit.setAttribute("aria-disabled", "true");
      }
      status.className = "form-status";
      status.textContent = t("sending");

      fetch(FORM_ENDPOINT, {
        method: "POST",
        headers: { "Content-Type": "application/json", Accept: "application/json" },
        body: JSON.stringify(data)
      })
        .then(function (response) {
          if (!response.ok) {
            throw new Error("endpoint returned " + response.status);
          }
          form.reset();
          status.className = "form-status ok";
          status.textContent = t("sent");
        })
        .catch(function () {
          status.className = "form-status error";
          status.textContent = t("endpointError") + CONTACT_EMAIL;
        })
        .finally(function () {
          if (submit) {
            submit.removeAttribute("aria-disabled");
          }
        });
    });
  }

  /* ---------- Small enhancements ---------- */

  function setupMisc() {
    document.querySelectorAll("[data-year]").forEach(function (node) {
      node.textContent = String(new Date().getFullYear());
    });

    document.querySelectorAll("[data-copy]").forEach(function (button) {
      button.addEventListener("click", function () {
        var value = button.getAttribute("data-copy");
        var original = button.textContent;
        if (navigator.clipboard && navigator.clipboard.writeText) {
          navigator.clipboard.writeText(value).then(function () {
            button.textContent = "✓";
            window.setTimeout(function () {
              button.textContent = original;
            }, 1600);
          });
        }
      });
    });
  }

  document.addEventListener("DOMContentLoaded", function () {
    setupLanguage();
    setupForm();
    setupMisc();
  });
})();
