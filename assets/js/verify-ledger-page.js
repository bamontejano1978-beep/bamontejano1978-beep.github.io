/* Integrity — page logic for the offline ledger verifier (/verifica-el-ledger/).
 *
 * It wires the drop zone and the two demo buttons to LedgerVerifier, and renders
 * the report in the visitor's language. All verification happens through
 * LedgerVerifier: this file never computes a hash on its own, so the page cannot
 * claim more than the verifier checked. */

(function () {
  "use strict";

  var STRINGS = {
    es: {
      reading: "Leyendo el archivo…",
      verifying: "Recalculando la cadena con SHA-256 en tu dispositivo…",
      valid: "VERIFICADO",
      invalid: "NO VERIFICADO",
      validNote:
        "Los 4 hashes, los 4 payloads y el enlace de la cadena coinciden con lo que el ledger dice haber escrito. Nadie ha tocado estos bytes desde que se registraron.",
      invalidNote:
        "Esta copia no cuadra con sus propios hashes. La verificación ha fallado y abajo está el punto exacto en el que falla.",
      tamperedNote:
        "Esta es una copia alterada a propósito en esta misma página: le hemos cambiado un byte del payload y no hemos recalculado ningún hash. Así se ve un bundle editado después de escribirlo.",
      noDemo:
        "No se ha podido cargar el ledger de demostración. Recarga la página y vuelve a intentarlo.",
      noVerifier:
        "No se ha podido cargar el verificador. Recarga la página y vuelve a intentarlo.",
      shaNative: "SHA-256 de tu navegador",
      shaPureJs: "SHA-256 incluido en esta página",
      pureJsNote:
        "Tu navegador no ofrece WebCrypto en este contexto (pasa en http sin certificado, por ejemplo en una red local). La página ha usado la implementación SHA-256 que viaja con ella: mismo algoritmo, mismos resultados, y sigue sin enviar nada a ningún sitio.",
      badFile: "Ese archivo no es un bundle JSON legible: ",
      eventsSuffix: "evento(s)",
      problemsSuffix: "problema(s)",
      checks: "Comprobaciones recalculadas aquí",
      events: "Eventos del ledger",
      event: "Evento",
      subject: "Sujeto",
      when: "Registrado",
      payload: "payload (tal como está guardado)",
      copyHead: "Copiar el head hash",
      copied: "Copiado",
      download: "Descargar el informe",
      reset: "Vaciar",
      operatorSays: "Lo que declaró el operador",
      technical: "Detalle técnico (en inglés, tal cual lo produce el verificador)",
      statuses: { pass: "correcto", fail: "falla", skip: "no comprobable aquí" },
      checksById: {
        bundle_version: "Versión del bundle admitida por este verificador",
        event_count: "El bundle declara el número de eventos que trae",
        sequence: "Los eventos están numerados 1..N seguidos",
        chain: "Cada previous_hash continúa el hash anterior; el primero arranca en el hash génesis",
        payload_hashes: "Cada payload_json produce el payload_sha256 guardado",
        event_hashes: "Cada event_hash es el SHA-256 de sus siete campos canónicos",
        event_ids: "Cada event_id deriva de su event_hash",
        payloads_parse: "Cada payload_json es JSON válido",
        canonical_rebuild: "Cada evento se ha podido reconstruir aquí desde sus campos en crudo",
        head_hash: "El hash head recomputado es el que el bundle declara",
        operator_claim: "El hash y el recuento que declaró el operador coinciden con los recomputados"
      },
      eventTypes: {
        incident_detected: "incidente detectado",
        change_card_generated: "tarjeta de cambio generada",
        sandbox_evaluated: "sandbox evaluado",
        release_review_signed: "revisión de release firmada"
      },
      zeroEvents: "El bundle no contiene eventos."
    },
    en: {
      reading: "Reading the file…",
      verifying: "Recomputing the SHA-256 chain on your device…",
      valid: "VERIFIED",
      invalid: "NOT VERIFIED",
      validNote:
        "Every hash, every payload and every chain link matches what the ledger says it stored. Nobody has touched these bytes since they were recorded.",
      invalidNote:
        "This copy does not match its own hashes. Verification failed, and the exact point where it fails is below.",
      tamperedNote:
        "This is a copy altered on purpose by this page: one byte of the payload changed and no hash was recomputed. This is what an edited bundle looks like.",
      noDemo: "The demo ledger could not be loaded. Reload the page and try again.",
      noVerifier: "The verifier could not be loaded. Reload the page and try again.",
      shaNative: "your browser's SHA-256",
      shaPureJs: "the SHA-256 included in this page",
      pureJsNote:
        "Your browser offers no WebCrypto in this context (that happens over plain HTTP without a certificate, for instance on a local network). The page used the SHA-256 implementation it carries: same algorithm, same results, and it still sends nothing anywhere.",
      badFile: "That file is not a readable JSON bundle: ",
      eventsSuffix: "event(s)",
      problemsSuffix: "problem(s)",
      checks: "Checks recomputed here",
      events: "Ledger events",
      event: "Event",
      subject: "Subject",
      when: "Recorded",
      payload: "payload (exactly as stored)",
      copyHead: "Copy the head hash",
      copied: "Copied",
      download: "Download the report",
      reset: "Clear",
      operatorSays: "What the operator declared",
      technical: "Technical detail, as the verifier produced it",
      statuses: { pass: "ok", fail: "failed", skip: "not checkable here" },
      checksById: {
        bundle_version: "Bundle version this verifier supports",
        event_count: "The bundle declares the number of events it carries",
        sequence: "Events are numbered 1..N without gaps",
        chain: "Every previous_hash continues the hash before it; the first starts at the genesis hash",
        payload_hashes: "Every payload_json produces the stored payload_sha256",
        event_hashes: "Every event_hash is the SHA-256 of its seven canonical fields",
        event_ids: "Every event_id derives from its event_hash",
        payloads_parse: "Every payload_json is valid JSON",
        canonical_rebuild: "Every event was rebuilt here from its raw fields",
        head_hash: "The recomputed head hash is the one the bundle declares",
        operator_claim: "The hash and count the operator declared match the recomputed ones"
      },
      eventTypes: {
        incident_detected: "incident detected",
        change_card_generated: "change card generated",
        sandbox_evaluated: "sandbox evaluated",
        release_review_signed: "release review signed"
      },
      zeroEvents: "The bundle carries no events."
    }
  };

  function lang() {
    return document.documentElement.getAttribute("data-lang") === "en" ? "en" : "es";
  }

  function strings() {
    return STRINGS[lang()] || STRINGS.es;
  }

  function shortHash(value) {
    if (typeof value !== "string") {
      return "";
    }
    return value.slice(0, 12) + "…" + value.slice(-6);
  }

  function element(tag, className, text) {
    var node = document.createElement(tag);
    if (className) {
      node.className = className;
    }
    if (text !== undefined) {
      node.textContent = text;
    }
    return node;
  }

  function clear(node) {
    while (node.firstChild) {
      node.removeChild(node.firstChild);
    }
  }

  function formatStamp(value) {
    if (typeof value !== "string") {
      return "";
    }
    var parsed = new Date(value);
    if (isNaN(parsed.getTime())) {
      return value;
    }
    return parsed.toISOString().replace("T", " ").replace(".000Z", "Z").slice(0, 19) + " UTC";
  }

  function setup() {
    var root = document.querySelector("[data-verifier]");
    if (!root) {
      return;
    }
    var status = root.querySelector("[data-verifier-status]");
    var reportPanel = root.querySelector("[data-verifier-report]");
    var verdictNode = root.querySelector("[data-verdict]");
    var noteNode = root.querySelector("[data-verdict-note]");
    var checksNode = root.querySelector("[data-checks]");
    var eventsBody = root.querySelector("[data-events-body]");
    var headNode = root.querySelector("[data-head]");
    var operatorNode = root.querySelector("[data-operator]");
    var problemsNode = root.querySelector("[data-problems]");
    var downloadButton = root.querySelector("[data-download-report]");
    var copyHeadButton = root.querySelector("[data-copy-head]");
    var resetButton = root.querySelector("[data-reset-verifier]");
    var demoButton = root.querySelector("[data-verify-demo]");
    var tamperButton = root.querySelector("[data-verify-tampered]");
    var dropzone = root.querySelector("[data-dropzone]");
    var input = root.querySelector("[data-file-input]");
    var lastReport = null;
    var lastBundle = null;

    function setStatus(text, kind) {
      status.textContent = text;
      status.className = "verifier-status" + (kind ? " " + kind : "");
    }

    function setVerdict(report, note) {
      if (!reportPanel || !verdictNode || !noteNode) {
        return;
      }
      reportPanel.hidden = report.event_count === 0 && report.valid === false && report.checks.length <= 1;
      verdictNode.textContent = report.valid ? strings().valid : strings().invalid;
      verdictNode.className = "verdict " + (report.valid ? "ok" : "bad");
      noteNode.textContent = note || (report.valid ? strings().validNote : strings().invalidNote);
    }

    function renderChecks(report) {
      if (!checksNode) {
        return;
      }
      clear(checksNode);
      report.checks.forEach(function (check) {
        var item = element("li", "check-item " + check.status);
        var label = element("span", "check-label");
        var title = strings().checksById[check.id] || check.id;
        label.appendChild(element("strong", null, title));
        label.appendChild(
          element(
            "span",
            "check-status",
            strings().statuses[check.status] || check.status
          )
        );
        item.appendChild(label);
        item.appendChild(element("span", "check-detail", check.detail || ""));
        checksNode.appendChild(item);
      });
    }

    function renderEvents(report) {
      if (!eventsBody) {
        return;
      }
      clear(eventsBody);
      report.events.forEach(function (event) {
        var row = element("tr");
        row.appendChild(element("td", "num", String(event.sequence)));
        var typeCell = element("td");
        typeCell.appendChild(
          element(
            "strong",
            null,
            strings().eventTypes[event.event_type] || event.event_type
          )
        );
        typeCell.appendChild(element("div", "mono small", event.event_type));
        row.appendChild(typeCell);
        var subjectCell = element("td");
        subjectCell.appendChild(element("div", "mono small", event.subject_id));
        subjectCell.appendChild(element("div", "muted small", formatStamp(event.recorded_at)));
        row.appendChild(subjectCell);
        var verdictCell = element("td", "check-cell");
        verdictCell.textContent =
          event.payload_ok && event.event_hash_ok && event.event_id_ok && event.previous_ok
            ? "✓"
            : "✕";
        verdictCell.className =
          "check-cell " + (verdictCell.textContent === "✓" ? "ok" : "bad");
        row.appendChild(verdictCell);

        var detailRow = element("tr", "event-detail");
        var detailCell = element("td");
        detailCell.colSpan = 4;
        var details = element("details");
        details.appendChild(element("summary", null, strings().payload));
        var pre = element("pre", "mono payload");
        var pretty = event.payload_json;
        try {
          pretty = JSON.stringify(JSON.parse(event.payload_json), null, 2);
        } catch (error) {
          /* keep the raw bytes: the hash was computed over them anyway */
        }
        pre.textContent = pretty;
        details.appendChild(pre);
        var hashes = element("dl", "hash-list");
        [
          ["payload_sha256", event.payload_sha256],
          ["event_hash", event.event_hash],
          ["recomputed_event_hash", event.recomputed_event_hash],
          ["previous_hash", event.previous_hash],
          ["event_id", event.event_id]
        ].forEach(function (pair) {
          hashes.appendChild(element("dt", null, pair[0]));
          hashes.appendChild(element("dd", "mono", String(pair[1])));
        });
        details.appendChild(hashes);
        detailCell.appendChild(details);
        detailRow.appendChild(detailCell);
        eventsBody.appendChild(row);
        eventsBody.appendChild(detailRow);
      });
    }

    function renderOperator(report) {
      if (!operatorNode) {
        return;
      }
      var claimed = report.operator_verification;
      if (!claimed) {
        operatorNode.hidden = true;
        return;
      }
      operatorNode.hidden = false;
      clear(operatorNode);
      operatorNode.appendChild(element("strong", null, strings().operatorSays + ": "));
      operatorNode.appendChild(
        element(
          "span",
          null,
          (claimed.valid ? strings().valid : strings().invalid) +
            " · " +
            claimed.event_count +
            " · " +
            (claimed.signatures_valid ? "Ed25519 ✓" : "Ed25519 ✕") +
            " · " +
            (claimed.active_staged_review_ids || []).join(", ")
        )
      );
    }

    function renderProblems(report) {
      if (!problemsNode) {
        return;
      }
      clear(problemsNode);
      if (report.problems.length === 0) {
        problemsNode.hidden = true;
        return;
      }
      problemsNode.hidden = false;
      var details = element("details");
      details.appendChild(
        element("summary", null, strings().technical + " (" + report.problems.length + ")")
      );
      var list = element("ul");
      report.problems.forEach(function (problem) {
        list.appendChild(element("li", "mono small", problem));
      });
      details.appendChild(list);
      problemsNode.appendChild(details);
    }

    function render(report, note) {
      lastReport = report;
      if (headNode) {
        headNode.textContent = report.head_hash || "";
      }
      if (copyHeadButton) {
        // site.js copies whatever data-copy holds at click time, so the value
        // can be set after the report exists.
        copyHeadButton.setAttribute("data-copy", report.head_hash || "");
        copyHeadButton.hidden = false;
      }
      setVerdict(report, note);
      renderChecks(report);
      renderEvents(report);
      renderOperator(report);
      renderProblems(report);
      if (downloadButton) {
        downloadButton.hidden = false;
      }
      if (resetButton) {
        resetButton.hidden = false;
      }
      var mode =
        report.sha256_mode === "pure-js" ? strings().shaPureJs : strings().shaNative;
      setStatus(
        (report.valid
          ? strings().valid +
            " · " +
            report.event_count +
            " " +
            strings().eventsSuffix
          : strings().invalid +
            " · " +
            report.problems.length +
            " " +
            strings().problemsSuffix) +
          " · " +
          mode,
        report.valid ? "ok" : "bad"
      );
      if (report.sha256_mode === "pure-js" && noteNode) {
        noteNode.textContent = (noteNode.textContent || "") + " " + strings().pureJsNote;
      }
    }

    function verify(bundle, note) {
      lastBundle = bundle;
      setStatus(strings().verifying);
      return window.LedgerVerifier.verifyBundle(bundle).then(function (report) {
        render(report, note);
        return report;
      });
    }

    function readFile(file) {
      if (!file) {
        return;
      }
      setStatus(strings().reading + " " + file.name);
      file
        .text()
        .then(function (text) {
          var bundle;
          try {
            bundle = JSON.parse(text);
          } catch (error) {
            setStatus(strings().badFile + error.message, "bad");
            return;
          }
          verify(bundle, null);
        })
        .catch(function (error) {
          setStatus(strings().badFile + error.message, "bad");
        });
    }

    function download() {
      if (!lastReport) {
        return;
      }
      var payload = {
        kind: "ledger_verification_report",
        report_version: "0.1",
        verified_in: "browser",
        generated_at: new Date().toISOString(),
        page: window.location.href,
        verifier: "web/assets/js/ledger-verifier.js",
        bundle: {
          bundle_version: lastBundle ? lastBundle.bundle_version : null,
          exported_at: lastReport.exported_at,
          generator: lastReport.generator,
          source: lastReport.source
        },
        result: lastReport
      };
      var blob = new Blob([JSON.stringify(payload, null, 2)], {
        type: "application/json"
      });
      var link = document.createElement("a");
      link.href = URL.createObjectURL(blob);
      link.download =
        (lang() === "en" ? "ledger-verification-" : "verificacion-ledger-") +
        (lastReport.head_hash || "report").slice(0, 12) +
        ".json";
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);
      URL.revokeObjectURL(link.href);
    }

    if (!window.LedgerVerifier) {
      setStatus(strings().noVerifier, "bad");
      if (demoButton) {
        demoButton.disabled = true;
      }
      if (tamperButton) {
        tamperButton.disabled = true;
      }
      if (dropzone) {
        dropzone.hidden = true;
      }
      return;
    }

    if (demoButton) {
      if (!window.INTEGRITY_DEMO_BUNDLE) {
        demoButton.disabled = true;
        setStatus(strings().noDemo, "bad");
      } else {
        demoButton.addEventListener("click", function () {
          verify(window.INTEGRITY_DEMO_BUNDLE, null);
        });
      }
    }

    if (tamperButton) {
      tamperButton.addEventListener("click", function () {
        if (!window.INTEGRITY_DEMO_BUNDLE) {
          return;
        }
        var modified = window.LedgerVerifier.tamperedCopy(window.INTEGRITY_DEMO_BUNDLE);
        var bundle = modified.bundle;
        verify(
          bundle,
          strings().tamperedNote +
            " (" +
            (lang() === "en" ? "event" : "evento") +
            " #" +
            modified.sequence +
            ")"
        );
      });
    }

    if (input) {
      input.addEventListener("change", function () {
        readFile(input.files && input.files[0]);
      });
    }

    if (dropzone) {
      ["dragenter", "dragover"].forEach(function (name) {
        dropzone.addEventListener(name, function (event) {
          event.preventDefault();
          dropzone.classList.add("dragging");
        });
      });
      ["dragleave", "drop"].forEach(function (name) {
        dropzone.addEventListener(name, function (event) {
          event.preventDefault();
          dropzone.classList.remove("dragging");
        });
      });
      dropzone.addEventListener("drop", function (event) {
        var files = event.dataTransfer && event.dataTransfer.files;
        if (files && files.length > 0) {
          readFile(files[0]);
        }
      });
    }

    if (downloadButton) {
      downloadButton.addEventListener("click", download);
    }

    if (resetButton) {
      resetButton.addEventListener("click", function () {
        lastReport = null;
        lastBundle = null;
        if (reportPanel) {
          reportPanel.hidden = true;
        }
        if (downloadButton) {
          downloadButton.hidden = true;
        }
        if (copyHeadButton) {
          copyHeadButton.hidden = true;
          copyHeadButton.removeAttribute("data-copy");
        }
        resetButton.hidden = true;
        if (input) {
          input.value = "";
        }
        setStatus("");
      });
    }
  }

  document.addEventListener("DOMContentLoaded", setup);
})();
