/* Integrity — portable audit-ledger verifier.
 *
 * Recomputes, in the visitor's own device, the SHA-256 hash chain of a bundle
 * exported by `python -m autopilot audit-export`. It mirrors the algorithm in
 * src/autopilot/audit.py: every event hash is the SHA-256 of the canonical JSON
 * of its seven fields, and every payload is hashed exactly as it was stored, so
 * this file never re-serialises a payload (Python and JavaScript disagree on how
 * to print some numbers, and a verifier that reformats the evidence is not a
 * verifier).
 *
 * What it proves: the bytes you have are internally consistent and untouched
 * since they were written into the ledger.
 * What it does not prove: who signed them. Signatures (Ed25519) are verified by
 * the CLI (`audit-verify`, `verify-review`), because this verifier deliberately
 * depends on nothing but SHA-256.
 *
 * Works in the browser (window.LedgerVerifier) and in Node
 * (require('.../ledger-verifier.js')).
 */

(function (root, factory) {
  "use strict";
  var api = factory();
  if (typeof module === "object" && module.exports) {
    module.exports = api;
  }
  if (root && typeof root === "object") {
    root.LedgerVerifier = api;
  }
})(typeof globalThis === "object" ? globalThis : this, function () {
  "use strict";

  var GENESIS_HASH =
    "0000000000000000000000000000000000000000000000000000000000000000";
  var BUNDLE_KIND = "audit_ledger_bundle";
  var SUPPORTED_BUNDLE_VERSIONS = ["0.1"];
  var EVENT_HASH_FIELDS = [
    "sequence",
    "event_type",
    "subject_id",
    "occurred_at",
    "recorded_at",
    "payload_sha256",
    "previous_hash"
  ];

  function nativeSha256Available() {
    return (
      typeof crypto === "object" &&
      crypto !== null &&
      typeof crypto.subtle === "object" &&
      crypto.subtle !== null &&
      typeof TextEncoder === "function"
    );
  }

  function utf8Bytes(text) {
    if (nativeSha256Available()) {
      return new TextEncoder().encode(text);
    }
    var bytes = [];
    for (var i = 0; i < text.length; i += 1) {
      var code = text.charCodeAt(i);
      if (code >= 0xd800 && code <= 0xdbff && i + 1 < text.length) {
        var next = text.charCodeAt(i + 1);
        if (next >= 0xdc00 && next <= 0xdfff) {
          code = (code - 0xd800) * 0x400 + (next - 0xdc00) + 0x10000;
          i += 1;
        }
      }
      if (code < 0x80) {
        bytes.push(code);
      } else if (code < 0x800) {
        bytes.push(0xc0 | (code >> 6), 0x80 | (code & 0x3f));
      } else if (code < 0x10000) {
        bytes.push(
          0xe0 | (code >> 12),
          0x80 | ((code >> 6) & 0x3f),
          0x80 | (code & 0x3f)
        );
      } else {
        bytes.push(
          0xf0 | (code >> 18),
          0x80 | ((code >> 12) & 0x3f),
          0x80 | ((code >> 6) & 0x3f),
          0x80 | (code & 0x3f)
        );
      }
    }
    return new Uint8Array(bytes);
  }

  function toHex(buffer) {
    var view = new Uint8Array(buffer);
    var out = "";
    for (var i = 0; i < view.length; i += 1) {
      out += view[i].toString(16).padStart(2, "0");
    }
    return out;
  }

  var SHA256_ROUND = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
  ];

  function rotr(word, bits) {
    return ((word >>> bits) | (word << (32 - bits))) >>> 0;
  }

  /* A self-contained SHA-256. The verifier is meant to run on a laptop at a
   * trade fair, over the local network, with no certificate and no internet:
   * that context has no WebCrypto, and this page must not depend on one. */
  function sha256HexPureJs(text) {
    var bytes = utf8Bytes(text);
    var length = bytes.length;
    var blockCount = ((length + 9 + 63) >> 6) << 6;
    var padded = new Uint8Array(blockCount);
    padded.set(bytes);
    padded[length] = 0x80;
    var bits = length * 8;
    var high = Math.floor(bits / 4294967296);
    var low = bits >>> 0;
    padded[blockCount - 8] = (high >>> 24) & 0xff;
    padded[blockCount - 7] = (high >>> 16) & 0xff;
    padded[blockCount - 6] = (high >>> 8) & 0xff;
    padded[blockCount - 5] = high & 0xff;
    padded[blockCount - 4] = (low >>> 24) & 0xff;
    padded[blockCount - 3] = (low >>> 16) & 0xff;
    padded[blockCount - 2] = (low >>> 8) & 0xff;
    padded[blockCount - 1] = low & 0xff;

    var hash = [
      0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    ];
    var schedule = new Uint32Array(64);

    for (var block = 0; block < blockCount; block += 64) {
      var t;
      for (t = 0; t < 16; t += 1) {
        schedule[t] =
          (padded[block + t * 4] << 24) |
          (padded[block + t * 4 + 1] << 16) |
          (padded[block + t * 4 + 2] << 8) |
          padded[block + t * 4 + 3];
      }
      for (t = 16; t < 64; t += 1) {
        var sigma0 = rotr(schedule[t - 15], 7) ^ rotr(schedule[t - 15], 18) ^ (schedule[t - 15] >>> 3);
        var sigma1 = rotr(schedule[t - 2], 17) ^ rotr(schedule[t - 2], 19) ^ (schedule[t - 2] >>> 10);
        schedule[t] =
          (schedule[t - 16] + sigma0 + schedule[t - 7] + sigma1) >>> 0;
      }

      var a = hash[0];
      var b = hash[1];
      var c = hash[2];
      var d = hash[3];
      var e = hash[4];
      var f = hash[5];
      var g = hash[6];
      var h = hash[7];

      for (t = 0; t < 64; t += 1) {
        var choice = (e & f) ^ (~e & g);
        var sum1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
        var temp1 = (h + sum1 + choice + SHA256_ROUND[t] + schedule[t]) >>> 0;
        var majority = (a & b) ^ (a & c) ^ (b & c);
        var sum0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
        var temp2 = (sum0 + majority) >>> 0;
        h = g;
        g = f;
        f = e;
        e = (d + temp1) >>> 0;
        d = c;
        c = b;
        b = a;
        a = (temp1 + temp2) >>> 0;
      }

      hash[0] = (hash[0] + a) >>> 0;
      hash[1] = (hash[1] + b) >>> 0;
      hash[2] = (hash[2] + c) >>> 0;
      hash[3] = (hash[3] + d) >>> 0;
      hash[4] = (hash[4] + e) >>> 0;
      hash[5] = (hash[5] + f) >>> 0;
      hash[6] = (hash[6] + g) >>> 0;
      hash[7] = (hash[7] + h) >>> 0;
    }

    var out = "";
    for (var index = 0; index < 8; index += 1) {
      out += (hash[index] >>> 0).toString(16).padStart(8, "0");
    }
    return out;
  }

  /* options.pureJs forces the included implementation, so a test can prove both
   * paths agree on the same bundle instead of trusting the one the browser
   * happened to choose. */
  function sha256(text, options) {
    if (nativeSha256Available() && !(options && options.pureJs)) {
      return crypto.subtle.digest("SHA-256", utf8Bytes(text)).then(toHex);
    }
    return Promise.resolve(sha256HexPureJs(text));
  }

  function sha256Mode(options) {
    return nativeSha256Available() && !(options && options.pureJs) ? "native" : "pure-js";
  }

  /* Python's json.dumps(value, sort_keys=True, separators=(",", ":"),
   * ensure_ascii=True). Returns null when this page cannot reproduce the value
   * byte for byte — a non-integer number, or a non-ASCII character — so callers
   * can report "not checkable here" instead of a false mismatch. */
  function pythonCanonicalJson(value) {
    if (value === null) {
      return "null";
    }
    if (value === true) {
      return "true";
    }
    if (value === false) {
      return "false";
    }
    if (typeof value === "number") {
      if (!Number.isFinite(value) || !Number.isInteger(value)) {
        return null;
      }
      return String(value);
    }
    if (typeof value === "string") {
      for (var i = 0; i < value.length; i += 1) {
        if (value.charCodeAt(i) > 0x7e) {
          return null;
        }
      }
      return JSON.stringify(value);
    }
    if (Array.isArray(value)) {
      var items = [];
      for (var j = 0; j < value.length; j += 1) {
        var item = pythonCanonicalJson(value[j]);
        if (item === null) {
          return null;
        }
        items.push(item);
      }
      return "[" + items.join(",") + "]";
    }
    if (typeof value === "object") {
      var keys = Object.keys(value)
        .filter(function (key) {
          return Object.prototype.hasOwnProperty.call(value, key);
        })
        .sort();
      var parts = [];
      for (var k = 0; k < keys.length; k += 1) {
        var serialized = pythonCanonicalJson(value[keys[k]]);
        if (serialized === null) {
          return null;
        }
        parts.push(JSON.stringify(keys[k]) + ":" + serialized);
      }
      return "{" + parts.join(",") + "}";
    }
    return null;
  }

  function result(id, status, detail) {
    return { id: id, status: status, detail: detail };
  }

  function eventHashInput(event) {
    var payload = {};
    for (var i = 0; i < EVENT_HASH_FIELDS.length; i += 1) {
      payload[EVENT_HASH_FIELDS[i]] = event[EVENT_HASH_FIELDS[i]];
    }
    return payload;
  }

  function isPlainObject(value) {
    return value !== null && typeof value === "object" && !Array.isArray(value);
  }

  function malformedReport(problems, mode) {
    var checks = [
      result("bundle_shape", "fail", problems[0] || "unreadable bundle")
    ];
    return {
      valid: false,
      sha256_mode: mode || null,
      event_count: 0,
      head_hash: null,
      declared_head_hash: null,
      declared_event_count: null,
      exported_at: null,
      generator: null,
      source: null,
      operator_verification: null,
      checks: checks,
      events: [],
      problems: problems
    };
  }

  /* Verify an already parsed bundle object. Resolves with a report; never
   * rejects: an unverifiable bundle is a result, not an exception. */
  async function verifyBundle(bundle, options) {
    var problems = [];
    var mode = sha256Mode(options);
    if (!isPlainObject(bundle)) {
      return malformedReport(["the bundle is not a JSON object"], mode);
    }
    if (bundle.kind !== BUNDLE_KIND) {
      return malformedReport(
        [
          "kind is " +
            JSON.stringify(bundle.kind) +
            ", expected " +
            JSON.stringify(BUNDLE_KIND)
        ],
        mode
      );
    }
    var ledger = bundle.ledger;
    if (!isPlainObject(ledger) || !Array.isArray(ledger.events)) {
      return malformedReport(["the bundle carries no ledger.events array"], mode);
    }

    var events = ledger.events;
    var checks = [];
    var declaredHead = typeof ledger.head_hash === "string" ? ledger.head_hash : null;
    var declaredCount =
      typeof ledger.event_count === "number" ? ledger.event_count : null;

    checks.push(
      result(
        "bundle_version",
        SUPPORTED_BUNDLE_VERSIONS.indexOf(bundle.bundle_version) === -1 ? "fail" : "pass",
        "bundle_version " + JSON.stringify(bundle.bundle_version)
      )
    );

    checks.push(
      result(
        "event_count",
        declaredCount === events.length ? "pass" : "fail",
        "declared " + declaredCount + ", present " + events.length
      )
    );

    var sequenceOk = true;
    var linkageOk = true;
    var payloadOk = true;
    var hashOk = true;
    var idOk = true;
    var parseOk = true;
    var previous = GENESIS_HASH;
    var described = [];
    var notCheckable = [];

    for (var index = 0; index < events.length; index += 1) {
      var event = isPlainObject(events[index]) ? events[index] : {};
      var position = index + 1;
      var payloadJson = typeof event.payload_json === "string" ? event.payload_json : null;
      var payloadDigest = payloadJson === null ? null : await sha256(payloadJson, options);
      var canonical = pythonCanonicalJson(eventHashInput(event));
      var eventDigest = canonical === null ? null : await sha256(canonical, options);

      if (event.sequence !== position) {
        sequenceOk = false;
        problems.push("event " + position + ": sequence is " + event.sequence);
      }
      if (event.previous_hash !== previous) {
        linkageOk = false;
        problems.push(
          "event " +
            position +
            ": previous_hash " +
            String(event.previous_hash) +
            " does not continue the chain"
        );
      }
      if (payloadDigest === null || event.payload_sha256 !== payloadDigest) {
        payloadOk = false;
        problems.push("event " + position + ": payload_sha256 does not match payload_json");
      }
      if (canonical === null) {
        notCheckable.push(position);
      } else if (event.event_hash !== eventDigest) {
        hashOk = false;
        problems.push("event " + position + ": event_hash does not match the recomputed hash");
      }
      if (
        eventDigest !== null &&
        event.event_id !== "AUD-" + eventDigest.slice(0, 24).toUpperCase()
      ) {
        idOk = false;
        problems.push("event " + position + ": event_id does not derive from the event hash");
      }
      if (payloadJson !== null) {
        try {
          JSON.parse(payloadJson);
        } catch (error) {
          parseOk = false;
          problems.push("event " + position + ": payload_json is not valid JSON");
        }
      }

      described.push({
        sequence: event.sequence,
        event_id: event.event_id,
        event_type: event.event_type,
        subject_id: event.subject_id,
        occurred_at: event.occurred_at,
        recorded_at: event.recorded_at,
        payload_json: payloadJson,
        payload_sha256: event.payload_sha256,
        previous_hash: event.previous_hash,
        event_hash: event.event_hash,
        recomputed_event_hash: eventDigest,
        payload_ok: payloadDigest !== null && event.payload_sha256 === payloadDigest,
        event_hash_ok: eventDigest !== null && event.event_hash === eventDigest,
        event_id_ok:
          eventDigest !== null &&
          event.event_id === "AUD-" + eventDigest.slice(0, 24).toUpperCase(),
        previous_ok: event.previous_hash === previous
      });
      previous = typeof event.event_hash === "string" ? event.event_hash : previous;
    }

    checks.push(
      result("sequence", sequenceOk ? "pass" : "fail", "events numbered 1.." + events.length)
    );
    checks.push(
      result(
        "chain",
        linkageOk ? "pass" : "fail",
        "every previous_hash continues the one before; the chain starts at the genesis hash"
      )
    );
    checks.push(
      result(
        "payload_hashes",
        payloadOk ? "pass" : "fail",
        "each payload_json hashes to the stored payload_sha256"
      )
    );
    checks.push(
      result(
        "event_hashes",
        hashOk ? "pass" : "fail",
        "each event_hash matches the SHA-256 of its seven canonical fields"
      )
    );
    checks.push(
      result("event_ids", idOk ? "pass" : "fail", "each event_id derives from its event hash")
    );
    checks.push(
      notCheckable.length === 0
        ? result(
            "canonical_rebuild",
            "pass",
            "every event rebuilt here from its raw fields"
          )
        : result(
            "canonical_rebuild",
            "skip",
            "events " +
              notCheckable.join(", ") +
              " carry non-ASCII text or fractional numbers, which this page does not reformat"
          )
    );
    checks.push(
      result("payloads_parse", parseOk ? "pass" : "fail", "every payload_json parses as JSON")
    );
    checks.push(
      result(
        "head_hash",
        declaredHead === previous ? "pass" : "fail",
        "recomputed head " + previous
      )
    );

    var claimed = isPlainObject(bundle.operator_verification) ? bundle.operator_verification : null;
    if (claimed) {
      var matches =
        claimed.head_hash === previous && claimed.event_count === events.length;
      checks.push(
        result(
          "operator_claim",
          matches ? "pass" : "fail",
          "the operator's CLI claimed " +
            claimed.event_count +
            " event(s), head " +
            String(claimed.head_hash) +
            (claimed.valid === true ? ", valid" : ", invalid") +
            ", signatures " +
            (claimed.signatures_valid === true ? "verified" : "not verified")
        )
      );
    } else {
      checks.push(
        result("operator_claim", "skip", "the bundle carries no operator verification block")
      );
    }

    var valid = checks.every(function (item) {
      return item.status !== "fail";
    });

    return {
      valid: valid,
      sha256_mode: sha256Mode(options),
      event_count: events.length,
      head_hash: previous,
      declared_head_hash: declaredHead,
      declared_event_count: declaredCount,
      exported_at: typeof bundle.exported_at === "string" ? bundle.exported_at : null,
      generator: typeof bundle.generator === "string" ? bundle.generator : null,
      source: isPlainObject(bundle.source) ? bundle.source : null,
      operator_verification: claimed,
      checks: checks,
      events: described,
      problems: problems
    };
  }

  /* Demo helper: return a copy with one stored payload edited and every hash
   * left untouched. Used by the page to show, deliberately, what a bundle that
   * was modified after the fact looks like to this same verifier. */
  function tamperedCopy(bundle, options) {
    var copy = JSON.parse(JSON.stringify(bundle));
    var events = copy.ledger.events;
    var index =
      options && typeof options.index === "number" ? options.index : events.length - 1;
    var original = events[index].payload_json;
    var replaced = original.replace('"status":"open"', '"status":"closed"');
    events[index].payload_json = replaced === original ? original + " " : replaced;
    return { bundle: copy, index: index, sequence: events[index].sequence };
  }

  return {
    GENESIS_HASH: GENESIS_HASH,
    BUNDLE_KIND: BUNDLE_KIND,
    SUPPORTED_BUNDLE_VERSIONS: SUPPORTED_BUNDLE_VERSIONS,
    nativeSha256Available: nativeSha256Available,
    sha256Mode: sha256Mode,
    sha256: sha256,
    sha256HexPureJs: sha256HexPureJs,
    utf8Bytes: utf8Bytes,
    pythonCanonicalJson: pythonCanonicalJson,
    verifyBundle: verifyBundle,
    tamperedCopy: tamperedCopy
  };
});
