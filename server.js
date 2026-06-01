"use strict";

/**
 * posthog-tap — a local PostHog ingestion sink + payload inspector.
 *
 * Point `posthog-js` (or any PostHog SDK) at this server instead of the real
 * PostHog cloud, and every event it would send is captured, decoded, and shown
 * in a web UI — without touching a real PostHog project. Built for verifying an
 * analytics integration locally and auditing payloads for accidental PII before
 * anything ships.
 *
 * Zero runtime dependencies (Node built-ins only). Events live in an in-memory
 * ring buffer; restart to clear.
 *
 * Endpoints:
 *   POST /e/ /i/v0/e/ /batch/ /capture/ /track/ /engage/   capture (returns {status:1})
 *   POST /decide/ /flags/                                   SDK config (returns sane defaults)
 *   GET  /                                                  web UI (auto-refreshing)
 *   GET  /events.json                                       captured events as JSON
 *   GET  /healthz                                           liveness probe
 *   POST /reset  (or DELETE /events)                        clear the buffer
 */

const http = require("http");
const zlib = require("zlib");

const PORT = Number(process.env.PORT || 4000);
const MAX_EVENTS = Number(process.env.MAX_EVENTS || 1000);

/** @type {Array<object>} newest last */
const events = [];

// --- PII / leak heuristics ---------------------------------------------------
const EMAIL_RE = /[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}/i;
const SENSITIVE_KEY_RE =
  /(e[-_]?mail|first[-_]?name|last[-_]?name|full[-_]?name|file[-_]?name|filename|comment|free[-_]?text|contract|amount|price|cost|url|address|phone|ssn|password|secret|api[-_]?key|token)/i;
const FREE_TEXT_MAX = 256;
// PostHog attaches its own system metadata to every event ($browser, $os,
// $current_url, $device_id, …) plus standard envelope keys (token, distinct_id,
// api_key). None of that is *your app's* data, so we don't flag it by key name —
// otherwise every event lights up red and real leaks get lost in the noise. We
// still scan their values for emails / long free text, since a leak is a leak
// wherever it lands.
const POSTHOG_STD_KEYS = new Set([
  "token",
  "distinct_id",
  "api_key",
  "timestamp",
  "uuid",
  "type",
  "event",
  "sent_at",
  "library",
  "library_version",
]);

/** Walk a value tree and collect human-readable leak warnings. */
function scan(distinctId, properties) {
  const warnings = [];
  if (distinctId && EMAIL_RE.test(String(distinctId))) {
    warnings.push(`distinct_id looks like an email — should be a stable internal id`);
  }
  const visit = (val, path) => {
    if (val == null) return;
    if (typeof val === "string") {
      if (EMAIL_RE.test(val)) warnings.push(`${path} contains an email address`);
      else if (val.length > FREE_TEXT_MAX)
        warnings.push(`${path} is long free text (${val.length} chars)`);
    } else if (Array.isArray(val)) {
      val.forEach((v, i) => visit(v, `${path}[${i}]`));
    } else if (typeof val === "object") {
      for (const [k, v] of Object.entries(val)) {
        // Flag a sensitive *key name* only for your-app keys — skip PostHog's
        // own $-prefixed metadata and standard envelope keys. Values are still
        // walked below, so an email or free-text leak inside a $-key is caught.
        const isSystemKey = k.startsWith("$") || POSTHOG_STD_KEYS.has(k);
        if (!isSystemKey && SENSITIVE_KEY_RE.test(k) && v != null && v !== "") {
          warnings.push(`property "${path ? path + "." : ""}${k}" matches a sensitive name`);
        }
        visit(v, path ? `${path}.${k}` : k);
      }
    }
  };
  visit(properties, "");
  return [...new Set(warnings)];
}

// --- body decoding -----------------------------------------------------------
function gunzipMaybe(buf, query, headers) {
  const looksGzip = buf.length > 2 && buf[0] === 0x1f && buf[1] === 0x8b;
  const declared =
    /gzip/.test(headers["content-encoding"] || "") ||
    query.compression === "gzip-js" ||
    query.compression === "gzip";
  if (looksGzip || declared) {
    try {
      return zlib.gunzipSync(buf);
    } catch {
      /* fall through with original bytes */
    }
  }
  return buf;
}

/** Decode a PostHog request body into a JS object, tolerant of every encoding. */
function decodeBody(buf, query, headers) {
  if (!buf || !buf.length) return null;
  let text = gunzipMaybe(buf, query, headers).toString("utf8").trim();
  if (!text) return null;

  // Legacy form transport: `data=<base64(json)>` (optionally gzipped base64).
  if (/^data=/.test(text) || (text.includes("data=") && !/^[[{]/.test(text))) {
    try {
      const d = new URLSearchParams(text).get("data");
      if (d) {
        let decoded = Buffer.from(d, "base64");
        if (decoded.length > 2 && decoded[0] === 0x1f && decoded[1] === 0x8b) {
          try {
            decoded = zlib.gunzipSync(decoded);
          } catch {
            /* keep base64 bytes */
          }
        }
        text = decoded.toString("utf8");
      }
    } catch {
      /* keep original text */
    }
  }

  try {
    return JSON.parse(text);
  } catch {
    return { _unparsed: text.slice(0, 1000) };
  }
}

/** Normalize any PostHog payload shape into a flat list of event objects. */
function toEvents(payload) {
  if (!payload) return [];
  if (Array.isArray(payload)) return payload;
  if (Array.isArray(payload.batch)) return payload.batch;
  return [payload];
}

function record(list, meta) {
  for (const e of list) {
    const properties = e.properties || {};
    const distinctId = e.distinct_id || properties.distinct_id || properties.$user_id || null;
    const rec = {
      received_at: new Date().toISOString(),
      endpoint: meta.endpoint,
      event: e.event || "(no event name)",
      distinct_id: distinctId,
      properties,
      set: e.$set || properties.$set || null,
      warnings: scan(distinctId, { ...properties, $set: e.$set }),
      raw: e,
    };
    events.push(rec);
    const flag = rec.warnings.length ? `  ⚠ ${rec.warnings.join("; ")}` : "";
    console.log(`[posthog-tap] ${rec.event}  distinct_id=${rec.distinct_id ?? "-"}${flag}`);
  }
  while (events.length > MAX_EVENTS) events.shift();
}

// --- responses ---------------------------------------------------------------
const CORS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, POST, DELETE, OPTIONS",
  "Access-Control-Allow-Headers": "*",
};

function sendJson(res, status, obj) {
  const body = JSON.stringify(obj);
  res.writeHead(status, { ...CORS, "Content-Type": "application/json" });
  res.end(body);
}

// Minimal but representative /decide|/flags response so the SDK initialises
// cleanly. Everything that could capture extra data is turned off.
const DECIDE = {
  config: { enable_collect_everything: false },
  isAuthenticated: false,
  supportedCompression: ["gzip", "gzip-js"],
  flags: {},
  featureFlags: {},
  featureFlagPayloads: {},
  errorsWhileComputingFlags: false,
  sessionRecording: false,
  captureDeadClicks: false,
  capturePerformance: false,
  autocaptureExceptions: false,
  autocapture_opt_out: true,
  heatmaps: false,
  surveys: false,
  toolbarParams: {},
  siteApps: [],
  quotaLimited: [],
};

// Remote-config response for GET /array/<token>/config. posthog-js fetches
// this during bootstrap and — critically — some versions buffer all captured
// events until it resolves successfully. Returning 404 here makes the SDK hold
// events forever (init + /flags still work, but nothing is ever sent). Serving
// a valid 200 lets capture proceed, exactly as against real PostHog.
const REMOTE_CONFIG = {
  supportedCompression: ["gzip", "gzip-js"],
  hasFeatureFlags: false,
  captureDeadClicks: false,
  capturePerformance: false,
  autocapture_opt_out: true,
  autocaptureExceptions: false,
  sessionRecording: false,
  heatmaps: false,
  surveys: false,
  defaultIdentifiedOnly: true,
  siteApps: [],
  elementsChainAsString: true,
  analytics: { endpoint: "/i/v0/e/" },
};

// --- HTML UI -----------------------------------------------------------------
const UI = `<!doctype html>
<html lang="en"><head><meta charset="utf-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>posthog-tap</title>
<style>
  :root { color-scheme: dark; }
  * { box-sizing: border-box; }
  body { margin: 0; font: 14px/1.5 ui-monospace, SFMono-Regular, Menlo, monospace;
         background: #0f1115; color: #e6e6e6; }
  header { position: sticky; top: 0; background: #151821; border-bottom: 1px solid #2a2f3a;
           padding: 12px 20px; display: flex; align-items: center; gap: 16px; }
  header h1 { font-size: 15px; margin: 0; color: #fff; letter-spacing: .04em; }
  header h1 span { color: #f59e0b; }
  .count { color: #9aa4b2; }
  button { background: #2a2f3a; color: #e6e6e6; border: 1px solid #3a4150; border-radius: 6px;
           padding: 6px 12px; cursor: pointer; font: inherit; }
  button:hover { background: #353c4a; }
  .wrap { padding: 16px 20px; display: flex; flex-direction: column; gap: 10px; }
  .empty { color: #6b7280; padding: 40px; text-align: center; }
  .card { background: #151821; border: 1px solid #2a2f3a; border-radius: 8px; padding: 12px 14px; }
  .card.warn { border-color: #b45309; }
  .row { display: flex; gap: 10px; align-items: baseline; flex-wrap: wrap; }
  .ev { font-weight: 700; color: #fff; }
  .badge { background: #1e3a8a; color: #dbeafe; border-radius: 4px; padding: 1px 7px; font-size: 12px; }
  .badge.id { background: #064e3b; color: #d1fae5; }
  .ts { color: #6b7280; font-size: 12px; margin-left: auto; }
  .warnings { color: #fca5a5; margin: 8px 0 0; font-size: 13px; }
  pre { margin: 8px 0 0; background: #0b0d12; border: 1px solid #20242e; border-radius: 6px;
        padding: 10px; overflow: auto; max-height: 360px; color: #c9d1d9; }
</style></head>
<body>
<header>
  <h1>posthog<span>·</span>tap</h1>
  <span class="count" id="count">0 events</span>
  <button onclick="clearAll()" style="margin-left:auto">Clear</button>
  <label class="count"><input type="checkbox" id="auto" checked /> auto-refresh</label>
</header>
<div class="wrap" id="list"><div class="empty">Waiting for events… point NEXT_PUBLIC_POSTHOG_HOST at this server and use the app.</div></div>
<script>
  async function load() {
    const r = await fetch('/events.json'); const { events } = await r.json();
    document.getElementById('count').textContent = events.length + ' event' + (events.length === 1 ? '' : 's');
    const list = document.getElementById('list');
    if (!events.length) { list.innerHTML = '<div class="empty">Waiting for events…</div>'; return; }
    list.innerHTML = events.slice().reverse().map(function (e) {
      var warn = (e.warnings && e.warnings.length)
        ? '<div class="warnings">⚠ ' + e.warnings.map(esc).join('<br>⚠ ') + '</div>' : '';
      return '<div class="card' + (e.warnings && e.warnings.length ? ' warn' : '') + '">' +
        '<div class="row"><span class="ev">' + esc(e.event) + '</span>' +
        '<span class="badge id">' + esc(e.distinct_id || '(anonymous)') + '</span>' +
        '<span class="badge">' + esc(e.endpoint) + '</span>' +
        '<span class="ts">' + esc(e.received_at) + '</span></div>' +
        warn +
        '<pre>' + esc(JSON.stringify(e.set || e.properties, null, 2)) + '</pre></div>';
    }).join('');
  }
  function esc(s) { return String(s == null ? '' : s).replace(/[&<>]/g, function (c) {
    return ({ '&': '&amp;', '<': '&lt;', '>': '&gt;' })[c]; }); }
  async function clearAll() { await fetch('/reset', { method: 'POST' }); load(); }
  setInterval(function () { if (document.getElementById('auto').checked) load(); }, 2000);
  load();
</script>
</body></html>`;

// --- request handling --------------------------------------------------------
function readBody(req) {
  return new Promise((resolve) => {
    const chunks = [];
    req.on("data", (c) => chunks.push(c));
    req.on("end", () => resolve(Buffer.concat(chunks)));
    req.on("error", () => resolve(Buffer.alloc(0)));
  });
}

const CAPTURE_RE = /^\/(e|i\/v0\/e|batch|capture|track|engage|s)\/?$/;
const DECIDE_RE = /^\/(decide|flags)\/?$/;

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, "http://localhost");
  const path = url.pathname;
  const query = Object.fromEntries(url.searchParams);

  if (req.method === "OPTIONS") {
    res.writeHead(204, CORS);
    return res.end();
  }

  if (req.method === "GET") {
    if (path === "/" || path === "/index.html") {
      res.writeHead(200, { ...CORS, "Content-Type": "text/html; charset=utf-8" });
      return res.end(UI);
    }
    if (path === "/events.json") return sendJson(res, 200, { count: events.length, events });
    if (path === "/healthz") {
      res.writeHead(200, { ...CORS, "Content-Type": "text/plain" });
      return res.end("ok");
    }
    // PostHog remote-config bootstrap endpoints (see REMOTE_CONFIG above).
    const arrayCfg = path.match(/^\/array\/[^/]+\/config(\.js)?$/);
    if (arrayCfg) {
      if (arrayCfg[1]) {
        // `config.js` is loaded as a <script>; an empty valid module is enough.
        res.writeHead(200, { ...CORS, "Content-Type": "application/javascript" });
        return res.end("/* posthog-tap: no remote config */\n");
      }
      return sendJson(res, 200, REMOTE_CONFIG);
    }
    // PostHog tries to load optional helper scripts (surveys, toolbar, …) from
    // /static/*.js. Serve an empty module so the SDK doesn't log load errors.
    if (/^\/static\/[^/]+\.js$/.test(path)) {
      res.writeHead(200, { ...CORS, "Content-Type": "application/javascript" });
      return res.end("/* posthog-tap: optional script stubbed */\n");
    }
    return sendJson(res, 404, { error: "not found" });
  }

  if (req.method === "DELETE" && path === "/events") {
    events.length = 0;
    return sendJson(res, 200, { status: 1 });
  }

  if (req.method === "POST") {
    if (path === "/reset") {
      events.length = 0;
      return sendJson(res, 200, { status: 1 });
    }
    if (DECIDE_RE.test(path)) return sendJson(res, 200, DECIDE);
    if (CAPTURE_RE.test(path)) {
      const buf = await readBody(req);
      try {
        record(toEvents(decodeBody(buf, query, req.headers)), { endpoint: path });
      } catch (err) {
        console.error("[posthog-tap] failed to record:", err.message);
      }
      return sendJson(res, 200, { status: 1 });
    }
    // Unknown POST: accept it so the SDK never errors, but log for visibility.
    console.log(`[posthog-tap] unhandled POST ${path}`);
    return sendJson(res, 200, { status: 1 });
  }

  return sendJson(res, 405, { error: "method not allowed" });
});

server.listen(PORT, () => {
  console.log(`[posthog-tap] listening on :${PORT} — UI at http://localhost:${PORT}`);
});
