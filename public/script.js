// --- Internationalisation ---------------------------------------------------
// The server renders each page in exactly one language (/en, /it) and inlines
// that language's dictionary as a non-executing JSON data block, so the page
// never flashes English and never fetches a second locale's resources. All
// dynamic strings resolve through t()/tp() against whole messages with named
// placeholders — sentences are never assembled from concatenated fragments —
// and dates, numbers, and durations go through the locale-aware Intl APIs.

const locale = document.documentElement.lang || "en";
const i18n = JSON.parse(document.querySelector("#i18n-data").textContent);

const pluralRules = new Intl.PluralRules(locale);
const numberFormat = new Intl.NumberFormat(locale);
const dateTimeFormat = new Intl.DateTimeFormat(locale, { dateStyle: "medium", timeStyle: "short" });
const timeFormat = new Intl.DateTimeFormat(locale, { timeStyle: "medium" });
const secondsFormat = new Intl.NumberFormat(locale, { style: "unit", unit: "second", unitDisplay: "narrow", maximumFractionDigits: 2 });
const millisFormat = new Intl.NumberFormat(locale, { style: "unit", unit: "millisecond", unitDisplay: "narrow", maximumFractionDigits: 1 });
const microsFormat = new Intl.NumberFormat(locale, { style: "unit", unit: "microsecond", unitDisplay: "narrow", maximumFractionDigits: 0 });

function formatMessage(message, params) {
  return message.replace(/\{(\w+)\}/g, (token, name) => (name in params ? String(params[name]) : token));
}

// Falls back to the key itself: a visible `some.key` on screen is a loud,
// diagnosable failure, unlike silently presenting another language.
function t(key, params = {}) {
  return formatMessage(i18n[key] ?? key, params);
}

// Pluralized lookup: `<key>.<CLDR category>` via Intl.PluralRules, with
// `other` as the category every language defines. The count is provided to
// the message pre-formatted for the locale.
function tp(key, count, params = {}) {
  const message = i18n[`${key}.${pluralRules.select(count)}`] ?? i18n[`${key}.other`] ?? key;
  return formatMessage(message, { count: numberFormat.format(count), ...params });
}

// The selector links are ordinary crawlable anchors; scripting only persists
// the explicit choice so the `/` redirect can honor it on the next visit. A
// language named in the URL always wins over this cookie.
for (const link of document.querySelectorAll("[data-lang-choice]")) {
  link.addEventListener("click", () => {
    document.cookie = `lang=${link.dataset.langChoice}; path=/; max-age=31536000; samesite=lax`;
  });
}

let accessToken = null;
let currentRole = null;

const message = document.querySelector("#message");
const identity = document.querySelector("#identity");
const identityPill = document.querySelector("#identity-pill");
const authDot = document.querySelector("#auth-dot");
const authBadge = document.querySelector("#auth-badge");
const authForm = document.querySelector("#auth-form");
const sessionPanel = document.querySelector("#session-panel");
const sessionEmail = document.querySelector("#session-email");
const sessionAvatar = document.querySelector("#session-avatar");
const sessionRole = document.querySelector("#session-role");
const sessionMeta = document.querySelector("#session-meta");
const matrixTable = document.querySelector("#permissions-matrix");
const permissionsRoleBadge = document.querySelector("#permissions-role-badge");
const activity = document.querySelector(".activity");

function syncActivityHeight() {
  document.documentElement.style.setProperty("--activity-height", `${activity.offsetHeight}px`);
}

new ResizeObserver(syncActivityHeight).observe(activity);
syncActivityHeight();

function show(label, data) {
  message.textContent = `${label}\n${typeof data === "string" ? data : JSON.stringify(data, null, 2)}`;
  message.scrollTop = 0;
}

function setIdentity(user) {
  const signedIn = Boolean(user);
  currentRole = signedIn ? user.role : null;

  identity.textContent = signedIn
    ? t("identity.signedIn", { email: user.email, role: user.role })
    : t("identity.signedOut");
  authDot.classList.remove("checking");
  authDot.classList.toggle("online", signedIn);
  identityPill.classList.toggle("online", signedIn);

  authBadge.textContent = signedIn ? t("auth.badgeSignedIn") : t("auth.badgeSignedOut");
  authBadge.classList.toggle("ok", signedIn);

  authForm.hidden = signedIn;
  sessionPanel.hidden = !signedIn;
  if (signedIn) {
    sessionEmail.textContent = user.email;
    sessionAvatar.textContent = user.email.charAt(0).toUpperCase();
    sessionRole.textContent = user.role;
    sessionMeta.textContent = user.created_at
      ? t("session.created", { date: dateTimeFormat.format(new Date(user.created_at)) })
      : "";
  }

  for (const badge of document.querySelectorAll(".badge.protected")) {
    badge.textContent = signedIn ? t("badges.unlocked") : t("badges.loginRequired");
    badge.classList.toggle("unlocked", signedIn);
  }

  // A realtime connection outlives the session that authorized it, so signing
  // out closes it here rather than leaving it pushing events.
  if (!signedIn) disconnectRealtime();

  syncMatrixAccess();
}

function setRuntime(runtime) {
  const runtimeBadge = document.querySelector("#runtime-badge");
  runtimeBadge.textContent =
    runtime.database === "embedded-postgresql" ? t("runtime.embedded") : t("runtime.fullStack");
  runtimeBadge.classList.add("ok");
}

// The API deliberately answers with stable error codes; the code is what gets
// translated here, so backend messages never need to know the page language.
// Codes whose server message carries request-specific detail (which field
// failed, which permission is missing) keep that detail visibly appended
// rather than silently dropped or passed off as translated.
function describeError(payload, status) {
  const code = payload?.error?.code;
  const serverMessage = payload?.error?.message;
  const translated = code && i18n[`errors.code.${code}`];
  if (!translated) {
    return serverMessage || t("errors.serverStatus", { status });
  }
  const detailed = ["bad_request", "forbidden", "conflict"].includes(code);
  return detailed && serverMessage ? `${translated} — ${serverMessage}` : translated;
}

async function parseResponse(response) {
  if (response.status === 204) return null;
  const data = await response.json().catch(() => ({}));
  if (!response.ok) {
    const error = new Error(describeError(data, response.status));
    error.status = response.status;
    throw error;
  }
  return data;
}

async function refreshAccessToken() {
  const response = await fetch("/api/auth/refresh", {
    method: "POST",
    credentials: "same-origin",
  });
  if (!response.ok) {
    accessToken = null;
    setIdentity(null);
    return false;
  }
  const data = await response.json();
  accessToken = data.access_token;
  setIdentity(data.user);
  return true;
}

async function api(path, options = {}, retry = true) {
  const headers = new Headers(options.headers || {});
  if (options.body) headers.set("content-type", "application/json");
  if (accessToken) headers.set("authorization", `Bearer ${accessToken}`);
  const response = await fetch(path, {
    ...options,
    headers,
    credentials: "same-origin",
  });
  if (response.status === 401 && retry && await refreshAccessToken()) {
    return api(path, options, false);
  }
  return parseResponse(response);
}

async function run(label, operation) {
  try {
    show(label, await operation());
  } catch (error) {
    show(t("labels.failed", { label }), error.message);
  }
}

document.querySelector("#health-button").addEventListener("click", () => run(t("labels.health"), async () => {
  const data = await api("/api/health");
  const badge = document.querySelector("#health-badge");
  badge.textContent = data.status;
  badge.classList.add("ok");
  return data;
}));

document.querySelector("#time-button").addEventListener("click", () => run(t("service.serverTime"), () => api("/api/time")));

async function authenticate(endpoint) {
  const payload = {
    email: document.querySelector("#email").value,
    password: document.querySelector("#password").value,
  };
  if (endpoint.endsWith("/register")) {
    payload.role = document.querySelector("#role").value;
  }
  const response = await api(endpoint, {
    method: "POST",
    body: JSON.stringify(payload),
  }, false);
  accessToken = response.access_token;
  setIdentity(response.user);
  return { user: response.user, expires_in: response.expires_in };
}

document.querySelector("#auth-form").addEventListener("submit", (event) => {
  event.preventDefault();
  run(t("labels.login"), () => authenticate("/api/auth/login"));
});

document.querySelector("#register-button").addEventListener("click", () => run(t("labels.registration"), () => authenticate("/api/auth/register")));

document.querySelector("#profile-button").addEventListener("click", () => run(t("labels.profile"), () => api("/api/me")));
document.querySelector("#logout-button").addEventListener("click", () => run(t("labels.logout"), async () => {
  await api("/api/auth/logout", { method: "POST" }, false);
  accessToken = null;
  setIdentity(null);
  return t("auth.logoutResult");
}));

// --- Permissions ---------------------------------------------------------
// The matrix is rendered from the server's catalog so the page never
// hardcodes permission names. The grants are fixed server-side; this view is
// read-only.

async function loadPermissions() {
  renderMatrix(await api("/api/permissions", {}, false));
}

function renderMatrix(matrix) {
  const roles = Object.keys(matrix.roles);

  const headRow = document.createElement("tr");
  const lead = document.createElement("th");
  lead.scope = "col";
  lead.textContent = t("permissions.columnPermission");
  headRow.append(lead);
  for (const role of roles) {
    const th = document.createElement("th");
    th.scope = "col";
    th.className = "grant";
    th.dataset.role = role;
    th.textContent = role;
    headRow.append(th);
  }
  const thead = document.createElement("thead");
  thead.append(headRow);

  const tbody = document.createElement("tbody");
  for (const permission of matrix.catalog) {
    const name = document.createElement("th");
    name.scope = "row";
    const label = document.createElement("code");
    label.textContent = permission.name;
    const hint = document.createElement("span");
    hint.className = "permission-hint";
    hint.textContent = permission.description;
    name.append(label, hint);

    const row = document.createElement("tr");
    row.append(name);
    for (const role of roles) {
      const granted = matrix.roles[role].includes(permission.name);
      const mark = document.createElement("span");
      mark.className = granted ? "grant-mark" : "grant-mark denied";
      mark.textContent = granted ? "✓" : "—";
      mark.setAttribute("role", "img");
      mark.setAttribute(
        "aria-label",
        t(granted ? "permissions.may" : "permissions.mayNot", { role, description: permission.description }),
      );
      const grant = document.createElement("td");
      grant.className = "grant";
      grant.dataset.role = role;
      grant.append(mark);
      row.append(grant);
    }
    tbody.append(row);
  }

  matrixTable.replaceChildren(thead, tbody);
  syncMatrixAccess();
}

function syncMatrixAccess() {
  const signedIn = Boolean(currentRole);
  for (const element of matrixTable.querySelectorAll("[data-role]")) {
    element.classList.toggle("current", element.dataset.role === currentRole);
  }
  permissionsRoleBadge.textContent = signedIn
    ? t("permissions.actingAs", { role: currentRole })
    : t("permissions.signedOut");
  permissionsRoleBadge.classList.toggle("ok", signedIn);
}

function bindDemoEndpoint(buttonId, badgeId, labelKey, path, options) {
  const badge = document.querySelector(badgeId);
  document.querySelector(buttonId).addEventListener("click", () => run(t(labelKey), async () => {
    try {
      const data = await api(path, options);
      badge.textContent = t("status.ok");
      badge.className = "badge ok";
      return data;
    } catch (error) {
      if (error.status === 403) {
        badge.textContent = t("status.forbidden");
        badge.className = "badge denied";
      } else if (error.status === 401) {
        badge.textContent = t("status.unauthorized");
        badge.className = "badge";
      } else {
        badge.textContent = t("status.error");
        badge.className = "badge";
      }
      throw error;
    }
  }));
}

bindDemoEndpoint("#reports-button", "#reports-outcome", "labels.demoReport", "/api/demo/reports", {});
bindDemoEndpoint("#purge-button", "#purge-outcome", "labels.recordPurge", "/api/demo/records", { method: "DELETE" });

document.querySelector("#cache-form").addEventListener("submit", (event) => {
  event.preventDefault();
  run(t("labels.cacheWrite"), () => {
    let value;
    try {
      value = JSON.parse(document.querySelector("#cache-value").value);
    } catch {
      throw new Error(t("cache.invalidJson"));
    }
    return api("/api/cache/demo", {
      method: "PUT",
      body: JSON.stringify({ value, ttl_seconds: Number(document.querySelector("#cache-ttl").value) }),
    });
  });
});

document.querySelector("#cache-get-button").addEventListener("click", () => run(t("labels.cacheRead"), () => api("/api/cache/demo")));
document.querySelector("#cache-delete-button").addEventListener("click", () => run(t("labels.cacheClear"), async () => {
  await api("/api/cache/demo", { method: "DELETE" });
  return t("cache.invalidated");
}));

document.querySelector("#job-form").addEventListener("submit", (event) => {
  event.preventDefault();
  run(t("labels.queue"), () => api("/api/jobs", {
    method: "POST",
    body: JSON.stringify({ kind: "audit_event", action: document.querySelector("#job-action").value }),
  }));
});

// --- Realtime -------------------------------------------------------------
// A browser WebSocket handshake cannot carry an Authorization header, so the
// page first spends an authenticated POST on a single-use ticket and redeems
// it in the query string. The ticket is worthless once used and expires within
// seconds, unlike the access token it stands in for.

const realtimeBadge = document.querySelector("#realtime-badge");
const realtimeState = document.querySelector("#realtime-state");
const realtimeClients = document.querySelector("#realtime-clients");
const realtimeEvents = document.querySelector("#realtime-events");
const realtimeFeed = document.querySelector("#realtime-feed");
const realtimeText = document.querySelector("#realtime-text");
const realtimeSendButton = document.querySelector("#realtime-send-button");
const realtimeConnectButton = document.querySelector("#realtime-connect-button");
const realtimeDisconnectButton = document.querySelector("#realtime-disconnect-button");

const FEED_LIMIT = 14;
const RECONNECT_DELAYS_MS = [1000, 2000, 4000, 8000];

let socket = null;
let connectionId = null;
let eventCount = 0;
let reconnectAttempt = 0;
let reconnectTimer = null;
// Set while the page is deliberately closing the socket, so the close handler
// can tell a user action apart from a connection that dropped on its own.
let closingDeliberately = false;

function setRealtimeState(state, { online = false, connecting = false } = {}) {
  realtimeState.textContent = state;
  realtimeBadge.textContent = state;
  realtimeBadge.classList.toggle("ok", online);
  realtimeConnectButton.disabled = online || connecting;
  realtimeDisconnectButton.disabled = !online && !connecting;
  realtimeSendButton.disabled = !online;
  realtimeText.disabled = !online;
}

function appendFeedEntry(kind, text) {
  const label = document.createElement("span");
  label.className = `feed-kind ${kind}`;
  label.textContent = kind;

  const body = document.createElement("span");
  body.className = "feed-text";
  body.textContent = text;

  const time = document.createElement("time");
  time.textContent = timeFormat.format(new Date());

  const entry = document.createElement("li");
  entry.append(label, body, time);
  realtimeFeed.prepend(entry);
  while (realtimeFeed.childElementCount > FEED_LIMIT) {
    realtimeFeed.lastElementChild.remove();
  }
}

// Events are fanned out to every connection, so they carry the opaque user id
// and role rather than an email.
function participantLabel(participant) {
  const short = participant.user_id.slice(0, 8);
  return `${participant.role} ${short}`;
}

function handleRealtimeEvent(event) {
  eventCount += 1;
  realtimeEvents.textContent = numberFormat.format(eventCount);
  if (typeof event.connections === "number") {
    realtimeClients.textContent = numberFormat.format(event.connections);
  }

  switch (event.type) {
    case "welcome":
      connectionId = event.connection_id;
      appendFeedEntry("welcome", t("realtime.welcome", {
        participant: participantLabel(event.you),
        max: numberFormat.format(event.limits.max_text_characters),
        messages: numberFormat.format(event.limits.messages_per_window),
        window: secondsFormat.format(event.limits.message_window_seconds),
      }));
      break;
    case "presence": {
      // The server reports the change as a stable code, translated here like
      // the API error codes; an unrecognized one falls back to the generic
      // message with the raw code visible.
      const family = event.connection_id === connectionId ? "realtime.presenceSelf" : "realtime.presence";
      const variant = event.change === "connected" || event.change === "disconnected" ? event.change : "changed";
      appendFeedEntry("presence", t(`${family}.${variant}`, {
        participant: participantLabel(event.participant),
        change: event.change,
      }));
      break;
    }
    case "message":
      appendFeedEntry("message", t("realtime.messageEntry", {
        sequence: event.sequence,
        participant: participantLabel(event.from),
        text: event.text,
      }));
      break;
    case "tick":
      appendFeedEntry("tick", t("realtime.tickEntry", { sequence: event.sequence }));
      break;
    case "notice":
      appendFeedEntry("notice", `${event.code}: ${event.detail}`);
      break;
    default:
      // Unknown event types are the forward-compatible case: the envelope is
      // still readable, so show it rather than dropping it.
      appendFeedEntry("event", event.type);
  }
}

async function openRealtimeSocket() {
  const { ticket } = await api("/api/realtime/ticket", { method: "POST" });
  // Same-origin, which is what the server's origin check and the page's
  // connect-src 'self' policy both allow.
  const scheme = location.protocol === "https:" ? "wss:" : "ws:";
  const url = `${scheme}//${location.host}/api/realtime/ws?ticket=${encodeURIComponent(ticket)}`;

  closingDeliberately = false;
  setRealtimeState(t("realtime.connecting"), { connecting: true });
  socket = new WebSocket(url);
  socket.addEventListener("open", () => {
    reconnectAttempt = 0;
    setRealtimeState(t("realtime.live"), { online: true });
  });
  socket.addEventListener("message", (event) => handleRealtimeEvent(JSON.parse(event.data)));
  socket.addEventListener("close", (event) => {
    socket = null;
    connectionId = null;
    realtimeClients.textContent = "—";
    if (closingDeliberately || !accessToken) {
      setRealtimeState(t("realtime.disconnected"));
      return;
    }
    const detail = `${event.code}${event.reason ? `: ${event.reason}` : ""}`;
    appendFeedEntry("notice", t("realtime.closed", { detail }));
    scheduleReconnect();
  });
  return t("realtime.ticketRedeemed");
}

// Reconnecting is the part of realtime that a demo usually skips: a dropped
// socket needs a fresh ticket, and retries back off so a server that is down
// is not hammered by every open tab.
function scheduleReconnect() {
  if (reconnectAttempt >= RECONNECT_DELAYS_MS.length) {
    setRealtimeState(t("realtime.disconnected"));
    appendFeedEntry("notice", t("realtime.gaveUp"));
    return;
  }
  const delay = RECONNECT_DELAYS_MS[reconnectAttempt];
  reconnectAttempt += 1;
  setRealtimeState(t("realtime.reconnectingIn", { delay: secondsFormat.format(delay / 1000) }), { connecting: true });
  reconnectTimer = setTimeout(() => {
    run(t("labels.realtimeReconnect"), async () => {
      try {
        return await openRealtimeSocket();
      } catch (error) {
        // A failed attempt — an expired session, a server still restarting —
        // is just another dropped connection, so it backs off again instead
        // of leaving the card stuck on "Reconnecting".
        scheduleReconnect();
        throw error;
      }
    });
  }, delay);
}

function disconnectRealtime() {
  clearTimeout(reconnectTimer);
  reconnectAttempt = 0;
  closingDeliberately = true;
  if (socket) {
    socket.close(1000, "client disconnected");
  } else {
    setRealtimeState(t("realtime.disconnected"));
  }
}

realtimeConnectButton.addEventListener("click", () => run(t("labels.realtime"), async () => {
  reconnectAttempt = 0;
  try {
    return await openRealtimeSocket();
  } catch (error) {
    setRealtimeState(t("realtime.disconnected"));
    throw error;
  }
}));

realtimeDisconnectButton.addEventListener("click", () => run(t("labels.realtime"), () => {
  disconnectRealtime();
  return t("realtime.socketClosed");
}));

document.querySelector("#realtime-form").addEventListener("submit", (event) => {
  event.preventDefault();
  run(t("labels.realtimeBroadcast"), () => {
    if (!socket || socket.readyState !== WebSocket.OPEN) {
      throw new Error(t("realtime.connectFirst"));
    }
    const text = realtimeText.value;
    socket.send(JSON.stringify({ type: "broadcast", text }));
    return { sent: { type: "broadcast", text }, note: t("realtime.sentNote") };
  });
});

document.querySelector("#telemetry-button").addEventListener("click", () => run(t("labels.telemetryTrace"), async () => {
  const data = await api("/api/telemetry/demo");
  const badge = document.querySelector("#telemetry-badge");

  document.querySelector("#telemetry-service").textContent = data.service_name;
  document.querySelector("#telemetry-request-id").textContent = data.request_id || t("telemetry.unavailable");
  document.querySelector("#telemetry-trace-id").textContent = data.trace_id || t("telemetry.unavailable");
  document.querySelector("#telemetry-result").hidden = false;

  if (!data.trace_id) {
    badge.textContent = t("telemetry.noTrace");
    badge.classList.remove("ok");
    return data;
  }

  const trace = await fetchTrace(data.trace_id);
  renderWaterfall(trace.spans);
  badge.textContent = tp("telemetry.spans", trace.spans.length);
  badge.classList.add("ok");

  return {
    ...data,
    span_count: trace.spans.length,
    hint: data.otlp_enabled ? t("telemetry.hintExporting") : t("telemetry.hintInProcess"),
  };
}));

// The root HTTP span finishes only as the demo response is sent, so the first
// lookup can race it into the store; retry briefly before giving up.
async function fetchTrace(traceId, attempt = 0) {
  try {
    return await api(`/api/telemetry/traces/${traceId}`, {}, false);
  } catch (error) {
    if (attempt >= 4) throw error;
    await new Promise((resolve) => setTimeout(resolve, 250));
    return fetchTrace(traceId, attempt + 1);
  }
}

function renderWaterfall(spans) {
  const container = document.querySelector("#trace-waterfall");
  container.replaceChildren();
  container.hidden = spans.length === 0;
  if (!spans.length) return;

  const start = Math.min(...spans.map((span) => span.start_unix_ms));
  const end = Math.max(...spans.map((span) => span.start_unix_ms + span.duration_ms));
  const total = Math.max(end - start, 0.001);

  const byId = new Map(spans.map((span) => [span.span_id, span]));
  const depthOf = (span, seen = new Set()) => {
    const parent = span.parent_span_id && byId.get(span.parent_span_id);
    if (!parent || seen.has(span.span_id)) return 0;
    return depthOf(parent, seen.add(span.span_id)) + 1;
  };

  for (const span of spans) {
    const label = document.createElement("span");
    label.className = "trace-label";
    label.style.paddingInlineStart = `${depthOf(span) * 0.9}rem`;
    label.textContent = span.name;
    label.title = `${span.name} · ${span.kind}`;

    const bar = document.createElement("span");
    bar.className = span.status === "error" ? "trace-bar error" : "trace-bar";
    bar.style.left = `${((span.start_unix_ms - start) / total) * 100}%`;
    bar.style.width = `${Math.max((span.duration_ms / total) * 100, 0.8)}%`;
    const track = document.createElement("span");
    track.className = "trace-track";
    track.append(bar);

    const duration = document.createElement("span");
    duration.className = "trace-duration";
    duration.textContent = formatDuration(span.duration_ms);

    const row = document.createElement("div");
    row.className = "trace-row";
    row.append(label, track, duration);
    container.append(row);
  }
}

// Durations use Intl's unit formatting, so both the number (decimal
// separator, grouping) and the unit symbol follow the page locale.
function formatDuration(ms) {
  if (ms >= 1000) return secondsFormat.format(ms / 1000);
  if (ms >= 1) return millisFormat.format(ms);
  return microsFormat.format(ms * 1000);
}

let wasmExports = null;
const WASM_BENCHMARK_ITERATIONS = 10;

async function loadWasmDemo() {
  if (wasmExports) return wasmExports;
  const source = fetch("/demo.wasm");
  // Streaming compilation is the standard path; the ArrayBuffer fallback
  // covers engines without instantiateStreaming.
  const { instance } = "instantiateStreaming" in WebAssembly
    ? await WebAssembly.instantiateStreaming(source)
    : await WebAssembly.instantiate(await (await source).arrayBuffer());
  wasmExports = instance.exports;
  return wasmExports;
}

// Mirrors count_primes in wasm/src/lib.rs; the demo cross-checks the counts.
function countPrimesJs(limit) {
  if (limit < 2) return 0;
  const composite = new Uint8Array(limit + 1);
  let count = 0;
  for (let n = 2; n <= limit; n += 1) {
    if (composite[n]) continue;
    count += 1;
    for (let multiple = n * n; multiple <= limit; multiple += n) {
      composite[multiple] = 1;
    }
  }
  return count;
}

document.querySelector("#wasm-form").addEventListener("submit", (event) => {
  event.preventDefault();
  run(t("labels.wasmBenchmark"), async () => {
    const badge = document.querySelector("#wasm-badge");
    const limit = Math.min(Math.max(Math.trunc(Number(document.querySelector("#wasm-limit").value) || 0), 2), 10_000_000);

    let exports;
    try {
      exports = await loadWasmDemo();
    } catch (error) {
      badge.textContent = t("wasm.unavailable");
      badge.classList.remove("ok");
      throw error;
    }
    badge.textContent = t("wasm.instantiated");
    badge.classList.add("ok");

    // Run both implementations once outside the timed section so the
    // benchmark does not include first-call JIT/tiering effects.
    const wasmWarmupCount = exports.count_primes(limit) >>> 0;
    const jsWarmupCount = countPrimesJs(limit);
    if (wasmWarmupCount !== jsWarmupCount) {
      throw new Error(t("wasm.warmupMismatch", {
        wasm: numberFormat.format(wasmWarmupCount),
        js: numberFormat.format(jsWarmupCount),
      }));
    }

    let wasmTotalMs = 0;
    let jsTotalMs = 0;
    for (let iteration = 0; iteration < WASM_BENCHMARK_ITERATIONS; iteration += 1) {
      const wasmStart = performance.now();
      const wasmCount = exports.count_primes(limit) >>> 0;
      wasmTotalMs += performance.now() - wasmStart;

      const jsStart = performance.now();
      const jsCount = countPrimesJs(limit);
      jsTotalMs += performance.now() - jsStart;

      if (wasmCount !== jsCount) {
        throw new Error(t("wasm.iterationMismatch", {
          iteration: numberFormat.format(iteration + 1),
          wasm: numberFormat.format(wasmCount),
          js: numberFormat.format(jsCount),
        }));
      }
    }
    const wasmMs = wasmTotalMs / WASM_BENCHMARK_ITERATIONS;
    const jsMs = jsTotalMs / WASM_BENCHMARK_ITERATIONS;

    document.querySelector("#wasm-count").textContent = numberFormat.format(wasmWarmupCount);
    document.querySelector("#wasm-time").textContent = millisFormat.format(wasmMs);
    document.querySelector("#wasm-js-time").textContent = millisFormat.format(jsMs);
    document.querySelector("#wasm-result").hidden = false;

    return {
      sieve_limit: limit,
      primes_found: wasmWarmupCount,
      iterations: WASM_BENCHMARK_ITERATIONS,
      wasm_ms: Number(wasmMs.toFixed(2)),
      js_ms: Number(jsMs.toFixed(2)),
      note: t("wasm.note"),
    };
  });
});

async function initialize() {
  try {
    const runtime = await api("/api/runtime", {}, false);
    setRuntime(runtime);
    await loadPermissions();

    // A surviving HTTP-only refresh cookie may restore the session after a reload.
    const restored = await refreshAccessToken();
    show(t("labels.session"), restored ? t("session.restored") : t("session.none"));
  } catch (error) {
    setIdentity(null);
    show(t("labels.startupFailed"), error.message);
  }
}

initialize();
