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
const sessionRoleSelect = document.querySelector("#session-role-select");
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

  identity.textContent = signedIn ? `Signed in as ${user.email} · ${user.role}` : "Signed out";
  authDot.classList.remove("checking");
  authDot.classList.toggle("online", signedIn);
  identityPill.classList.toggle("online", signedIn);

  authBadge.textContent = signedIn ? "Signed in" : "Signed out";
  authBadge.classList.toggle("ok", signedIn);

  authForm.hidden = signedIn;
  sessionPanel.hidden = !signedIn;
  if (signedIn) {
    sessionEmail.textContent = user.email;
    sessionAvatar.textContent = user.email.charAt(0).toUpperCase();
    sessionRole.textContent = user.role;
    sessionRoleSelect.value = user.role;
    sessionMeta.textContent = user.created_at
      ? `Account created ${new Date(user.created_at).toLocaleString()}`
      : "";
  }

  for (const badge of document.querySelectorAll(".badge.protected")) {
    badge.textContent = signedIn ? "Unlocked" : "Log in required";
    badge.classList.toggle("unlocked", signedIn);
  }

  syncMatrixAccess();
}

function setRuntime(runtime) {
  const runtimeBadge = document.querySelector("#runtime-badge");
  runtimeBadge.textContent =
    runtime.database === "embedded-postgresql" ? "Embedded database" : "Full stack";
  runtimeBadge.classList.add("ok");
}

async function parseResponse(response) {
  if (response.status === 204) return null;
  const data = await response.json().catch(() => ({}));
  if (!response.ok) {
    const error = new Error(data?.error?.message || `Server returned ${response.status}`);
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
    show(`${label} failed`, error.message);
  }
}

document.querySelector("#health-button").addEventListener("click", () => run("Health", async () => {
  const data = await api("/api/health");
  const badge = document.querySelector("#health-badge");
  badge.textContent = data.status;
  badge.classList.add("ok");
  return data;
}));

document.querySelector("#time-button").addEventListener("click", () => run("Server time", () => api("/api/time")));

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
  run("Login", () => authenticate("/api/auth/login"));
});

document.querySelector("#register-button").addEventListener("click", () => run("Registration", () => authenticate("/api/auth/register")));

// Switching the role re-issues the access token: the role travels as a JWT
// claim, so the server hands back a token carrying the new one.
sessionRoleSelect.addEventListener("change", () => {
  const role = sessionRoleSelect.value;
  run(`Switch role to ${role}`, async () => {
    try {
      const response = await api("/api/me/role", {
        method: "PUT",
        body: JSON.stringify({ role }),
      });
      accessToken = response.access_token;
      setIdentity(response.user);
      return {
        user: response.user,
        note: "A fresh access token was issued so the new role applies immediately.",
      };
    } catch (error) {
      sessionRoleSelect.value = currentRole;
      throw error;
    }
  });
});
document.querySelector("#profile-button").addEventListener("click", () => run("Profile", () => api("/api/me")));
document.querySelector("#logout-button").addEventListener("click", () => run("Logout", async () => {
  await api("/api/auth/logout", { method: "POST" }, false);
  accessToken = null;
  setIdentity(null);
  return "Refresh session revoked and cookie removed.";
}));

// --- Permissions ---------------------------------------------------------
// The matrix is rendered from the server's catalog so the page never
// hardcodes permission names; every toggle is saved immediately with a PUT.

async function loadPermissions() {
  renderMatrix(await api("/api/permissions", {}, false));
}

function renderMatrix(matrix) {
  const roles = Object.keys(matrix.roles);

  const headRow = document.createElement("tr");
  const lead = document.createElement("th");
  lead.scope = "col";
  lead.textContent = "Permission";
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
      const box = document.createElement("input");
      box.type = "checkbox";
      box.dataset.role = role;
      box.dataset.permission = permission.name;
      box.checked = matrix.roles[role].includes(permission.name);
      box.setAttribute("aria-label", `${role}: ${permission.description}`);
      const grant = document.createElement("td");
      grant.className = "grant";
      grant.dataset.role = role;
      grant.append(box);
      row.append(grant);
    }
    tbody.append(row);
  }

  matrixTable.replaceChildren(thead, tbody);
  syncMatrixAccess();
}

function syncMatrixAccess() {
  const signedIn = Boolean(currentRole);
  for (const box of matrixTable.querySelectorAll("input[type=checkbox]")) {
    box.disabled = !signedIn;
  }
  for (const element of matrixTable.querySelectorAll("[data-role]")) {
    element.classList.toggle("current", element.dataset.role === currentRole);
  }
  permissionsRoleBadge.textContent = signedIn ? `Acting as ${currentRole}` : "Signed out";
  permissionsRoleBadge.classList.toggle("ok", signedIn);
}

matrixTable.addEventListener("change", (event) => {
  const box = event.target;
  if (box.type !== "checkbox") return;
  const role = box.dataset.role;
  const permissions = [...matrixTable.querySelectorAll(`input[data-role="${role}"]`)]
    .filter((input) => input.checked)
    .map((input) => input.dataset.permission);
  run(`Permissions for ${role}`, async () => {
    try {
      const matrix = await api(`/api/permissions/${role}`, {
        method: "PUT",
        body: JSON.stringify({ permissions }),
      });
      renderMatrix(matrix);
      return { role, granted: matrix.roles[role] };
    } catch (error) {
      // Revert the optimistic toggle to the server's state.
      await loadPermissions().catch(() => {});
      throw error;
    }
  });
});

function bindDemoEndpoint(buttonId, badgeId, label, path, options) {
  const badge = document.querySelector(badgeId);
  document.querySelector(buttonId).addEventListener("click", () => run(label, async () => {
    try {
      const data = await api(path, options);
      badge.textContent = "200 OK";
      badge.className = "badge ok";
      return data;
    } catch (error) {
      if (error.status === 403) {
        badge.textContent = "403 Forbidden";
        badge.className = "badge denied";
      } else if (error.status === 401) {
        badge.textContent = "401 Unauthorized";
        badge.className = "badge";
      } else {
        badge.textContent = "Error";
        badge.className = "badge";
      }
      throw error;
    }
  }));
}

bindDemoEndpoint("#reports-button", "#reports-outcome", "Demo report", "/api/demo/reports", {});
bindDemoEndpoint("#purge-button", "#purge-outcome", "Record purge", "/api/demo/records", { method: "DELETE" });

document.querySelector("#cache-form").addEventListener("submit", (event) => {
  event.preventDefault();
  run("Cache write", () => {
    let value;
    try {
      value = JSON.parse(document.querySelector("#cache-value").value);
    } catch {
      throw new Error("Cache value must be valid JSON.");
    }
    return api("/api/cache/demo", {
      method: "PUT",
      body: JSON.stringify({ value, ttl_seconds: Number(document.querySelector("#cache-ttl").value) }),
    });
  });
});

document.querySelector("#cache-get-button").addEventListener("click", () => run("Cache read", () => api("/api/cache/demo")));
document.querySelector("#cache-delete-button").addEventListener("click", () => run("Cache clear", async () => {
  await api("/api/cache/demo", { method: "DELETE" });
  return "Cache key invalidated.";
}));

document.querySelector("#job-form").addEventListener("submit", (event) => {
  event.preventDefault();
  run("Queue", () => api("/api/jobs", {
    method: "POST",
    body: JSON.stringify({ kind: "audit_event", action: document.querySelector("#job-action").value }),
  }));
});

document.querySelector("#telemetry-button").addEventListener("click", () => run("OpenTelemetry trace", async () => {
  const data = await api("/api/telemetry/demo");
  const badge = document.querySelector("#telemetry-badge");

  document.querySelector("#telemetry-service").textContent = data.service_name;
  document.querySelector("#telemetry-request-id").textContent = data.request_id || "Unavailable";
  document.querySelector("#telemetry-trace-id").textContent = data.trace_id || "Unavailable";
  document.querySelector("#telemetry-result").hidden = false;

  if (!data.trace_id) {
    badge.textContent = "No trace";
    badge.classList.remove("ok");
    return data;
  }

  const trace = await fetchTrace(data.trace_id);
  renderWaterfall(trace.spans);
  badge.textContent = `${trace.spans.length} spans`;
  badge.classList.add("ok");

  return {
    ...data,
    span_count: trace.spans.length,
    hint: data.otlp_enabled
      ? "Spans are captured in-process for the waterfall below and batch-exported to the configured OTLP endpoint."
      : "Spans are captured in-process. Set OTEL_EXPORTER_OTLP_ENDPOINT to also export them over OTLP.",
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
    label.style.paddingLeft = `${depthOf(span) * 0.9}rem`;
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

function formatDuration(ms) {
  if (ms >= 1000) return `${(ms / 1000).toFixed(2)} s`;
  if (ms >= 1) return `${ms.toFixed(1)} ms`;
  return `${(ms * 1000).toFixed(0)} µs`;
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
  run("WebAssembly benchmark", async () => {
    const badge = document.querySelector("#wasm-badge");
    const limit = Math.min(Math.max(Math.trunc(Number(document.querySelector("#wasm-limit").value) || 0), 2), 10_000_000);

    let exports;
    try {
      exports = await loadWasmDemo();
    } catch (error) {
      badge.textContent = "Unavailable";
      badge.classList.remove("ok");
      throw error;
    }
    badge.textContent = "Instantiated";
    badge.classList.add("ok");

    // Run both implementations once outside the timed section so the
    // benchmark does not include first-call JIT/tiering effects.
    const wasmWarmupCount = exports.count_primes(limit) >>> 0;
    const jsWarmupCount = countPrimesJs(limit);
    if (wasmWarmupCount !== jsWarmupCount) {
      throw new Error(`WebAssembly and JavaScript disagree during warmup: ${wasmWarmupCount} vs ${jsWarmupCount}`);
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
        throw new Error(`WebAssembly and JavaScript disagree on iteration ${iteration + 1}: ${wasmCount} vs ${jsCount}`);
      }
    }
    const wasmMs = wasmTotalMs / WASM_BENCHMARK_ITERATIONS;
    const jsMs = jsTotalMs / WASM_BENCHMARK_ITERATIONS;

    document.querySelector("#wasm-count").textContent = wasmWarmupCount.toLocaleString();
    document.querySelector("#wasm-time").textContent = `${wasmMs.toFixed(1)} ms`;
    document.querySelector("#wasm-js-time").textContent = `${jsMs.toFixed(1)} ms`;
    document.querySelector("#wasm-result").hidden = false;

    return {
      sieve_limit: limit,
      primes_found: wasmWarmupCount,
      iterations: WASM_BENCHMARK_ITERATIONS,
      wasm_ms: Number(wasmMs.toFixed(2)),
      js_ms: Number(jsMs.toFixed(2)),
      note: "10-run averages after one untimed warmup; identical byte-array sieves must return matching counts. Timings vary by device.",
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
    show(
      "Session",
      restored
        ? "Restored from the refresh cookie."
        : "No active session. Log in or register to use the protected endpoints.",
    );
  } catch (error) {
    setIdentity(null);
    show("Startup check failed", error.message);
  }
}

initialize();
