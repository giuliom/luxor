let accessToken = null;
let standaloneMode = false;

const message = document.querySelector("#message");
const identity = document.querySelector("#identity");
const identityPill = document.querySelector("#identity-pill");
const authDot = document.querySelector("#auth-dot");
const authBadge = document.querySelector("#auth-badge");
const authForm = document.querySelector("#auth-form");
const sessionPanel = document.querySelector("#session-panel");
const sessionEmail = document.querySelector("#session-email");
const sessionAvatar = document.querySelector("#session-avatar");
const sessionMeta = document.querySelector("#session-meta");

function show(label, data) {
  message.textContent = `${label}\n${typeof data === "string" ? data : JSON.stringify(data, null, 2)}`;
}

function setIdentity(user) {
  const signedIn = Boolean(user);

  identity.textContent = standaloneMode
    ? "Standalone · no database"
    : signedIn
      ? `Signed in as ${user.email}`
      : "Signed out";
  authDot.classList.remove("checking");
  authDot.classList.toggle("online", signedIn && !standaloneMode);
  authDot.classList.toggle("standalone", standaloneMode);
  identityPill.classList.toggle("online", signedIn && !standaloneMode);
  identityPill.classList.toggle("standalone", standaloneMode);

  authBadge.textContent = standaloneMode ? "Unavailable" : signedIn ? "Signed in" : "Signed out";
  authBadge.classList.toggle("ok", signedIn && !standaloneMode);
  authBadge.classList.toggle("offline", standaloneMode);

  authForm.hidden = signedIn;
  sessionPanel.hidden = !signedIn;
  if (signedIn) {
    sessionEmail.textContent = user.email;
    sessionAvatar.textContent = user.email.charAt(0).toUpperCase();
    sessionMeta.textContent = user.created_at
      ? `Account created ${new Date(user.created_at).toLocaleString()}`
      : "";
  }

  for (const badge of document.querySelectorAll(".badge.protected")) {
    badge.textContent = standaloneMode ? "Memory demo" : signedIn ? "Unlocked" : "Log in required";
    badge.classList.toggle("unlocked", standaloneMode || signedIn);
  }
}

function setRuntime(runtime) {
  standaloneMode = runtime.mode === "standalone";
  const runtimeBadge = document.querySelector("#runtime-badge");
  runtimeBadge.textContent = standaloneMode ? "Standalone" : "Full stack";
  runtimeBadge.classList.toggle("standalone", standaloneMode);
  runtimeBadge.classList.toggle("ok", !standaloneMode);

  document.querySelector("#auth-description").textContent = standaloneMode
    ? "Persistent authentication is disabled. Cache and queue actions use ephemeral in-memory backends."
    : "Register or sign in against PostgreSQL-backed sessions.";
  for (const control of authForm.querySelectorAll("input, button")) {
    control.disabled = standaloneMode;
  }
}

async function parseResponse(response) {
  if (response.status === 204) return null;
  const data = await response.json().catch(() => ({}));
  if (!response.ok) {
    throw new Error(data?.error?.message || `Server returned ${response.status}`);
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
  const response = await api(endpoint, {
    method: "POST",
    body: JSON.stringify({
      email: document.querySelector("#email").value,
      password: document.querySelector("#password").value,
    }),
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
document.querySelector("#profile-button").addEventListener("click", () => run("Profile", () => api("/api/me")));
document.querySelector("#logout-button").addEventListener("click", () => run("Logout", async () => {
  await api("/api/auth/logout", { method: "POST" }, false);
  accessToken = null;
  setIdentity(null);
  return "Refresh session revoked and cookie removed.";
}));

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
  badge.textContent = data.enabled ? "Exporting" : "Exporter off";
  badge.classList.toggle("ok", data.enabled);

  document.querySelector("#telemetry-service").textContent = data.service_name;
  document.querySelector("#telemetry-request-id").textContent = data.request_id || "Unavailable";
  document.querySelector("#telemetry-trace-id").textContent = data.trace_id || "Enable OTLP export to create one";
  document.querySelector("#telemetry-result").hidden = false;

  return {
    ...data,
    hint: data.enabled
      ? "The batch exporter may take a few seconds before this trace appears in Jaeger."
      : "Set OTEL_EXPORTER_OTLP_ENDPOINT and restart Luxor to export traces.",
  };
}));

async function initialize() {
  try {
    const runtime = await api("/api/runtime", {}, false);
    setRuntime(runtime);
    if (standaloneMode) {
      setIdentity(null);
      show("Runtime", {
        ...runtime,
        note: "Data is kept in memory and is cleared when Luxor stops.",
      });
      return;
    }

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
