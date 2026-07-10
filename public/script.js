let accessToken = null;

const message = document.querySelector("#message");
const identity = document.querySelector("#identity");
const authDot = document.querySelector("#auth-dot");

function show(label, data) {
  message.textContent = `${label}\n${typeof data === "string" ? data : JSON.stringify(data, null, 2)}`;
}

function setIdentity(user) {
  identity.textContent = user ? user.email : "Signed out";
  authDot.classList.toggle("online", Boolean(user));
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

// A surviving HTTP-only refresh cookie may restore the session after a reload.
refreshAccessToken().then((restored) => {
  if (restored) show("Session", "Restored from the refresh cookie.");
});
