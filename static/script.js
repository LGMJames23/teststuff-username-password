const qs = (id) => document.getElementById(id);

async function postJSON(url, body) {
  const res = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
    credentials: "same-origin"
  });

  return res.json()
    .then((j) => ({ ok: res.ok, status: res.status, json: j }))
    .catch(() => ({ ok: res.ok, status: res.status, json: null }));
}

qs("regBtn").addEventListener("click", async () => {
  const username = qs("regUsername").value.trim();
  const name = qs("regName").value.trim();
  const password = qs("regPassword").value;

  const res = await postJSON("/api/register", { username, name, password });

  qs("regStatus").textContent = res.ok
    ? "Registered"
    : (res.json?.error || "Error");
});

qs("loginBtn").addEventListener("click", async () => {
  const username = qs("loginUsername").value.trim();
  const password = qs("loginPassword").value;

  const res = await fetch("/api/login", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ username, password }),
    credentials: "same-origin"
  });

  const json = await res.json().catch(() => null);

  if (res.ok) {
    qs("loginStatus").textContent = "Logged in successfully";
  } else {
    qs("loginStatus").textContent = json?.error || "Login failed";
  }
});

qs("callProtected").addEventListener("click", async () => {
  const res = await fetch("/api/protected", {
    method: "GET",
    credentials: "same-origin"
  });

  const text = await res.json().catch(() => ({}));

  qs("protectedResult").textContent = res.ok
    ? (text.message || "ok")
    : (text.error || "Not authorized");
});
