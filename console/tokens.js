// API tokens view. Separate file so the console core stays small.
(() => {
  const key = "eg.session";
  const el = (id) => document.getElementById(id);

  async function sessionId() {
    let sid = sessionStorage.getItem(key) || "";
    if (sid) return sid;
    const made = await fetch("/v1/sessions", { method: "POST" }).then((r) => r.json());
    sid = made.session_id || "";
    sessionStorage.setItem(key, sid);
    return sid;
  }

  async function call(method, path, body) {
    const headers = { "x-eg-session": await sessionId() };
    const options = { method, headers };
    if (body !== undefined) {
      headers["content-type"] = "application/json";
      options.body = JSON.stringify(body);
    }
    const response = await fetch(path, options);
    const data = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(data.error || "request failed");
    return data;
  }

  function when(unix) {
    return unix ? new Date(unix * 1000).toLocaleString() : "never";
  }

  async function refresh() {
    const list = el("token-list");
    if (!list) return;
    try {
      const { tokens } = await call("GET", "/v1/tokens");
      list.replaceChildren();
      if (!tokens.length) {
        const empty = document.createElement("p");
        empty.textContent = "No tokens yet.";
        list.append(empty);
      }
      tokens.forEach((token) => {
        const card = document.createElement("article");
        card.className = "glass";
        card.dataset.testid = "token-row";
        const title = document.createElement("h2");
        title.textContent = `${token.name} (${token.prefix}…)`;
        const meta = document.createElement("p");
        meta.textContent = `Scopes: ${token.scopes.join(", ")} · expires ${when(token.expires_unix)} · last used ${when(token.last_used_unix)}`;
        const revoke = document.createElement("button");
        revoke.className = "btn";
        revoke.type = "button";
        revoke.textContent = "Revoke";
        revoke.addEventListener("click", async () => {
          await call("DELETE", `/v1/tokens/${encodeURIComponent(token.id)}`);
          el("token-status").textContent = `Revoked ${token.name}.`;
          refresh();
        });
        card.append(title, meta, revoke);
        list.append(card);
      });
    } catch (error) {
      el("token-status").textContent = error.message;
    }
  }

  el("token-form")?.addEventListener("submit", async (event) => {
    event.preventDefault();
    const scopes = [...document.querySelectorAll("#token-scopes input:checked")].map((box) => box.value);
    try {
      const made = await call("POST", "/v1/tokens", {
        name: el("token-name").value.trim(),
        scopes,
        expires_in_days: Number(el("token-days").value),
      });
      el("token-once").textContent = made.token;
      el("token-status").textContent = `Created ${made.name}. It will not be shown again.`;
      refresh();
    } catch (error) {
      el("token-status").textContent = error.message;
    }
  });

  document.querySelectorAll('[data-nav="tokens"]').forEach((button) => button.addEventListener("click", refresh));
})();
