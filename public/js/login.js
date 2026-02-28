// ── login.js – Login page logic ────────────────────────

const form     = document.getElementById("loginForm");
const stepsEl  = document.getElementById("steps");
const statusEl = document.getElementById("status");

function showStep(id, state = "done") {
  const el = document.getElementById(`step-${id}`);
  if (!el) return;
  if (state === "done") el.textContent = el.textContent.replace("⏳", "✅");
  if (state === "fail") el.textContent = el.textContent.replace("⏳", "❌");
}

function showStatus(msg, type) {
  statusEl.innerHTML = msg;
  statusEl.className = "status-msg " + type;
}

form.addEventListener("submit", async (e) => {
  e.preventDefault();

  const username = document.getElementById("username").value.trim();
  const password = document.getElementById("password").value;

  stepsEl.classList.remove("hidden");
  document.getElementById("btnLogin").disabled = true;

  try {
    const payload = await CryptoAuth.prepareLogin(username, password, (step) => {
      showStep(step);
    });

    showStep("send");
    const res = await fetch("/api/auth/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });

    const data = await res.json();
    showStep("result");

    if (data.success) {
      showStep("result", "done");
      // Store session token
      localStorage.setItem("sessionToken", data.token);
      localStorage.setItem("username", data.username);
      showStatus("✅ Login successful! Redirecting…", "success");
      setTimeout(() => { window.location.href = "/"; }, 1000);
    } else {
      showStep("result", "fail");
      showStatus("❌ " + data.error, "error");
    }
  } catch (err) {
    showStatus("Network error: " + err.message, "error");
  } finally {
    document.getElementById("btnLogin").disabled = false;
  }
});
