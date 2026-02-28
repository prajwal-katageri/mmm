// ── register.js – Registration page logic ──────────────

const form    = document.getElementById("registerForm");
const stepsEl = document.getElementById("steps");
const statusEl= document.getElementById("status");

function showStep(id, state = "done") {
  const el = document.getElementById(`step-${id}`);
  if (!el) return;
  if (state === "active") el.textContent = el.textContent.replace("⏳", "⏳");
  if (state === "done")   el.textContent = el.textContent.replace("⏳", "✅");
  if (state === "fail")   el.textContent = el.textContent.replace("⏳", "❌");
}

function showStatus(msg, type) {
  statusEl.innerHTML = msg;
  statusEl.className = "status-msg " + type;
}

form.addEventListener("submit", async (e) => {
  e.preventDefault();

  const username = document.getElementById("username").value.trim();
  const password = document.getElementById("password").value;
  const confirm  = document.getElementById("confirmPassword").value;

  if (password !== confirm) {
    showStatus("Passwords do not match", "error");
    return;
  }

  stepsEl.classList.remove("hidden");
  document.getElementById("btnRegister").disabled = true;

  try {
    // Client-side flowchart steps 2-4
    const payload = await CryptoAuth.prepareRegistration(username, password, (step) => {
      showStep(step);
    });

    // Step 5: Send to cloud
    showStep("send");
    const res = await fetch("/api/auth/register", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });

    const data = await res.json();
    showStep("result");

    if (data.success) {
      showStep("result", "done");
      showStatus('✅ Account created! <a href="/login.html">Login now</a>', "success");
    } else {
      showStep("result", "fail");
      // Map server step to UI step for the "NO" path (go back)
      if (data.step === "decrypt")           showStep("send", "fail");
      if (data.step === "verify-credentials")showStep("result", "fail");
      if (data.step === "verify-signature")  showStep("result", "fail");
      showStatus("❌ " + data.error, "error");
    }
  } catch (err) {
    showStatus("Network error: " + err.message, "error");
  } finally {
    document.getElementById("btnRegister").disabled = false;
  }
});
