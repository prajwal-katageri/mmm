// ── Photo Grabber – Camera & Upload Logic ──────────

// ── Auth guard ──────────────────────────────────────
const TOKEN = localStorage.getItem("sessionToken");
if (!TOKEN) { window.location.href = "/login.html"; }
function authHeaders() { return { "x-session-token": TOKEN }; }

const video       = document.getElementById("videoFeed");
const canvas      = document.getElementById("snapshotCanvas");
const btnStart    = document.getElementById("btnStart");
const btnCapture  = document.getElementById("btnCapture");
const btnRetake   = document.getElementById("btnRetake");
const btnUpload   = document.getElementById("btnUpload");
const previewSec  = document.querySelector(".preview-section");
const previewImg  = document.getElementById("previewImg");
const status      = document.getElementById("status");
const fileInput   = document.getElementById("fileInput");
const spinner     = document.getElementById("spinner");
const totalPhotosEl = document.getElementById("totalPhotos");
const todayPhotosEl = document.getElementById("todayPhotos");

let stream = null;
let capturedBlob = null;
let facingMode = "user";            // front camera default

// ── Fetch & display stats ─────────────────────────────
async function updateStats() {
  try {
    const res  = await fetch("/api/photos", { headers: authHeaders() });
    const data = await res.json();
    if (totalPhotosEl) totalPhotosEl.textContent = data.total || 0;
    if (todayPhotosEl) {
      const today = new Date().toDateString();
      const todayCount = (data.photos || []).filter(p => new Date(p.date).toDateString() === today).length;
      todayPhotosEl.textContent = todayCount;
    }
  } catch { /* silent */ }
}
updateStats();

// ── Step 1 & 2: Auto-request Camera Permission on page load ──
// Browser will show the permission prompt automatically
window.addEventListener("DOMContentLoaded", () => {
  startCamera();
});

btnStart.addEventListener("click", () => {
  facingMode = facingMode === "user" ? "environment" : "user";
  startCamera();
});

async function startCamera() {
  try {
    if (stream) stopCamera();

    stream = await navigator.mediaDevices.getUserMedia({
      video: { facingMode, width: { ideal: 1280 }, height: { ideal: 720 } },
      audio: false,
    });

    video.srcObject = stream;
    btnStart.textContent = "🔄 Switch Camera";
    btnCapture.disabled = false;
    showStatus("Camera ready — smile! 📸", "info");
  } catch (err) {
    showStatus("⚠️ Camera access denied or unavailable: " + err.message, "error");
  }
}

// (Switch camera is now handled by single-click on Start/Switch button above)

// ── Step 3: Capture Photo ──────────────────────────────
btnCapture.addEventListener("click", () => {
  if (!stream) return;

  canvas.width  = video.videoWidth;
  canvas.height = video.videoHeight;
  canvas.getContext("2d").drawImage(video, 0, 0);

  canvas.toBlob((blob) => {
    capturedBlob = blob;
    previewImg.src = URL.createObjectURL(blob);
    previewSec.style.display = "block";
    btnRetake.style.display  = "inline-block";
    btnUpload.style.display  = "inline-block";
    btnCapture.disabled      = true;
    showStatus("Photo captured! Review and upload.", "success");
  }, "image/jpeg", 0.92);
});

// Retake
btnRetake.addEventListener("click", () => {
  capturedBlob = null;
  previewSec.style.display = "none";
  btnRetake.style.display  = "none";
  btnUpload.style.display  = "none";
  btnCapture.disabled      = false;
  status.className = "status-msg";
});

// ── Step 4: Upload to Server (POST multipart) ─────────
btnUpload.addEventListener("click", () => uploadBlob(capturedBlob));

async function uploadBlob(blob) {
  if (!blob) return;
  const fd = new FormData();
  fd.append("photo", blob, `capture_${Date.now()}.jpg`);

  showStatus("Uploading…", "info");
  if (spinner) spinner.style.display = "block";
  try {
    const res  = await fetch("/api/upload", { method: "POST", headers: authHeaders(), body: fd });
    const data = await res.json();

    if (data.success) {
      showStatus(`✅ Uploaded! <a href="/gallery.html">View in Gallery</a>`, "success");
      btnRetake.click();                       // reset to camera
      updateStats();
    } else {
      showStatus("Upload failed: " + (data.error || "Unknown error"), "error");
    }
  } catch (err) {
    showStatus("Network error: " + err.message, "error");
  } finally {
    if (spinner) spinner.style.display = "none";
  }
}

// ── Alternative: File input upload ─────────────────────
fileInput.addEventListener("change", async (e) => {
  const file = e.target.files[0];
  if (!file) return;

  const fd = new FormData();
  fd.append("photo", file);

  showStatus("Uploading file…", "info");
  try {
    const res  = await fetch("/api/upload", { method: "POST", headers: authHeaders(), body: fd });
    const data = await res.json();

    if (data.success) {
      showStatus(`✅ File uploaded! <a href="/gallery.html">View in Gallery</a>`, "success");
      updateStats();
    } else {
      showStatus("Upload failed: " + (data.error || "Unknown error"), "error");
    }
  } catch (err) {
    showStatus("Network error: " + err.message, "error");
  }
  fileInput.value = "";
});

// ── Helpers ────────────────────────────────────────────
function showStatus(msg, type) {
  status.innerHTML   = msg;
  status.className   = "status-msg " + type;
}

function stopCamera() {
  if (stream) stream.getTracks().forEach((t) => t.stop());
  stream = null;
}

window.addEventListener("beforeunload", stopCamera);
