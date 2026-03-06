// ── Photo Grabber – Gallery Logic ──────────────────────

// Auth guard
const TOKEN = localStorage.getItem("sessionToken");
if (!TOKEN) { window.location.href = "/login.html"; }
function authHeaders() { return { "x-session-token": TOKEN }; }

function handleUnauthorized() {
  localStorage.removeItem("sessionToken");
  localStorage.removeItem("username");
  window.location.href = "/login.html";
}

// Since protected images require auth headers, we load them as blobs and
// attach via object URLs.
const objectUrls = new Set();
function trackObjectUrl(url) {
  objectUrls.add(url);
  return url;
}
function revokeAllObjectUrls() {
  for (const url of objectUrls) URL.revokeObjectURL(url);
  objectUrls.clear();
}

async function fetchImageObjectUrl(photoUrl) {
  const res = await fetch(photoUrl, { headers: authHeaders() });
  if (res.status === 401) {
    handleUnauthorized();
    return null;
  }
  if (!res.ok) return null;
  const blob = await res.blob();
  return trackObjectUrl(URL.createObjectURL(blob));
}

const grid       = document.getElementById("galleryGrid");
const emptyMsg   = document.getElementById("emptyMsg");
const countEl    = document.getElementById("photoCount");
const btnRefresh = document.getElementById("btnRefresh");
const btnClearAll= document.getElementById("btnClearAll");

// Lightbox elements
const lightbox     = document.getElementById("lightbox");
const lightboxImg  = document.getElementById("lightboxImg");
const lightboxName = document.getElementById("lightboxName");
const lightboxDl   = document.getElementById("lightboxDownload");
const lightboxDel  = document.getElementById("lightboxDelete");
const lightboxClose= document.getElementById("lightboxClose");

// ── Load photos from server (Step 7) ──────────────────
async function loadPhotos() {
  countEl.textContent = "Loading…";
  grid.innerHTML = "";
  revokeAllObjectUrls();

  try {
    const res  = await fetch("/api/photos", { headers: authHeaders() });
    if (res.status === 401) return handleUnauthorized();
    const data = await res.json();

    if (!data.photos || !data.photos.length) {
      emptyMsg.style.display = "block";
      countEl.textContent    = "0 photos";
      return;
    }

    emptyMsg.style.display = "none";
    countEl.textContent    = `${data.total} photo${data.total !== 1 ? "s" : ""}`;

    data.photos.forEach(async (photo) => {
      const card = document.createElement("div");
      card.className = "gallery-card";

      const img = document.createElement("img");
      img.alt = photo.filename;
      img.loading = "lazy";
      img.decoding = "async";
      card.appendChild(img);

      const delBtn = document.createElement("button");
      delBtn.className = "card-delete-btn";
      delBtn.dataset.id = photo.id;
      delBtn.title = "Delete";
      delBtn.innerHTML = "&times;";
      card.appendChild(delBtn);

      const meta = document.createElement("div");
      meta.className = "card-meta";
      meta.textContent = new Date(photo.date).toLocaleString();
      card.appendChild(meta);

      const objectUrl = await fetchImageObjectUrl(photo.url);
      if (objectUrl) img.src = objectUrl;

      delBtn.addEventListener("click", async (e) => {
        e.stopPropagation();
        if (!confirm(`Delete ${photo.filename}?`)) return;
        try {
          const r = await fetch(`/api/photos/${photo.id}`, { method: "DELETE", headers: authHeaders() });
          if (r.status === 401) return handleUnauthorized();
          const d = await r.json();
          if (d.success) loadPhotos();
        } catch (err) { alert("Delete failed: " + err.message); }
      });
      card.addEventListener("click", () => openLightbox(photo));
      grid.appendChild(card);
    });
    emptyMsg.style.display = "none";
  } catch (err) {
    countEl.textContent = "Error loading photos";
    console.error(err);
  }
}

// ── Lightbox ───────────────────────────────────────────
function openLightbox(photo) {
  lightboxImg.src          = "";
  lightboxName.textContent = photo.filename;
  lightboxDl.removeAttribute("href");
  lightboxDl.download      = photo.filename;
  lightbox.style.display   = "flex";
  lightbox.dataset.id       = photo.id;       // MongoDB _id
  lightbox.dataset.filename = photo.filename;

  fetchImageObjectUrl(photo.url).then((objectUrl) => {
    if (!objectUrl) return;
    if (lightbox.style.display !== "flex") return;
    lightboxImg.src = objectUrl;
    lightboxDl.href = objectUrl;
  });
}

lightboxClose.addEventListener("click", () => { lightbox.style.display = "none"; });
lightbox.addEventListener("click", (e) => { if (e.target === lightbox) lightbox.style.display = "none"; });

// Delete photo
lightboxDel.addEventListener("click", async () => {
  const photoId  = lightbox.dataset.id;
  const filename = lightbox.dataset.filename;
  if (!confirm(`Delete ${filename}?`)) return;

  try {
    const res = await fetch(`/api/photos/${photoId}`, { method: "DELETE", headers: authHeaders() });
    if (res.status === 401) return handleUnauthorized();
    const data = await res.json();
    if (data.success) {
      lightbox.style.display = "none";
      loadPhotos();
    }
  } catch (err) {
    alert("Delete failed: " + err.message);
  }
});

// Keyboard: Escape closes lightbox
document.addEventListener("keydown", (e) => {
  if (e.key === "Escape") lightbox.style.display = "none";
});

// ── Init ───────────────────────────────────────────────
btnRefresh.addEventListener("click", loadPhotos);
// Clear All Photos
btnClearAll.addEventListener("click", async () => {
  if (!confirm("Are you sure you want to delete ALL photos?")) return;
  try {
    const res = await fetch("/api/photos", { method: "DELETE", headers: authHeaders() });
    if (res.status === 401) return handleUnauthorized();
    const data = await res.json();
    if (!data.success) throw new Error(data.error || "Clear failed");
    loadPhotos();
  } catch (err) {
    alert("Clear all failed: " + err.message);
  }
});
loadPhotos();

window.addEventListener("beforeunload", revokeAllObjectUrls);
