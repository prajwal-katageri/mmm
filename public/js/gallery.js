// ── Photo Grabber – Gallery Logic ──────────────────────

// Auth guard
const TOKEN = localStorage.getItem("sessionToken");
if (!TOKEN) { window.location.href = "/login.html"; }
function authHeaders() { return { "x-session-token": TOKEN }; }

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

  try {
    const res  = await fetch("/api/photos", { headers: authHeaders() });
    const data = await res.json();

    if (!data.photos.length) {
      emptyMsg.style.display = "block";
      countEl.textContent    = "0 photos";
      return;
    }

    emptyMsg.style.display = "none";
    countEl.textContent    = `${data.total} photo${data.total !== 1 ? "s" : ""}`;

    data.photos.forEach((photo) => {
      const card = document.createElement("div");
      card.className = "gallery-card";
      card.innerHTML = `
        <img src="${photo.url}" alt="${photo.filename}" loading="lazy" />
        <button class="card-delete-btn" data-id="${photo.id}" title="Delete">&times;</button>
        <div class="card-meta">${new Date(photo.date).toLocaleString()}</div>
      `;
      card.querySelector(".card-delete-btn").addEventListener("click", async (e) => {
        e.stopPropagation();
        if (!confirm(`Delete ${photo.filename}?`)) return;
        try {
          const r = await fetch(`/api/photos/${photo.id}`, { method: "DELETE", headers: authHeaders() });
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
  lightboxImg.src          = photo.url;
  lightboxName.textContent = photo.filename;
  lightboxDl.href          = photo.url;
  lightboxDl.download      = photo.filename;
  lightbox.style.display   = "flex";
  lightbox.dataset.id       = photo.id;       // MongoDB _id
  lightbox.dataset.filename = photo.filename;
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
    const res  = await fetch("/api/photos", { headers: authHeaders() });
    const data = await res.json();
    if (!data.photos.length) return;
    await Promise.all(
      data.photos.map((p) =>
        fetch(`/api/photos/${p.id}`, { method: "DELETE", headers: authHeaders() })
      )
    );
    loadPhotos();
  } catch (err) {
    alert("Clear all failed: " + err.message);
  }
});
loadPhotos();
