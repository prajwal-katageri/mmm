const express = require("express");
const multer = require("multer");
const cors = require("cors");
const path = require("path");
const crypto = require("crypto");
const { MongoClient, ObjectId, Binary } = require("mongodb");

const app = express();
const PORT = process.env.PORT || 3500;

// ── MongoDB config ─────────────────────────────────────
const MONGO_URI = process.env.MONGODB_URI || "mongodb://localhost:27017";
const DB_NAME = process.env.DB_NAME || "photo_grabber";
const PHOTO_COL = "photos";
const USER_COL = "users";
const SESSION_COL = "sessions";

let db, photosCol, usersCol, sessionsCol;

async function connectMongo() {
  const client = new MongoClient(MONGO_URI);
  await client.connect();
  db = client.db(DB_NAME);
  photosCol = db.collection(PHOTO_COL);
  usersCol = db.collection(USER_COL);
  sessionsCol = db.collection(SESSION_COL);
  // Unique index on username
  await usersCol.createIndex({ username: 1 }, { unique: true });
  console.log(`✔ Connected to MongoDB → ${DB_NAME}`);
}

// ── Server RSA key pair (cloud keys) ───────────────────────
// Generated once at startup; in production store persistently
const { publicKey: serverPubKey, privateKey: serverPrivKey } =
  crypto.generateKeyPairSync("rsa", {
    modulusLength: 2048,
    publicKeyEncoding:  { type: "spki",  format: "pem" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
  });

// ── Middleware ──────────────────────────────────────────────
app.use(cors());
app.use(express.json({ limit: "10mb" }));
app.use(express.static(path.join(__dirname, "public")));

// ── Auth middleware ─────────────────────────────────────────
async function requireAuth(req, res, next) {
  const token = req.headers["x-session-token"];
  if (!token) return res.status(401).json({ error: "Not authenticated" });
  const session = await sessionsCol.findOne({ token, expiresAt: { $gt: new Date() } });
  if (!session) return res.status(401).json({ error: "Session expired or invalid" });
  req.userId = session.userId;
  req.username = session.username;
  next();
}

// ════════════════════════════════════════════════════════════
//  AUTH ROUTES  –  implements the flowchart exactly
// ════════════════════════════════════════════════════════════

// GET /api/auth/server-pubkey  –  client needs this to encrypt data for cloud
app.get("/api/auth/server-pubkey", (_req, res) => {
  res.json({ publicKey: serverPubKey });
});

/*
  POST /api/auth/register
  Client sends:
  {
    encryptedPayload: <base64>,   // RSA-encrypted (with server pub key) JSON of {mergedData, hash}
    publicKey: <PEM>,             // user's RSA public key
    signature: <base64>           // hash signed with user's private key (digital signature)
  }

  Flowchart steps on server (cloud):
  1. Cloud receives and Decrypts data           → decrypt encryptedPayload with server private key
  2. If data successfully Decrypted?             → YES / NO
  3. Verify username and Password?               → check mergedData parses, username not taken
  4. Verify Digital Signature?                   → verify signature using user's public key
  5. Create Account                              → store in MongoDB
*/
app.post("/api/auth/register", async (req, res) => {
  try {
    const { encryptedPayload, publicKey: userPubKeyPem, signature } = req.body;

    if (!encryptedPayload || !userPubKeyPem || !signature) {
      return res.status(400).json({ error: "Missing fields", step: "input" });
    }

    // ── Step 6: Cloud receives and Decrypts data ───────────
    let decrypted;
    try {
      decrypted = crypto.privateDecrypt(
        { key: serverPrivKey, padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
          oaepHash: "sha256" },
        Buffer.from(encryptedPayload, "base64")
      );
    } catch {
      // Step 7 decision: Decryption failed → NO
      return res.status(400).json({ error: "Decryption failed – invalid payload", step: "decrypt" });
    }

    // Step 7 decision: YES – parse merged data
    let mergedData, clientHash;
    try {
      const parsed = JSON.parse(decrypted.toString("utf8"));
      mergedData = parsed.mergedData;   // "username:password"
      clientHash = parsed.hash;         // SHA-256 hex of mergedData
    } catch {
      return res.status(400).json({ error: "Decrypted data is malformed", step: "decrypt" });
    }

    // ── Step 8: Verify username and Password? ──────────────
    const parts = mergedData.split(":");
    if (parts.length < 2 || !parts[0] || !parts[1]) {
      // NO → ask to re-enter
      return res.status(400).json({ error: "Invalid username or password format", step: "verify-credentials" });
    }
    const username = parts[0];
    const password = parts.slice(1).join(":");   // in case password has ':'

    // Verify the hash matches merged data
    const expectedHash = crypto.createHash("sha256").update(mergedData).digest("hex");
    if (expectedHash !== clientHash) {
      return res.status(400).json({ error: "Hash mismatch – data integrity check failed", step: "verify-credentials" });
    }

    // Check username not already taken
    const existing = await usersCol.findOne({ username });
    if (existing) {
      return res.status(409).json({ error: "Username already exists", step: "verify-credentials" });
    }

    // ── Step 9: Verify Digital Signature? ──────────────────
    try {
      const verifier = crypto.createVerify("SHA256");
      verifier.update(clientHash);         // signature was over the hash
      const sigValid = verifier.verify(userPubKeyPem, Buffer.from(signature, "base64"));
      if (!sigValid) {
        // NO → ask to re-enter
        return res.status(400).json({ error: "Digital signature verification failed", step: "verify-signature" });
      }
    } catch {
      return res.status(400).json({ error: "Digital signature verification error", step: "verify-signature" });
    }

    // ── Step 10: Create Account ────────────────────────────
    // Store salted-hashed password (never plain text)
    const salt = crypto.randomBytes(16).toString("hex");
    const hashedPassword = crypto.scryptSync(password, salt, 64).toString("hex");

    const userDoc = {
      username,
      passwordHash: hashedPassword,
      salt,
      publicKey: userPubKeyPem,
      createdAt: new Date(),
    };

    await usersCol.insertOne(userDoc);
    console.log(`✔ Account created: ${username}`);
    res.json({ success: true, message: "Account created successfully" });

  } catch (err) {
    console.error("Register error:", err);
    res.status(500).json({ error: "Server error during registration" });
  }
});

/*
  POST /api/auth/login
  Same encrypted flow but returns a session token.
*/
app.post("/api/auth/login", async (req, res) => {
  try {
    const { encryptedPayload, signature } = req.body;

    if (!encryptedPayload) {
      return res.status(400).json({ error: "Missing encrypted payload" });
    }

    // Decrypt
    let decrypted;
    try {
      decrypted = crypto.privateDecrypt(
        { key: serverPrivKey, padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
          oaepHash: "sha256" },
        Buffer.from(encryptedPayload, "base64")
      );
    } catch {
      return res.status(400).json({ error: "Decryption failed", step: "decrypt" });
    }

    let mergedData, clientHash;
    try {
      const parsed = JSON.parse(decrypted.toString("utf8"));
      mergedData = parsed.mergedData;
      clientHash = parsed.hash;
    } catch {
      return res.status(400).json({ error: "Malformed payload", step: "decrypt" });
    }

    const parts = mergedData.split(":");
    const username = parts[0];
    const password = parts.slice(1).join(":");

    // Verify hash
    const expectedHash = crypto.createHash("sha256").update(mergedData).digest("hex");
    if (expectedHash !== clientHash) {
      return res.status(400).json({ error: "Hash mismatch", step: "verify-credentials" });
    }

    // Find user
    const user = await usersCol.findOne({ username });
    if (!user) {
      return res.status(401).json({ error: "Invalid username or password", step: "verify-credentials" });
    }

    // Verify password
    const testHash = crypto.scryptSync(password, user.salt, 64).toString("hex");
    if (testHash !== user.passwordHash) {
      return res.status(401).json({ error: "Invalid username or password", step: "verify-credentials" });
    }

    // Verify digital signature (if provided)
    if (signature) {
      try {
        const verifier = crypto.createVerify("SHA256");
        verifier.update(clientHash);
        const sigValid = verifier.verify(user.publicKey, Buffer.from(signature, "base64"));
        if (!sigValid) {
          return res.status(400).json({ error: "Digital signature failed", step: "verify-signature" });
        }
      } catch {
        return res.status(400).json({ error: "Signature verification error", step: "verify-signature" });
      }
    }

    // Create session
    const token = crypto.randomBytes(32).toString("hex");
    await sessionsCol.insertOne({
      token,
      userId: user._id,
      username: user.username,
      createdAt: new Date(),
      expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000), // 24 hours
    });

    console.log(`✔ Login: ${username}`);
    res.json({ success: true, token, username });

  } catch (err) {
    console.error("Login error:", err);
    res.status(500).json({ error: "Server error during login" });
  }
});

// GET /api/auth/me  –  check current session
app.get("/api/auth/me", requireAuth, (req, res) => {
  res.json({ username: req.username });
});

// POST /api/auth/logout
app.post("/api/auth/logout", requireAuth, async (req, res) => {
  await sessionsCol.deleteOne({ token: req.headers["x-session-token"] });
  res.json({ success: true });
});

// Multer stores in memory (we push to MongoDB, not disk)
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 10 * 1024 * 1024 }, // 10 MB
  fileFilter: (_req, file, cb) => {
    if (file.mimetype.startsWith("image/")) cb(null, true);
    else cb(new Error("Only image files are allowed"));
  },
});

// ── Routes ─────────────────────────────────────────────────

// POST /api/upload  –  receive image via multipart form data → MongoDB
app.post("/api/upload", requireAuth, upload.single("photo"), async (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ error: "No image received" });

    const filename = `photo_${Date.now()}_${Math.round(Math.random() * 1e4)}${path.extname(req.file.originalname) || ".jpg"}`;

    const doc = {
      filename,
      contentType: req.file.mimetype,
      size: req.file.size,
      data: new Binary(req.file.buffer),     // store binary in MongoDB
      uploadedBy: req.username,
      userId: req.userId,
      uploadedAt: new Date(),
    };

    const result = await photosCol.insertOne(doc);
    console.log(`✔ Image saved to MongoDB: ${filename} (${result.insertedId})`);
    res.json({ success: true, id: result.insertedId, filename });
  } catch (err) {
    console.error("Upload error:", err);
    res.status(500).json({ error: "Server error during upload" });
  }
});

// POST /api/upload-base64  –  receive image as Base64 string → MongoDB
app.post("/api/upload-base64", requireAuth, async (req, res) => {
  try {
    const { image } = req.body;
    if (!image) return res.status(400).json({ error: "No image data" });

    const matches = image.match(/^data:image\/(\w+);base64,(.+)$/);
    if (!matches) return res.status(400).json({ error: "Invalid Base64 image" });

    const ext = matches[1];
    const buffer = Buffer.from(matches[2], "base64");
    const filename = `photo_${Date.now()}_${Math.round(Math.random() * 1e4)}.${ext}`;

    const doc = {
      filename,
      contentType: `image/${ext}`,
      size: buffer.length,
      data: new Binary(buffer),
      uploadedBy: req.username,
      userId: req.userId,
      uploadedAt: new Date(),
    };

    const result = await photosCol.insertOne(doc);
    console.log(`✔ Image saved to MongoDB (base64): ${filename}`);
    res.json({ success: true, id: result.insertedId, filename });
  } catch (err) {
    console.error("Upload error:", err);
    res.status(500).json({ error: "Server error during upload" });
  }
});

// GET /api/photos  –  list all stored photos (metadata only, no binary)
app.get("/api/photos", requireAuth, async (_req, res) => {
  try {
    const photos = await photosCol
      .find({}, { projection: { data: 0 } })       // exclude heavy binary
      .sort({ uploadedAt: -1 })
      .toArray();

    const mapped = photos.map((p) => ({
      id: p._id,
      filename: p.filename,
      contentType: p.contentType,
      size: p.size,
      uploadedBy: p.uploadedBy || "unknown",
      url: `/api/photos/${p._id}/image`,            // serve via route below
      date: p.uploadedAt,
    }));

    res.json({ photos: mapped, total: mapped.length });
  } catch (err) {
    console.error("List error:", err);
    res.status(500).json({ error: "Failed to list photos" });
  }
});

// GET /api/photos/:id/image  –  serve actual image binary from MongoDB
app.get("/api/photos/:id/image", async (req, res) => {
  try {
    const doc = await photosCol.findOne({ _id: new ObjectId(req.params.id) });
    if (!doc) return res.status(404).json({ error: "Not found" });

    res.set("Content-Type", doc.contentType);
    res.set("Content-Disposition", `inline; filename="${doc.filename}"`);
    res.send(doc.data.buffer);
  } catch (err) {
    res.status(500).json({ error: "Failed to serve image" });
  }
});

// DELETE /api/photos/:id  –  remove a photo from MongoDB
app.delete("/api/photos/:id", requireAuth, async (req, res) => {
  try {
    const result = await photosCol.deleteOne({ _id: new ObjectId(req.params.id) });
    if (result.deletedCount === 0) return res.status(404).json({ error: "Not found" });
    console.log(`✖ Deleted: ${req.params.id}`);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: "Failed to delete" });
  }
});

// ── Start server (after MongoDB connects) ──────────────────
connectMongo().then(() => {
  app.listen(PORT, () => {
    console.log(`\n🚀  Photo Grabber running at  http://localhost:${PORT}`);
    console.log(`📷  Capture:  http://localhost:${PORT}/`);
    console.log(`🖼️  Gallery:  http://localhost:${PORT}/gallery.html`);
    console.log(`🗄️  MongoDB:  ${MONGO_URI}/${DB_NAME}\n`);
  });
}).catch((err) => {
  console.error("❌ Failed to connect to MongoDB:", err.message);
  process.exit(1);
});
