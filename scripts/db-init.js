const fs = require("fs");
const path = require("path");
const { MongoClient, ServerApiVersion } = require("mongodb");

function readEnvFile(envPath) {
  const content = fs.readFileSync(envPath, "utf8");
  const lines = content.split(/\r?\n/);
  const map = new Map();

  for (const rawLine of lines) {
    const line = rawLine.trim();
    if (!line || line.startsWith("#")) continue;
    const eq = line.indexOf("=");
    if (eq < 0) continue;
    const key = line.slice(0, eq).trim();
    let value = line.slice(eq + 1).trim();
    if (
      (value.startsWith('"') && value.endsWith('"')) ||
      (value.startsWith("'") && value.endsWith("'"))
    ) {
      value = value.slice(1, -1);
    }
    map.set(key, value);
  }

  return map;
}

(async () => {
  const envPath = path.join(process.cwd(), ".env");
  if (!fs.existsSync(envPath)) {
    console.error(".env not found");
    process.exit(2);
  }

  const env = readEnvFile(envPath);
  const uri = env.get("MONGODB_URI");
  const dbName = env.get("DB_NAME") || "photo_grabber";
  const maxAttempts = Number(env.get("DB_INIT_RETRIES") || 10);
  const retryMs = Number(env.get("DB_INIT_RETRY_MS") || 5000);

  if (!uri) {
    console.error("MONGODB_URI missing in .env");
    process.exit(2);
  }

  const client = new MongoClient(uri, {
    serverApi: {
      version: ServerApiVersion.v1,
      strict: true,
      deprecationErrors: true,
    },
  });

  try {
    let lastError;
    for (let attempt = 1; attempt <= maxAttempts; attempt++) {
      try {
        await client.connect();
        await client.db("admin").command({ ping: 1 });

        const db = client.db(dbName);

        // Create collections if missing (ignore if already exists)
        for (const name of ["users", "photos", "sessions"]) {
          const exists = await db.listCollections({ name }, { nameOnly: true }).hasNext();
          if (!exists) {
            await db.createCollection(name);
          }
        }

        // Indexes
        await db.collection("users").createIndex({ username: 1 }, { unique: true });
        await db.collection("photos").createIndex({ userId: 1, uploadedAt: -1 });
        await db.collection("sessions").createIndex({ token: 1 }, { unique: true });
        await db.collection("sessions").createIndex({ expiresAt: 1 }, { expireAfterSeconds: 0 });

        console.log(`DB init ok: ${dbName}`);
        return;
      } catch (err) {
        lastError = err;
        const msg = err?.message ?? String(err);
        console.error(`DB init attempt ${attempt}/${maxAttempts} failed: ${msg}`);
        if (attempt < maxAttempts) {
          await new Promise((r) => setTimeout(r, retryMs));
        }
      }
    }

    throw lastError;
  } catch (err) {
    console.error(JSON.stringify({
      ok: false,
      name: err?.name ?? null,
      code: err?.code ?? null,
      message: err?.message ?? String(err),
    }, null, 2));
    process.exitCode = 1;
  } finally {
    try {
      await client.close();
    } catch {
      // ignore
    }
  }
})();
