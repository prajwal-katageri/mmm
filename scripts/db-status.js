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

function safeMongoHost(uri) {
  const match = uri.match(/@([^/?]+)/) || uri.match(/^[A-Za-z0-9+.-]+:\/\/([^/?]+)/);
  return match ? match[1] : "unknown";
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
  const maxAttempts = Number(env.get("DB_STATUS_RETRIES") || 10);
  const retryMs = Number(env.get("DB_STATUS_RETRY_MS") || 3000);

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
        const collections = await db.listCollections({}, { nameOnly: true }).toArray();
        const names = collections.map((c) => c.name).sort();

        console.log(JSON.stringify({
          ok: true,
          mongoHost: safeMongoHost(uri),
          dbName,
          collections: names,
        }, null, 2));

        // Optional: print index names for the core collections (no secrets)
        for (const colName of ["users", "photos", "sessions"]) {
          if (!names.includes(colName)) continue;
          const idx = await db.collection(colName).indexes();
          console.log(`\n[${colName}] indexes:`);
          for (const i of idx) {
            console.log(`- ${i.name} ${JSON.stringify(i.key)}`);
          }
        }

        return;
      } catch (err) {
        lastError = err;
        const msg = err?.message ?? String(err);
        console.error(`DB status attempt ${attempt}/${maxAttempts} failed: ${msg}`);
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
