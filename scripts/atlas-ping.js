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

function sanitizeError(err) {
  return {
    name: err?.name ?? null,
    code: err?.code ?? null,
    message: err?.message ?? String(err),
    cause: err?.cause?.message ?? null,
  };
}

(async () => {
  const envPath = path.join(process.cwd(), ".env");
  if (!fs.existsSync(envPath)) {
    console.error(".env not found in current directory");
    process.exit(2);
  }

  const env = readEnvFile(envPath);
  const uri = env.get("MONGODB_URI");

  if (!uri) {
    console.error("MONGODB_URI not found in .env");
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
    await client.connect();
    await client.db("admin").command({ ping: 1 });
    console.log("Atlas ping ok");
  } catch (err) {
    console.log(JSON.stringify(sanitizeError(err), null, 2));
    process.exitCode = 1;
  } finally {
    try {
      await client.close();
    } catch {
      // ignore
    }
  }
})();
