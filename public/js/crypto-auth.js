// ── crypto-auth.js  –  Client-side RSA + SHA-256 (Web Crypto API) ──
// Implements the LEFT side of the flowchart:
//   1. Merge username:password
//   2. Generate SHA-256 hash of merged data
//   3. Encrypt hash + merged data with server's RSA public key
//   4. Sign the hash with user's RSA private key (digital signature)

const CryptoAuth = (() => {
  // ── Helpers ────────────────────────────────────────────

  /** Convert ArrayBuffer to Base64 string */
  function ab2b64(buf) {
    return btoa(String.fromCharCode(...new Uint8Array(buf)));
  }

  /** Convert Base64 string to ArrayBuffer */
  function b642ab(b64) {
    const bin = atob(b64);
    const buf = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) buf[i] = bin.charCodeAt(i);
    return buf.buffer;
  }

  /** Convert PEM to ArrayBuffer (strips header/footer) */
  function pem2ab(pem) {
    const b64 = pem.replace(/-----[^-]+-----/g, "").replace(/\s/g, "");
    return b642ab(b64);
  }

  /** Convert ArrayBuffer to PEM with given label */
  function ab2pem(buf, label) {
    const b64 = ab2b64(buf);
    const lines = b64.match(/.{1,64}/g).join("\n");
    return `-----BEGIN ${label}-----\n${lines}\n-----END ${label}-----`;
  }

  /** SHA-256 hash → hex string */
  async function sha256hex(text) {
    const enc = new TextEncoder().encode(text);
    const hash = await crypto.subtle.digest("SHA-256", enc);
    return Array.from(new Uint8Array(hash)).map(b => b.toString(16).padStart(2, "0")).join("");
  }

  // ── Step 2: Merge data and generate hash ───────────────
  async function mergeAndHash(username, password) {
    const mergedData = `${username}:${password}`;
    const hash = await sha256hex(mergedData);
    return { mergedData, hash };
  }

  // ── Fetch server's RSA public key ──────────────────────
  async function getServerPublicKey() {
    const res = await fetch("/api/auth/server-pubkey");
    const data = await res.json();
    const keyData = pem2ab(data.publicKey);
    return crypto.subtle.importKey(
      "spki", keyData,
      { name: "RSA-OAEP", hash: "SHA-256" },
      false, ["encrypt"]
    );
  }

  // ── Step 3: Encrypt merged data + hash with server pubkey (RSA-OAEP) ──
  async function encryptForServer(mergedData, hash) {
    const serverKey = await getServerPublicKey();
    const payload = JSON.stringify({ mergedData, hash });
    const encoded = new TextEncoder().encode(payload);
    const encrypted = await crypto.subtle.encrypt(
      { name: "RSA-OAEP" }, serverKey, encoded
    );
    return ab2b64(encrypted);   // base64 ciphertext
  }

  // ── Generate user RSA key pair (for digital signature) ─
  async function generateUserKeyPair() {
    const keyPair = await crypto.subtle.generateKey(
      { name: "RSASSA-PKCS1-v1_5", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" },
      true, ["sign", "verify"]
    );
    // Export as PEM
    const pubBuf  = await crypto.subtle.exportKey("spki", keyPair.publicKey);
    const privBuf = await crypto.subtle.exportKey("pkcs8", keyPair.privateKey);
    return {
      publicKeyPem:  ab2pem(pubBuf, "PUBLIC KEY"),
      privateKeyPem: ab2pem(privBuf, "PRIVATE KEY"),
      privateKey:    keyPair.privateKey,
    };
  }

  // ── Step 4: Sign the hash with user's private key ──────
  async function signHash(hash, privateKey) {
    const encoded = new TextEncoder().encode(hash);
    const sig = await crypto.subtle.sign(
      { name: "RSASSA-PKCS1-v1_5" }, privateKey, encoded
    );
    return ab2b64(sig);
  }

  // ── Full registration flow (client side) ───────────────
  async function prepareRegistration(username, password, onStep) {
    // Step 2: merge + hash
    onStep("merge");
    const { mergedData, hash } = await mergeAndHash(username, password);

    // Step 3: encrypt for server
    onStep("encrypt");
    const encryptedPayload = await encryptForServer(mergedData, hash);

    // Step 4: generate user key pair + sign
    onStep("sign");
    const keys = await generateUserKeyPair();
    const signature = await signHash(hash, keys.privateKey);

    // Store user's private key in sessionStorage for future logins
    sessionStorage.setItem("userPrivateKey", keys.privateKeyPem);
    sessionStorage.setItem("userPublicKey", keys.publicKeyPem);

    return { encryptedPayload, publicKey: keys.publicKeyPem, signature };
  }

  // ── Full login flow (client side) ──────────────────────
  async function prepareLogin(username, password, onStep) {
    // merge + hash
    onStep("merge");
    const { mergedData, hash } = await mergeAndHash(username, password);

    // encrypt
    onStep("encrypt");
    const encryptedPayload = await encryptForServer(mergedData, hash);

    // sign if we have  stored private key
    let signature = null;
    const privPem = sessionStorage.getItem("userPrivateKey");
    if (privPem) {
      const privBuf = pem2ab(privPem);
      const privKey = await crypto.subtle.importKey(
        "pkcs8", privBuf,
        { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
        false, ["sign"]
      );
      signature = await signHash(hash, privKey);
    }

    return { encryptedPayload, signature };
  }

  return { prepareRegistration, prepareLogin };
})();
