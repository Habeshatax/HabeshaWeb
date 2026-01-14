// server.js (FULL FILE - copy/paste)

import express from "express";
import fs from "fs";
import path from "path";
import os from "os";
import cors from "cors";
import jwt from "jsonwebtoken";
import { fileURLToPath } from "url";

const app = express();

// ----- ESM __dirname fix -----
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// ----- Middleware -----
app.use(express.json({ limit: "25mb" }));

// ----- CORS -----
const ALLOWED_ORIGINS = (process.env.ALLOWED_ORIGINS || "")
  .split(",")
  .map((s) => s.trim())
  .filter(Boolean);

const corsOptions = {
  origin: (origin, cb) => {
    if (!origin) return cb(null, true);
    if (ALLOWED_ORIGINS.length === 0) return cb(null, true);
    if (ALLOWED_ORIGINS.includes(origin)) return cb(null, true);
    return cb(new Error("CORS blocked for origin: " + origin));
  },
  credentials: true,
  methods: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization"],
  maxAge: 86400,
};

app.use(cors(corsOptions));
app.options("*", cors(corsOptions));

// ----- Config -----
const PORT = process.env.PORT || 8787;

// Optional legacy static token support
const AUTH_TOKEN = (process.env.AUTH_TOKEN || "").trim();

// Admin credentials
const ADMIN_EMAIL = (process.env.ADMIN_EMAIL || "").trim().toLowerCase();
const ADMIN_PASSWORD = (process.env.ADMIN_PASSWORD || "").trim();

// (Legacy single client fallback)
const CLIENT_EMAIL = (process.env.CLIENT_EMAIL || "").trim().toLowerCase();
const CLIENT_PASSWORD = (process.env.CLIENT_PASSWORD || "").trim();
const CLIENT_NAME = (process.env.CLIENT_NAME || "").trim();

// ✅ New: multiple client users via JSON
// Example:
// CLIENT_USERS_JSON=[{"email":"a@x.com","password":"123","client":"Client A"},{"email":"b@x.com","password":"456","client":"Client B"}]
const CLIENT_USERS_JSON = (process.env.CLIENT_USERS_JSON || "").trim();

// JWT secret
const JWT_SECRET = (process.env.JWT_SECRET || "").trim();

const BASE_DIR =
  process.env.BASE_DIR ||
  (process.env.RENDER ? "/tmp/habesha" : path.join(os.homedir(), "Documents", "Habesha"));

const CLIENTS_DIR = path.join(BASE_DIR, "clients");

// ----- Helpers -----
function ensureDir(p) {
  if (!fs.existsSync(p)) fs.mkdirSync(p, { recursive: true });
}

function safeName(input) {
  return String(input || "")
    .trim()
    .replace(/[^a-zA-Z0-9._ -]/g, "_")
    .replace(/\s+/g, " ")
    .slice(0, 120);
}

function resolveInside(base, target) {
  const baseResolved = path.resolve(base);
  const full = path.resolve(baseResolved, target);
  if (!full.startsWith(baseResolved + path.sep) && full !== baseResolved) {
    throw new Error("Invalid path");
  }
  return full;
}

function getBearer(req) {
  const auth = req.headers.authorization || "";
  if (auth.toLowerCase().startsWith("bearer ")) return auth.slice(7).trim();
  return "";
}

function verifyJwtToken(token) {
  if (!JWT_SECRET) return null;
  try {
    return jwt.verify(token, JWT_SECRET);
  } catch {
    return null;
  }
}

function normalizeRelPath(p) {
  const raw = String(p || "").trim();
  if (!raw) return "";

  const cleaned = raw.replace(/\\/g, "/").replace(/^\/+/, "");
  const decoded = decodeURIComponent(cleaned);

  if (decoded.includes("..")) throw new Error("Invalid path");
  if (decoded.includes("\0")) throw new Error("Invalid path");

  return decoded.replace(/\/{2,}/g, "/");
}

// ✅ Recursive copy (folder fallback)
function copyRecursiveSync(src, dest) {
  const stat = fs.statSync(src);

  if (stat.isDirectory()) {
    ensureDir(dest);
    for (const entry of fs.readdirSync(src)) {
      copyRecursiveSync(path.join(src, entry), path.join(dest, entry));
    }
    return;
  }

  fs.copyFileSync(src, dest);
}

// ✅ Recursive delete (folder support)
function removeRecursiveSync(target) {
  if (!fs.existsSync(target)) return;
  const stat = fs.statSync(target);

  if (stat.isDirectory()) {
    for (const entry of fs.readdirSync(target)) {
      removeRecursiveSync(path.join(target, entry));
    }
    fs.rmdirSync(target);
    return;
  }

  fs.unlinkSync(target);
}

// --------------------------
// Build client user list
// --------------------------
function parseClientUsers() {
  const users = [];

  // 1) New JSON list
  if (CLIENT_USERS_JSON) {
    try {
      const parsed = JSON.parse(CLIENT_USERS_JSON);
      if (!Array.isArray(parsed)) throw new Error("CLIENT_USERS_JSON must be a JSON array");

      for (const u of parsed) {
        const email = String(u?.email || "").trim().toLowerCase();
        const password = String(u?.password || "").trim();
        const client = String(u?.client || "").trim();

        if (!email || !password || !client) continue;
        users.push({ email, password, client: safeName(client) });
      }
    } catch (e) {
      console.error("❌ Failed to parse CLIENT_USERS_JSON:", e.message);
    }
  }

  // 2) Legacy single-client fallback
  if (CLIENT_EMAIL && CLIENT_PASSWORD && CLIENT_NAME) {
    users.push({
      email: CLIENT_EMAIL,
      password: CLIENT_PASSWORD,
      client: safeName(CLIENT_NAME),
    });
  }

  // de-duplicate by email
  const map = new Map();
  for (const u of users) map.set(u.email, u);
  return Array.from(map.values());
}

const CLIENT_USERS = parseClientUsers();

// --------------------------
// AUTH middleware
// --------------------------

// Protect only /api routes
function requireAuth(req, res, next) {
  if (!AUTH_TOKEN && !JWT_SECRET) return next();

  const token = getBearer(req);

  // Legacy fixed AUTH_TOKEN
  if (AUTH_TOKEN && token === AUTH_TOKEN) {
    req.user = { id: "legacy", email: "legacy@token", role: "admin" };
    return next();
  }

  const payload = verifyJwtToken(token);
  if (payload) {
    req.user = payload;
    return next();
  }

  return res.status(401).json({ ok: false, error: "Unauthorized" });
}

function requireAdmin(req, res, next) {
  if ((req.user?.role || "") === "admin") return next();
  return res.status(403).json({ ok: false, error: "Forbidden (admin only)" });
}

// Client can only access their own :client folder
function enforceClientMatch(req, res, next) {
  const role = req.user?.role || "admin";
  if (role === "admin") return next();

  const routeClient = safeName(req.params.client || "");
  const tokenClient = safeName(req.user?.client || "");
  if (!routeClient || !tokenClient) return res.status(403).json({ ok: false, error: "Forbidden" });

  if (routeClient !== tokenClient) {
    return res.status(403).json({ ok: false, error: "Forbidden (client mismatch)" });
  }
  return next();
}

// Client writes allowed only inside these roots
const CLIENT_WRITE_ROOTS = ["05 Downloads", "03 Work"];

function isAllowedClientWrite(rel) {
  const r = normalizeRelPath(rel || "");
  if (!r) return false;
  return CLIENT_WRITE_ROOTS.some((root) => r === root || r.startsWith(root + "/"));
}

function requireWriteAccess(req, res, next) {
  const role = req.user?.role || "admin";
  if (role === "admin") return next();

  const rel = normalizeRelPath(req.query.path || "");
  if (!isAllowedClientWrite(rel)) {
    return res.status(403).json({
      ok: false,
      error: `Forbidden (client can only write inside: ${CLIENT_WRITE_ROOTS.join(", ")})`,
    });
  }
  return next();
}

ensureDir(CLIENTS_DIR);

// ----- Health -----
app.get("/health", (req, res) => res.status(200).send("ok"));

app.get("/api/health", (req, res) =>
  res.status(200).json({
    ok: true,
    service: "habeshaweb",
    baseDir: BASE_DIR,
    clientsDir: CLIENTS_DIR,
    clientUsers: CLIENT_USERS.map((u) => ({ email: u.email, client: u.client })), // safe: no passwords
  })
);

// ----- Home -----
app.get("/", (req, res) => {
  res.status(200).send("HabeshaWeb backend is running. Try /health or /api/health");
});

// ----- Admin Login (PUBLIC) -----
app.post("/login", (req, res) => {
  try {
    const email = String(req.body?.email || "").trim().toLowerCase();
    const password = String(req.body?.password || "").trim();

    if (!ADMIN_EMAIL || !ADMIN_PASSWORD) {
      return res.status(500).json({ ok: false, error: "ADMIN_EMAIL / ADMIN_PASSWORD not set on server" });
    }
    if (email !== ADMIN_EMAIL || password !== ADMIN_PASSWORD) {
      return res.status(401).json({ ok: false, error: "Invalid login" });
    }
    if (!JWT_SECRET) return res.status(500).json({ ok: false, error: "JWT_SECRET not set on server" });

    const user = { id: "admin", email: ADMIN_EMAIL, role: "admin" };
    const token = jwt.sign(user, JWT_SECRET, { expiresIn: "7d" });
    return res.json({ ok: true, token, user });
  } catch (e) {
    return res.status(500).json({ ok: false, error: e.message });
  }
});

// ----- Client Login (PUBLIC) -----
// POST /client-login { email, password }
app.post("/client-login", (req, res) => {
  try {
    const email = String(req.body?.email || "").trim().toLowerCase();
    const password = String(req.body?.password || "").trim();

    if (!JWT_SECRET) return res.status(500).json({ ok: false, error: "JWT_SECRET not set on server" });

    if (!CLIENT_USERS.length) {
      return res.status(500).json({
        ok: false,
        error: "No client users configured. Set CLIENT_USERS_JSON (recommended) or CLIENT_EMAIL/CLIENT_PASSWORD/CLIENT_NAME",
      });
    }

    const match = CLIENT_USERS.find((u) => u.email === email && u.password === password);
    if (!match) return res.status(401).json({ ok: false, error: "Invalid login" });

    // ensure folder exists (best effort)
    const clientFolder = safeName(match.client);
    const clientPath = resolveInside(CLIENTS_DIR, clientFolder);
    ensureDir(clientPath);

    const user = { id: "client", email: match.email, role: "client", client: clientFolder };
    const token = jwt.sign(user, JWT_SECRET, { expiresIn: "7d" });

    return res.json({ ok: true, token, user });
  } catch (e) {
    return res.status(500).json({ ok: false, error: e.message });
  }
});

// ----- API (protected) -----
app.use("/api", requireAuth);

app.get("/api/me", (req, res) => res.json({ ok: true, user: req.user || null }));

// Admin-only: list clients
app.get("/api/clients", requireAdmin, (req, res) => {
  try {
    const items = fs
      .readdirSync(CLIENTS_DIR, { withFileTypes: true })
      .filter((d) => d.isDirectory())
      .map((d) => d.name)
      .sort((a, b) => a.localeCompare(b));

    res.json({ ok: true, clients: items });
  } catch (e) {
    res.status(500).json({ ok: false, error: e.message });
  }
});

// Admin-only: create client
app.post("/api/clients", requireAdmin, (req, res) => {
  try {
    const name = safeName(req.body?.name);
    if (!name) return res.status(400).json({ ok: false, error: "Client name required" });

    const clientPath = resolveInside(CLIENTS_DIR, name);
    const existed = fs.existsSync(clientPath);
    ensureDir(clientPath);

    res.json({ ok: true, client: name, created: !existed });
  } catch (e) {
    res.status(500).json({ ok: false, error: e.message });
  }
});

// Create folder (write)
app.post("/api/clients/:client/mkdir", enforceClientMatch, requireWriteAccess, (req, res) => {
  try {
    const client = safeName(req.params.client);
    const rel = normalizeRelPath(req.query.path || "");
    const name = safeName(req.body?.name);
    if (!name) return res.status(400).json({ ok: false, error: "name required" });

    const clientPath = resolveInside(CLIENTS_DIR, client);
    ensureDir(clientPath);

    const targetDir = rel ? resolveInside(clientPath, rel) : clientPath;
    ensureDir(targetDir);

    const folderPath = resolveInside(targetDir, name);
    ensureDir(folderPath);

    res.json({ ok: true, created: true, name, path: rel });
  } catch (e) {
    res.status(500).json({ ok: false, error: e.message });
  }
});

// Write text (write)
app.post("/api/clients/:client/writeText", enforceClientMatch, requireWriteAccess, (req, res) => {
  try {
    const client = safeName(req.params.client);
    const rel = normalizeRelPath(req.query.path || "");
    const fileName = safeName(req.body?.fileName);
    const text = String(req.body?.text || "");
    if (!fileName) return res.status(400).json({ ok: false, error: "fileName required" });

    const clientPath = resolveInside(CLIENTS_DIR, client);
    ensureDir(clientPath);

    const targetDir = rel ? resolveInside(clientPath, rel) : clientPath;
    ensureDir(targetDir);

    const full = resolveInside(targetDir, fileName);
    fs.writeFileSync(full, text, "utf8");

    res.json({ ok: true, savedAs: fileName, bytes: Buffer.byteLength(text, "utf8"), path: rel });
  } catch (e) {
    res.status(500).json({ ok: false, error: e.message });
  }
});

// List items (read)
app.get("/api/clients/:client/files", enforceClientMatch, (req, res) => {
  try {
    const client = safeName(req.params.client);
    const rel = normalizeRelPath(req.query.path || "");

    const clientPath = resolveInside(CLIENTS_DIR, client);
    ensureDir(clientPath);

    const targetDir = rel ? resolveInside(clientPath, rel) : clientPath;
    ensureDir(targetDir);

    const raw = fs.readdirSync(targetDir, { withFileTypes: true }).map((d) => ({
      name: d.name,
      type: d.isDirectory() ? "dir" : "file",
    }));

    raw.sort((a, b) => {
      if (a.type !== b.type) return a.type === "dir" ? -1 : 1;
      return a.name.localeCompare(b.name);
    });

    res.json({
      ok: true,
      client,
      path: rel,
      fullPath: rel ? `${client}/${rel}` : client,
      items: raw,
    });
  } catch (e) {
    res.status(500).json({ ok: false, error: e.message });
  }
});

// Download (read)
app.get("/api/clients/:client/download", enforceClientMatch, (req, res) => {
  try {
    const client = safeName(req.params.client);
    const file = String(req.query.file || "");
    const rel = normalizeRelPath(req.query.path || "");
    if (!file) return res.status(400).json({ ok: false, error: "file query required" });

    const clientPath = resolveInside(CLIENTS_DIR, client);
    const targetDir = rel ? resolveInside(clientPath, rel) : clientPath;
    const full = resolveInside(targetDir, file);

    if (!fs.existsSync(full)) return res.status(404).json({ ok: false, error: "Not found" });
    if (fs.statSync(full).isDirectory()) return res.status(400).json({ ok: false, error: "Not a file" });

    res.download(full);
  } catch (e) {
    res.status(500).json({ ok: false, error: e.message });
  }
});

// Upload base64 (write)
app.post("/api/clients/:client/uploadBase64", enforceClientMatch, requireWriteAccess, (req, res) => {
  try {
    const client = safeName(req.params.client);
    const rel = normalizeRelPath(req.query.path || "");
    const contentType = String(req.body?.contentType || "");

    let fileName = safeName(req.body?.fileName);
    const base64Input = String(req.body?.base64 || "");

    if (!fileName) return res.status(400).json({ ok: false, error: "fileName required" });
    if (!base64Input) return res.status(400).json({ ok: false, error: "base64 required" });

    if (!path.extname(fileName)) {
      const ct = String(contentType || "").toLowerCase();
      if (ct.includes("pdf")) fileName = `${fileName}.pdf`;
      else if (ct.includes("png")) fileName = `${fileName}.png`;
      else if (ct.includes("jpeg") || ct.includes("jpg")) fileName = `${fileName}.jpg`;
      else if (ct.includes("text")) fileName = `${fileName}.txt`;
    }

    const clientPath = resolveInside(CLIENTS_DIR, client);
    ensureDir(clientPath);

    const targetDir = rel ? resolveInside(clientPath, rel) : clientPath;
    ensureDir(targetDir);

    const full = resolveInside(targetDir, fileName);

    const cleaned = base64Input.includes("base64,") ? base64Input.split("base64,")[1] : base64Input;
    const buf = Buffer.from(cleaned, "base64");
    fs.writeFileSync(full, buf);

    res.json({ ok: true, savedAs: fileName, bytes: buf.length, path: rel });
  } catch (e) {
    res.status(500).json({ ok: false, error: e.message });
  }
});

// ✅ Trash (soft delete) (write)
app.post("/api/clients/:client/trash", enforceClientMatch, requireWriteAccess, (req, res) => {
  try {
    const client = safeName(req.params.client);
    const rel = normalizeRelPath(req.query.path || "");
    const name = safeName(req.body?.name);

    if (!name) return res.status(400).json({ ok: false, error: "name required" });

    const clientPath = resolveInside(CLIENTS_DIR, client);
    const fromDir = rel ? resolveInside(clientPath, rel) : clientPath;
    const fromFull = resolveInside(fromDir, name);

    if (!fs.existsSync(fromFull)) return res.status(404).json({ ok: false, error: "Not found" });

    const trashBase = resolveInside(clientPath, path.join("05 Downloads", "_Trash"));
    ensureDir(trashBase);

    const trashSub = rel ? resolveInside(trashBase, rel) : trashBase;
    ensureDir(trashSub);

    const stamp = new Date().toISOString().replace(/[:.]/g, "-");
    let destName = name;
    let destFull = resolveInside(trashSub, destName);

    if (fs.existsSync(destFull)) {
      const ext = path.extname(name);
      const baseName = ext ? path.basename(name, ext) : name;
      destName = `${baseName}__${stamp}${ext || ""}`;
      destFull = resolveInside(trashSub, destName);
    }

    try {
      fs.renameSync(fromFull, destFull);
    } catch {
      copyRecursiveSync(fromFull, destFull);
      removeRecursiveSync(fromFull);
    }

    return res.json({
      ok: true,
      moved: name,
      fromPath: rel,
      trashedAs: destName,
      trashPath: rel ? `05 Downloads/_Trash/${rel}` : "05 Downloads/_Trash",
    });
  } catch (e) {
    return res.status(500).json({ ok: false, error: e.message });
  }
});

// ♻️ Restore from Trash (write)
app.post("/api/clients/:client/restore", enforceClientMatch, requireWriteAccess, (req, res) => {
  try {
    const client = safeName(req.params.client);
    const rel = normalizeRelPath(req.query.path || "");
    const name = safeName(req.query.name || req.body?.name);

    if (!name) return res.status(400).json({ ok: false, error: "name required" });

    const clientPath = resolveInside(CLIENTS_DIR, client);
    ensureDir(clientPath);

    const trashBase = resolveInside(clientPath, path.join("05 Downloads", "_Trash"));
    ensureDir(trashBase);

    const trashSub = rel ? resolveInside(trashBase, rel) : trashBase;
    const trashedFull = resolveInside(trashSub, name);

    if (!fs.existsSync(trashedFull)) {
      return res.status(404).json({ ok: false, error: "Item not found in Trash" });
    }

    const toDir = rel ? resolveInside(clientPath, rel) : clientPath;
    ensureDir(toDir);

    const stamp = new Date().toISOString().replace(/[:.]/g, "-");
    let destName = name;
    let destFull = resolveInside(toDir, destName);

    if (fs.existsSync(destFull)) {
      const ext = path.extname(name);
      const baseName = ext ? path.basename(name, ext) : name;
      destName = `${baseName}__restored__${stamp}${ext || ""}`;
      destFull = resolveInside(toDir, destName);
    }

    try {
      fs.renameSync(trashedFull, destFull);
    } catch {
      copyRecursiveSync(trashedFull, destFull);
      removeRecursiveSync(trashedFull);
    }

    return res.json({ ok: true, restored: name, restoredAs: destName, toPath: rel });
  } catch (e) {
    return res.status(500).json({ ok: false, error: e.message });
  }
});

// 🧨 Empty Trash (write)
app.delete("/api/clients/:client/trash", enforceClientMatch, requireWriteAccess, (req, res) => {
  try {
    const client = safeName(req.params.client);
    const rel = normalizeRelPath(req.query.path || "");

    const clientPath = resolveInside(CLIENTS_DIR, client);
    ensureDir(clientPath);

    const trashBase = resolveInside(clientPath, path.join("05 Downloads", "_Trash"));
    ensureDir(trashBase);

    const trashTarget = rel ? resolveInside(trashBase, rel) : trashBase;
    if (!fs.existsSync(trashTarget)) {
      return res.json({ ok: true, emptied: true, path: rel, note: "Trash folder did not exist" });
    }

    const entries = fs.readdirSync(trashTarget);
    for (const entry of entries) {
      removeRecursiveSync(path.join(trashTarget, entry));
    }

    return res.json({ ok: true, emptied: true, path: rel });
  } catch (e) {
    return res.status(500).json({ ok: false, error: e.message });
  }
});

// ❌ Delete ONE item from Trash permanently (write)
app.delete("/api/clients/:client/trashItem", enforceClientMatch, requireWriteAccess, (req, res) => {
  try {
    const client = safeName(req.params.client);
    const rel = normalizeRelPath(req.query.path || "");
    const name = safeName(req.query.name || "");

    if (!name) return res.status(400).json({ ok: false, error: "name query required" });

    const clientPath = resolveInside(CLIENTS_DIR, client);
    ensureDir(clientPath);

    const trashBase = resolveInside(clientPath, path.join("05 Downloads", "_Trash"));
    ensureDir(trashBase);

    const trashSub = rel ? resolveInside(trashBase, rel) : trashBase;
    const itemFull = resolveInside(trashSub, name);

    if (!fs.existsSync(itemFull)) return res.status(404).json({ ok: false, error: "Not found in Trash" });

    removeRecursiveSync(itemFull);

    return res.json({ ok: true, deleted: name, path: rel });
  } catch (e) {
    return res.status(500).json({ ok: false, error: e.message });
  }
});

// Hard delete file (admin only)
app.delete(
  "/api/clients/:client/file",
  enforceClientMatch,
  (req, res, next) => {
    if ((req.user?.role || "") === "client") {
      return res.status(403).json({ ok: false, error: "Forbidden (use Trash / Delete in Trash)" });
    }
    return next();
  },
  (req, res) => {
    try {
      const client = safeName(req.params.client);
      const file = String(req.query.file || "");
      const rel = normalizeRelPath(req.query.path || "");
      if (!file) return res.status(400).json({ ok: false, error: "file query required" });

      const clientPath = resolveInside(CLIENTS_DIR, client);
      const targetDir = rel ? resolveInside(clientPath, rel) : clientPath;
      const full = resolveInside(targetDir, file);

      if (!fs.existsSync(full)) return res.status(404).json({ ok: false, error: "Not found" });
      if (fs.statSync(full).isDirectory()) return res.status(400).json({ ok: false, error: "Not a file" });

      fs.unlinkSync(full);
      res.json({ ok: true, deleted: file, path: rel });
    } catch (e) {
      res.status(500).json({ ok: false, error: e.message });
    }
  }
);

// ----- Start -----
app.listen(PORT, "0.0.0.0", () => {
  console.log(`HabeshaWeb backend running on :${PORT}`);
  console.log(
    `ALLOWED_ORIGINS: ${ALLOWED_ORIGINS.length ? ALLOWED_ORIGINS.join(", ") : "(not set - allowing all)"}`
  );
  console.log(`AUTH_TOKEN set: ${AUTH_TOKEN ? "YES" : "NO"}`);
  console.log(`JWT_SECRET set: ${JWT_SECRET ? "YES" : "NO"}`);
  console.log(`ADMIN_EMAIL set: ${ADMIN_EMAIL ? "YES" : "NO"}`);
  console.log(`BASE_DIR: ${BASE_DIR}`);
  console.log(`CLIENTS_DIR: ${CLIENTS_DIR}`);
  console.log(`CLIENT_WRITE_ROOTS: ${CLIENT_WRITE_ROOTS.join(", ")}`);
  console.log(`CLIENT_USERS configured: ${CLIENT_USERS.length}`);
});
