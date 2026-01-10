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
const ALLOWED_ORIGINS = (process.env.ALLOWED_ORIGINS || "")
  .split(",")
  .map((s) => s.trim())
  .filter(Boolean);

app.use(
  cors({
    origin: (origin, cb) => {
      if (!origin) return cb(null, true);
      if (ALLOWED_ORIGINS.length === 0) return cb(null, true);
      if (ALLOWED_ORIGINS.includes(origin)) return cb(null, true);
      return cb(new Error("CORS blocked for origin: " + origin));
    },
    credentials: true,
  })
);

app.use(express.json({ limit: "25mb" }));

// ----- Config -----
const PORT = process.env.PORT || 8787;
const AUTH_TOKEN = (process.env.AUTH_TOKEN || "").trim();
const ADMIN_EMAIL = (process.env.ADMIN_EMAIL || "").trim().toLowerCase();
const ADMIN_PASSWORD = (process.env.ADMIN_PASSWORD || "").trim();
const JWT_SECRET = (process.env.JWT_SECRET || "").trim();

/**
 * Storage directory
 * - Priority 1: BASE_DIR env var (if you set it)
 * - Priority 2 (LOCAL DEFAULT): OneDrive\Documents\Habesha   ✅ (your real path)
 * - Priority 3 (Render): /var/data/habesha
 */
const LOCAL_DEFAULT_BASE_DIR = path.join(
  os.homedir(),
  "OneDrive",
  "Documents",
  "Habesha"
);

const BASE_DIR =
  process.env.BASE_DIR ||
  (process.env.RENDER ? "/var/data/habesha" : LOCAL_DEFAULT_BASE_DIR);

const CLIENTS_DIR = path.join(BASE_DIR, "clients");

// ----- Helpers -----
function ensureDir(p) {
  if (!fs.existsSync(p)) fs.mkdirSync(p, { recursive: true });
}

function safeName(input) {
  return String(input || "")
    .trim()
    .replace(/[^a-zA-Z0-9._ -]/g, "_")
    .slice(0, 120);
}

function resolveInside(base, target) {
  const full = path.resolve(base, target);
  const baseResolved = path.resolve(base);
  if (!full.startsWith(baseResolved)) throw new Error("Invalid path");
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

/**
 * ✅ Ensure "Church Related" exists inside "04 Personal" for:
 * 1) A specific client folder: <BASE_DIR>/clients/<client>/04 Personal/Church Related
 * 2) The global personal folder: <BASE_DIR>/04 Personal/Church Related
 */
function ensureChurchRelatedFolder(targetBasePath) {
  const personalDir = path.join(targetBasePath, "04 Personal");
  const churchDir = path.join(personalDir, "Church Related");
  ensureDir(personalDir);
  ensureDir(churchDir);
}

// ----- Auth -----
function requireAuth(req, res, next) {
  if (!AUTH_TOKEN && !JWT_SECRET) return next();

  const token = getBearer(req);

  if (AUTH_TOKEN && token === AUTH_TOKEN) return next();

  const payload = verifyJwtToken(token);
  if (payload) {
    req.user = payload;
    return next();
  }

  return res.status(401).json({ ok: false, error: "Unauthorized" });
}

// Ensure base folders exist
ensureDir(BASE_DIR);
ensureDir(CLIENTS_DIR);

// ----- Health -----
app.get("/health", (req, res) => res.send("ok"));

app.get("/api/health", (req, res) =>
  res.json({
    ok: true,
    baseDir: BASE_DIR,
    clientsDir: CLIENTS_DIR,
    runningOn: process.env.RENDER ? "render" : "local",
  })
);

// ----- Login -----
app.post("/login", (req, res) => {
  const email = String(req.body?.email || "").trim().toLowerCase();
  const password = String(req.body?.password || "").trim();

  if (email !== ADMIN_EMAIL || password !== ADMIN_PASSWORD) {
    return res.status(401).json({ ok: false, error: "Invalid login" });
  }

  if (!JWT_SECRET) {
    return res.status(500).json({ ok: false, error: "JWT_SECRET not set" });
  }

  const user = { id: "admin", email, role: "admin" };
  const token = jwt.sign(user, JWT_SECRET, { expiresIn: "7d" });

  res.json({ ok: true, token, user });
});

app.use("/api", requireAuth);

// ----- GLOBAL PERSONAL (your OneDrive folder) -----
// Create: <BASE_DIR>/04 Personal/Church Related
app.post("/api/personal/church-related", (req, res) => {
  try {
    ensureChurchRelatedFolder(BASE_DIR);
    return res.json({
      ok: true,
      created: path.join("04 Personal", "Church Related"),
      location: path.join(BASE_DIR, "04 Personal", "Church Related"),
    });
  } catch (e) {
    return res.status(500).json({ ok: false, error: e.message });
  }
});

// ----- Clients -----
// List clients (folders)
app.get("/api/clients", (req, res) => {
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

// Create client folder + ensure per-client personal/church folder exists
app.post("/api/clients", (req, res) => {
  try {
    const name = safeName(req.body?.name);
    if (!name)
      return res.status(400).json({ ok: false, error: "name required" });

    const clientPath = resolveInside(CLIENTS_DIR, name);
    ensureDir(clientPath);

    // ✅ Per-client: clients/<name>/04 Personal/Church Related
    ensureChurchRelatedFolder(clientPath);

    res.json({ ok: true, client: name });
  } catch (e) {
    res.status(500).json({ ok: false, error: e.message });
  }
});

// List files for a client + auto-fix folder for old clients
app.get("/api/clients/:client/files", (req, res) => {
  try {
    const client = safeName(req.params.client);
    const clientPath = resolveInside(CLIENTS_DIR, client);
    ensureDir(clientPath);

    // ✅ Ensure folder exists for older clients
    ensureChurchRelatedFolder(clientPath);

    const items = fs.readdirSync(clientPath, { withFileTypes: true }).map((d) => ({
      name: d.name,
      type: d.isDirectory() ? "dir" : "file",
    }));

    res.json({ ok: true, client, items });
  } catch (e) {
    res.status(500).json({ ok: false, error: e.message });
  }
});

// ----- Start -----
app.listen(PORT, "0.0.0.0", () => {
  console.log(`HabeshaWeb backend running on :${PORT}`);
  console.log(`BASE_DIR: ${BASE_DIR}`);
  console.log(`CLIENTS_DIR: ${CLIENTS_DIR}`);
});
