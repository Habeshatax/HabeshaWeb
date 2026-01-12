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
      if (!origin) return cb(null, true); // allow tools like curl/PS
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

// Optional legacy static token support
const AUTH_TOKEN = (process.env.AUTH_TOKEN || "").trim();

// Admin credentials for login
const ADMIN_EMAIL = (process.env.ADMIN_EMAIL || "").trim().toLowerCase();
const ADMIN_PASSWORD = (process.env.ADMIN_PASSWORD || "").trim();

// JWT secret for issuing/verifying tokens
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
  // allow letters, numbers, dot, underscore, dash, space
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

// Protect only /api routes
function requireAuth(req, res, next) {
  // If no auth configured, do not lock yourself out
  if (!AUTH_TOKEN && !JWT_SECRET) return next();

  const token = getBearer(req);

  // 1) Allow old fixed AUTH_TOKEN
  if (AUTH_TOKEN && token === AUTH_TOKEN) {
    req.user = { id: "legacy", email: "legacy@token", role: "admin" };
    return next();
  }

  // 2) Allow JWT
  const payload = verifyJwtToken(token);
  if (payload) {
    req.user = payload;
    return next();
  }

  return res.status(401).json({ ok: false, error: "Unauthorized" });
}

function normalizeRelPath(p) {
  // allow empty -> root
  const raw = String(p || "").trim();
  if (!raw) return "";

  // convert backslashes to forward slashes and remove leading slashes
  const cleaned = raw.replace(/\\/g, "/").replace(/^\/+/, "");

  // block traversal + null byte
  const decoded = decodeURIComponent(cleaned);
  if (decoded.includes("..")) throw new Error("Invalid path");
  if (decoded.includes("\0")) throw new Error("Invalid path");

  // remove duplicate slashes
  return decoded.replace(/\/{2,}/g, "/");
}

function getCurrentTaxYearLabel(now = new Date()) {
  // UK tax year: 6 April -> 5 April
  const y = now.getFullYear();
  const april6 = new Date(y, 3, 6);
  const startYear = now >= april6 ? y : y - 1;
  const endYear = startYear + 1;
  return `${startYear}-${String(endYear).slice(2)}`; // e.g. 2025-26
}

function createTaxYearTree(basePath, label) {
  const p = path.join(basePath, label);
  ensureDir(p);

  const sub = [
    "01 Income",
    "02 Expenses",
    "03 Bank Statements",
    "04 CIS Statements",
    "05 Pensions & Benefits",
    "06 Other",
    "07 Final & Submitted",
  ];
  sub.forEach((s) => ensureDir(path.join(p, s)));
}

function createStandardClientRoot(clientPath) {
  const roots = [
    "00 Engagement Letter",
    "01 Proof of ID",
    "02 Compliance",
    "03 Work",
    "04 Personal",
    "05 Downloads",
  ];
  roots.forEach((r) => ensureDir(path.join(clientPath, r)));

  // Proof of ID subfolders
  const idBase = path.join(clientPath, "01 Proof of ID");
  ["01 Passport - BRP - eVisa", "02 Proof of Address", "03 Signed Engagement Letter"].forEach((s) =>
    ensureDir(path.join(idBase, s))
  );
}

function normalizeBusinessType(businessType) {
  const t = String(businessType || "").trim().toLowerCase();
  if (t === "landlord") return "landlords";
  if (t === "individual") return "self_assessment";
  if (t === "self assessment") return "self_assessment";
  if (t === "limited company") return "limited_company";
  return t || "self_assessment";
}

function normalizeServices(services) {
  if (!Array.isArray(services)) return [];
  return services.map((s) => String(s || "").trim().toLowerCase()).filter(Boolean);
}

function createComplianceStructure(clientPath, businessType, services) {
  const complianceBase = path.join(clientPath, "02 Compliance");
  ensureDir(complianceBase);

  const type = normalizeBusinessType(businessType);
  const svc = normalizeServices(services);

  // Always useful
  ensureDir(path.join(complianceBase, "00 Client Info"));

  // --- Self Assessment ---
  if (svc.includes("self_assessment") || type === "self_assessment") {
    const sa = path.join(complianceBase, "01 Self Assessment");
    ensureDir(sa);

    const current = getCurrentTaxYearLabel();
    const startYear = parseInt(current.split("-")[0], 10);
    const prev = `${startYear - 1}-${String(startYear).slice(2)}`;

    createTaxYearTree(sa, prev);
    createTaxYearTree(sa, current);
  }

  // --- Landlords ---
  if (svc.includes("landlords") || type === "landlords") {
    const ll = path.join(complianceBase, "02 Landlords");
    ensureDir(ll);

    const current = getCurrentTaxYearLabel();
    const startYear = parseInt(current.split("-")[0], 10);
    const prev = `${startYear - 1}-${String(startYear).slice(2)}`;

    createTaxYearTree(ll, prev);
    createTaxYearTree(ll, current);

    ["08 Properties", "09 Tenancy Agreements", "10 Mortgage Interest", "11 Letting Agent Statements"].forEach(
      (s) => ensureDir(path.join(ll, s))
    );
  }

  // --- Limited Company ---
  if (svc.includes("limited_company") || type === "limited_company") {
    const ltd = path.join(complianceBase, "03 Limited Company");
    ensureDir(ltd);

    [
      "01 Company Details",
      "02 Sales (Invoices - POS - Reports)",
      "03 Purchases & Expenses (Invoices - Receipts)",
      "04 Banking (Bank Statements - Credit Cards - Cash)",
      "05 Directors Loan Account",
      "06 Payroll",
      "07 VAT (MTD)",
      "08 CIS",
      "09 Loans (Agreements - HP - Leases - Interest)",
      "10 Grants",
      "11 Previous Year",
      "12 Accounts & CT600",
      "13 Final & Submitted",
    ].forEach((s) => ensureDir(path.join(ltd, s)));
  }

  // --- Bookkeeping ---
  if (svc.includes("bookkeeping")) {
    const bk = path.join(complianceBase, "04 Bookkeeping");
    ensureDir(bk);
    ["01 Sales", "02 Purchases", "03 Banking", "04 Reports", "05 Queries"].forEach((s) =>
      ensureDir(path.join(bk, s))
    );
  }

  // --- VAT / MTD ---
  if (svc.includes("vat_mtd")) {
    const vat = path.join(complianceBase, "05 VAT (MTD)");
    ensureDir(vat);
    ["01 VAT Returns", "02 VAT Working Papers", "03 VAT Receipts", "04 Final & Submitted"].forEach((s) =>
      ensureDir(path.join(vat, s))
    );
  }

  // --- Payroll ---
  if (svc.includes("payroll")) {
    const pr = path.join(complianceBase, "06 Payroll");
    ensureDir(pr);
    [
      "01 Employees",
      "02 Timesheets",
      "03 Payroll Reports",
      "04 RTI (FPS - EPS)",
      "05 P45 - P60",
      "06 Pension",
      "07 Final & Submitted",
    ].forEach((s) => ensureDir(path.join(pr, s)));
  }

  // --- Home Office ---
  if (svc.includes("home_office")) {
    const ho = path.join(complianceBase, "07 Home Office Applications");
    ensureDir(ho);
    ["01 Applications", "02 Supporting Docs", "03 Correspondence", "04 Final & Submitted"].forEach((s) =>
      ensureDir(path.join(ho, s))
    );
  }
}

function createClientFolderTree(clientPath, businessType, services) {
  createStandardClientRoot(clientPath);
  createComplianceStructure(clientPath, businessType, services);
}

// optional helper: auto add extension if user uploads without one
function addExtIfMissing(fileName, contentType) {
  if (!fileName) return fileName;
  if (path.extname(fileName)) return fileName;

  const ct = String(contentType || "").toLowerCase();
  if (ct.includes("pdf")) return `${fileName}.pdf`;
  if (ct.includes("png")) return `${fileName}.png`;
  if (ct.includes("jpeg") || ct.includes("jpg")) return `${fileName}.jpg`;
  if (ct.includes("text")) return `${fileName}.txt`;
  return fileName;
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
  })
);

// ----- Home -----
app.get("/", (req, res) => {
  res.status(200).send("HabeshaWeb backend is running. Try /health or /api/health");
});

// Helpful (so browser doesn't say Cannot GET /login)
app.get("/login", (req, res) => {
  res.status(200).send("Use POST /login with JSON body { email, password }. This is an API endpoint.");
});

// ----- LOGIN (PUBLIC) -----
// POST /login  body: { email, password }
app.post("/login", (req, res) => {
  try {
    const email = String(req.body?.email || "").trim().toLowerCase();
    const password = String(req.body?.password || "").trim();

    if (!ADMIN_EMAIL || !ADMIN_PASSWORD) {
      return res.status(500).json({
        ok: false,
        error: "ADMIN_EMAIL / ADMIN_PASSWORD not set on server",
      });
    }

    if (email !== ADMIN_EMAIL || password !== ADMIN_PASSWORD) {
      return res.status(401).json({ ok: false, error: "Invalid login" });
    }

    if (!JWT_SECRET) {
      return res.status(500).json({
        ok: false,
        error: "JWT_SECRET not set on server",
      });
    }

    const user = { id: "admin", email: ADMIN_EMAIL, role: "admin" };
    const token = jwt.sign(user, JWT_SECRET, { expiresIn: "7d" });

    return res.json({ ok: true, token, user });
  } catch (e) {
    return res.status(500).json({ ok: false, error: e.message });
  }
});

// ----- API (protected) -----
app.use("/api", requireAuth);

// ✅ /api/me
app.get("/api/me", (req, res) => {
  return res.json({ ok: true, user: req.user || null });
});

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

// ✅ Create client folder + FULL STRUCTURE
// body: { name, businessType, services[] }
app.post("/api/clients", (req, res) => {
  try {
    const name = safeName(req.body?.name);
    if (!name) return res.status(400).json({ ok: false, error: "Client name required" });

    const businessType = normalizeBusinessType(req.body?.businessType || "self_assessment");
    const services = normalizeServices(req.body?.services || []);

    const clientPath = resolveInside(CLIENTS_DIR, name);

    const existed = fs.existsSync(clientPath);
    ensureDir(clientPath);

    // build folder tree (idempotent)
    createClientFolderTree(clientPath, businessType, services);

    res.json({ ok: true, client: name, created: !existed, businessType, services });
  } catch (e) {
    res.status(500).json({ ok: false, error: e.message });
  }
});

// ✅ NEW: create folder (mkdir) (supports ?path=...)
// body: { name }
app.post("/api/clients/:client/mkdir", (req, res) => {
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

// ✅ NEW: write text file (supports ?path=...)
// body: { fileName, text }
app.post("/api/clients/:client/writeText", (req, res) => {
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

    res.json({
      ok: true,
      savedAs: fileName,
      bytes: Buffer.byteLength(text, "utf8"),
      path: rel,
    });
  } catch (e) {
    res.status(500).json({ ok: false, error: e.message });
  }
});

// ✅ List files/folders for a client (supports ?path=sub/folder)
app.get("/api/clients/:client/files", (req, res) => {
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

// ✅ Download a file (supports ?file=...&path=...)
app.get("/api/clients/:client/download", (req, res) => {
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

// ✅ Upload base64 (supports ?path=...)
// body: { fileName, base64, contentType? }
app.post("/api/clients/:client/uploadBase64", (req, res) => {
  try {
    const client = safeName(req.params.client);
    const rel = normalizeRelPath(req.query.path || "");
    const contentType = String(req.body?.contentType || "");

    let fileName = safeName(req.body?.fileName);
    const base64Input = String(req.body?.base64 || "");

    if (!fileName) return res.status(400).json({ ok: false, error: "fileName required" });
    if (!base64Input) return res.status(400).json({ ok: false, error: "base64 required" });

    fileName = addExtIfMissing(fileName, contentType);

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

// ✅ Delete file (supports ?file=...&path=...)
app.delete("/api/clients/:client/file", (req, res) => {
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
});

// ----- Start -----
app.listen(PORT, "0.0.0.0", () => {
  console.log(`HabeshaWeb backend running on :${PORT}`);
  console.log(`AUTH_TOKEN set: ${AUTH_TOKEN ? "YES" : "NO"}`);
  console.log(`JWT_SECRET set: ${JWT_SECRET ? "YES" : "NO"}`);
  console.log(`ADMIN_EMAIL set: ${ADMIN_EMAIL ? "YES" : "NO"}`);
  console.log(`BASE_DIR: ${BASE_DIR}`);
  console.log(`CLIENTS_DIR: ${CLIENTS_DIR}`);
});
