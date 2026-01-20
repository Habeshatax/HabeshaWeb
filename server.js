// server.js (FULL FILE)

import express from "express";
import fs from "fs";
import path from "path";
import cors from "cors";
import jwt from "jsonwebtoken";
import crypto from "crypto";
import nodemailer from "nodemailer";
import { fileURLToPath } from "url";

const app = express();

// ----- ESM __dirname fix -----
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// ----- Middleware -----
app.use(express.json({ limit: "25mb" }));

// =========================
// CONFIG / ENV
// =========================
const PORT = process.env.PORT || 10000;

const JWT_SECRET = process.env.JWT_SECRET || "";
if (!JWT_SECRET) console.warn("⚠️ JWT_SECRET is missing. Set it in Render env vars.");

const ADMIN_EMAIL = String(process.env.ADMIN_EMAIL || "").trim().toLowerCase();
const ADMIN_PASSWORD = String(process.env.ADMIN_PASSWORD || "").trim();

// ✅ Admin notification recipient (defaults to ADMIN_EMAIL)
const ADMIN_NOTIFY_EMAIL = String(process.env.ADMIN_NOTIFY_EMAIL || ADMIN_EMAIL || "")
  .trim()
  .toLowerCase();

const BASE_DIR = process.env.BASE_DIR || "/var/data/habesha";
const CLIENTS_DIR = process.env.CLIENTS_DIR || path.join(BASE_DIR, "clients");
const USERS_DIR = process.env.USERS_DIR || path.join(BASE_DIR, "_users");
const CLIENT_USERS_FILE =
  process.env.CLIENT_USERS_FILE || path.join(USERS_DIR, "clients.json");

// CORS allowed origins (comma separated) + allow localhost any port
const ALLOWED_ORIGINS = (process.env.ALLOWED_ORIGINS || "")
  .split(",")
  .map((s) => s.trim())
  .filter(Boolean);

const allowLocalhostAnyPort = true;

const corsOptions = {
  origin: (origin, cb) => {
    if (!origin) return cb(null, true);

    if (allowLocalhostAnyPort) {
      try {
        const u = new URL(origin);
        if (u.hostname === "localhost" || u.hostname === "127.0.0.1") return cb(null, true);
      } catch {}
    }

    if (ALLOWED_ORIGINS.length === 0) return cb(null, true);
    if (ALLOWED_ORIGINS.includes(origin)) return cb(null, true);

    return cb(new Error("CORS blocked for origin: " + origin));
  },
  credentials: false,
  methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization"],
};

app.use(cors(corsOptions));
app.options("*", cors(corsOptions));

// =========================
// UTILITIES
// =========================
function ensureDir(p) {
  fs.mkdirSync(p, { recursive: true });
}

function readJsonSafe(file, fallback) {
  try {
    if (!fs.existsSync(file)) return fallback;
    const txt = fs.readFileSync(file, "utf8");
    return txt ? JSON.parse(txt) : fallback;
  } catch (e) {
    console.warn("readJsonSafe error:", e.message);
    return fallback;
  }
}

function writeJsonSafe(file, data) {
  ensureDir(path.dirname(file));
  fs.writeFileSync(file, JSON.stringify(data, null, 2), "utf8");
}

function normalizeName(s) {
  return String(s || "")
    .trim()
    .replace(/\s+/g, " ")
    .replace(/[<>:"/\\|?*\x00-\x1F]/g, "")
    .trim();
}

function clientDisplayName({ businessType, firstName, lastName, companyName }) {
  if (businessType === "limited_company") return normalizeName(companyName);
  return normalizeName(`${firstName} ${lastName}`);
}

function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString("hex");
  const hash = crypto.pbkdf2Sync(password, salt, 120000, 32, "sha256").toString("hex");
  return `${salt}:${hash}`;
}

function verifyPassword(password, stored) {
  const [salt, hash] = String(stored || "").split(":");
  if (!salt || !hash) return false;
  const test = crypto.pbkdf2Sync(password, salt, 120000, 32, "sha256").toString("hex");
  return crypto.timingSafeEqual(Buffer.from(test, "hex"), Buffer.from(hash, "hex"));
}

function signToken(user) {
  return jwt.sign(
    { role: user.role, email: user.email, client: user.client || "" },
    JWT_SECRET,
    { expiresIn: "30d" }
  );
}

function authRequired(req, res, next) {
  const h = req.headers.authorization || "";
  const token = h.startsWith("Bearer ") ? h.slice(7) : "";
  if (!token) return res.status(401).json({ ok: false, error: "Missing token" });

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch {
    return res.status(401).json({ ok: false, error: "Invalid token" });
  }
}

function adminOnly(req, res, next) {
  if (req.user?.role !== "admin") return res.status(403).json({ ok: false, error: "Admin only" });
  next();
}

function safeRel(p) {
  const clean = String(p || "").replace(/\\/g, "/").replace(/^\/+/, "");
  if (clean.includes("..")) throw new Error("Invalid path");
  return clean;
}

function clientRoot(clientName) {
  return path.join(CLIENTS_DIR, clientName);
}

// =========================
// EMAIL (Outlook / Microsoft 365)
// =========================
// Render env vars you should set:
// SMTP_HOST=smtp.office365.com
// SMTP_PORT=587
// SMTP_USER=info@habeshatax.co.uk
// SMTP_PASS=*** (app password / smtp enabled password)
// SMTP_FROM=info@habeshatax.co.uk  (optional)
// SMTP_FROM_NAME=Habesha Tax & Support (optional)
// ADMIN_NOTIFY_EMAIL=info@habeshatax.co.uk
function makeMailer() {
  const host = process.env.SMTP_HOST;
  const port = Number(process.env.SMTP_PORT || "587");
  const user = process.env.SMTP_USER;
  const pass = process.env.SMTP_PASS;

  const fromEmail = (process.env.SMTP_FROM || user || "").trim();
  const fromName = (process.env.SMTP_FROM_NAME || "").trim();

  if (!host || !user || !pass || !fromEmail) return null;

  const transporter = nodemailer.createTransport({
    host,
    port,
    secure: false, // STARTTLS on 587
    auth: { user, pass },
  });

  const from = fromName ? `"${fromName}" <${fromEmail}>` : fromEmail;

  return { transporter, from };
}

async function sendAdminNewClientEmail(payload, createdClientFolder) {
  if (!ADMIN_NOTIFY_EMAIL) return;

  const mailer = makeMailer();
  if (!mailer) return;

  const { transporter, from } = mailer;

  const subject = `New client registered: ${payload.email}`;
  const lines = [
    "A new client has registered in HabeshaWeb.",
    "",
    `Email: ${payload.email}`,
    `Business Type: ${payload.businessType}`,
    `Client Folder: ${createdClientFolder}`,
    `Name/Company: ${
      payload.businessType === "limited_company"
        ? payload.companyName
        : `${payload.firstName} ${payload.lastName}`
    }`,
    `Services: ${(payload.services || []).join(", ") || "(none)"}`,
    "",
    `Time (UTC): ${new Date().toISOString()}`,
  ];

  await transporter.sendMail({
    from,
    to: ADMIN_NOTIFY_EMAIL,
    subject,
    text: lines.join("\n"),
  });
}

async function sendPasswordResetCodeEmail({ toEmail, code }) {
  const mailer = makeMailer();
  if (!mailer) return;

  const { transporter, from } = mailer;

  const subject = "Your password reset code (Habesha Tax & Support)";
  const lines = [
    "You requested a password reset for HabeshaWeb.",
    "",
    `Your reset code is: ${code}`,
    "",
    "This code expires in 15 minutes.",
    "If you didn’t request this, you can ignore this email.",
    "",
    `Time (UTC): ${new Date().toISOString()}`,
  ];

  await transporter.sendMail({
    from,
    to: toEmail,
    subject,
    text: lines.join("\n"),
  });
}

// =========================
// FOLDER STRUCTURE CREATION
// =========================
function createClientStructure(clientFolderName, services = []) {
  const root = clientRoot(clientFolderName);
  ensureDir(root);

  ensureDir(path.join(root, "00 Engagement Letter"));
  ensureDir(path.join(root, "01 Proof of ID", "01 Passport - BRP - eVisa"));
  ensureDir(path.join(root, "01 Proof of ID", "02 Proof of Address"));
  ensureDir(path.join(root, "01 Proof of ID", "03 Signed Engagement Letter"));

  ensureDir(path.join(root, "03 Work"));
  ensureDir(path.join(root, "05 Downloads", "_Trash"));

  const compliance = path.join(root, "02 Compliance");
  ensureDir(compliance);

  const addServiceFolder = (name) => ensureDir(path.join(compliance, name));

  if (services.includes("self_assessment")) addServiceFolder("01 Self Assessment");
  if (services.includes("landlords")) addServiceFolder("02 Landlords");
  if (services.includes("limited_company")) addServiceFolder("03 Limited Company");
  if (services.includes("payroll")) addServiceFolder("04 Payroll");
  if (services.includes("vat_mtd")) addServiceFolder("05 VAT - MTD");
  if (services.includes("bookkeeping")) addServiceFolder("06 Bookkeeping");
  if (services.includes("home_office")) addServiceFolder("07 Home Office - Other");
}

// =========================
// USERS STORAGE
// =========================
function loadClientUsers() {
  return readJsonSafe(CLIENT_USERS_FILE, []);
}

function saveClientUsers(users) {
  writeJsonSafe(CLIENT_USERS_FILE, users);
}

// =========================
// PASSWORD RESET HELPERS
// =========================
const RESET_CODE_TTL_MS = 15 * 60 * 1000; // 15 minutes
const RESET_MAX_ATTEMPTS = 10;

function make6DigitCode() {
  // 000000 -> 999999, padded
  const n = crypto.randomInt(0, 1000000);
  return String(n).padStart(6, "0");
}

function hashResetCode(code) {
  return crypto.createHash("sha256").update(String(code)).digest("hex");
}

// =========================
// ROUTES
// =========================
app.get("/api/health", (req, res) => {
  const diskUsers = loadClientUsers().map((u) => ({ email: u.email, client: u.client }));
  res.json({
    ok: true,
    service: "habeshaweb",
    baseDir: BASE_DIR,
    clientsDir: CLIENTS_DIR,
    usersFile: CLIENT_USERS_FILE,
    allowedOrigins: ALLOWED_ORIGINS,
    diskClientUsers: diskUsers,
  });
});

// Admin login (PUBLIC)
app.post("/login", (req, res) => {
  const email = String(req.body?.email || "").trim().toLowerCase();
  const password = String(req.body?.password || "").trim();

  if (!email || !password) return res.status(400).json({ ok: false, error: "Email and password required" });
  if (!ADMIN_EMAIL || !ADMIN_PASSWORD) return res.status(500).json({ ok: false, error: "Admin credentials not configured" });

  if (email !== ADMIN_EMAIL || password !== ADMIN_PASSWORD) {
    return res.status(401).json({ ok: false, error: "Invalid credentials" });
  }

  const user = { role: "admin", email, client: "" };
  const token = signToken(user);
  res.json({ ok: true, token, user });
});

// Client login (PUBLIC)
app.post("/client-login", (req, res) => {
  const email = String(req.body?.email || "").trim().toLowerCase();
  const password = String(req.body?.password || "").trim();

  if (!email || !password) return res.status(400).json({ ok: false, error: "Email and password required" });

  const users = loadClientUsers();
  const u = users.find((x) => x.email === email);
  if (!u) return res.status(401).json({ ok: false, error: "Invalid credentials" });

  if (!verifyPassword(password, u.passwordHash)) {
    return res.status(401).json({ ok: false, error: "Invalid credentials" });
  }

  const user = { role: "client", email: u.email, client: u.client };
  const token = signToken(user);

  res.json({ ok: true, token, user });
});

// ✅ Forgot password (PUBLIC) -> send 6-digit code
app.post("/forgot-password", async (req, res) => {
  const email = String(req.body?.email || "").trim().toLowerCase();
  if (!email) return res.status(400).json({ ok: false, error: "Email is required" });

  // Always respond ok (don’t reveal if the email exists)
  try {
    const users = loadClientUsers();
    const u = users.find((x) => x.email === email);

    if (u) {
      const code = make6DigitCode();
      u.reset = {
        codeHash: hashResetCode(code),
        expiresAt: Date.now() + RESET_CODE_TTL_MS,
        attempts: 0,
        createdAt: new Date().toISOString(),
      };
      saveClientUsers(users);

      // send email (if SMTP not configured, this will throw and we'll still respond ok)
      await sendPasswordResetCodeEmail({ toEmail: email, code });
    }
  } catch (e) {
    console.warn("forgot-password error:", e?.message || e);
  }

  res.json({ ok: true, message: "If that email exists, a reset code has been sent." });
});

// ✅ Reset password (PUBLIC) -> verify code + set new password
app.post("/reset-password", (req, res) => {
  const email = String(req.body?.email || "").trim().toLowerCase();
  const code = String(req.body?.code || "").trim();
  const newPassword = String(req.body?.newPassword || "").trim();

  if (!email) return res.status(400).json({ ok: false, error: "Email is required" });
  if (!code || code.length !== 6) return res.status(400).json({ ok: false, error: "6-digit code is required" });
  if (!newPassword || newPassword.length < 8) return res.status(400).json({ ok: false, error: "Password must be at least 8 characters" });

  const users = loadClientUsers();
  const u = users.find((x) => x.email === email);
  if (!u || !u.reset?.codeHash) {
    return res.status(400).json({ ok: false, error: "Invalid or expired reset code" });
  }

  const r = u.reset;

  if (typeof r.expiresAt !== "number" || Date.now() > r.expiresAt) {
    u.reset = null;
    saveClientUsers(users);
    return res.status(400).json({ ok: false, error: "Invalid or expired reset code" });
  }

  r.attempts = Number(r.attempts || 0) + 1;
  if (r.attempts > RESET_MAX_ATTEMPTS) {
    u.reset = null;
    saveClientUsers(users);
    return res.status(429).json({ ok: false, error: "Too many attempts. Please request a new code." });
  }

  const incomingHash = hashResetCode(code);
  if (incomingHash !== r.codeHash) {
    saveClientUsers(users);
    return res.status(400).json({ ok: false, error: "Invalid or expired reset code" });
  }

  // success: set new password + clear reset data
  u.passwordHash = hashPassword(newPassword);
  u.reset = null;
  saveClientUsers(users);

  res.json({ ok: true, message: "Password updated successfully" });
});

// Client register (PUBLIC)
app.post("/client-register", async (req, res) => {
  try {
    const businessType = String(req.body?.businessType || "").trim();
    const firstName = String(req.body?.firstName || "").trim();
    const lastName = String(req.body?.lastName || "").trim();
    const companyName = String(req.body?.companyName || "").trim();
    const email = String(req.body?.email || "").trim().toLowerCase();
    const password = String(req.body?.password || "").trim();
    const services = Array.isArray(req.body?.services) ? req.body.services.map((s) => String(s)) : [];

    if (!email) return res.status(400).json({ ok: false, error: "Email is required" });
    if (!password || password.length < 8) return res.status(400).json({ ok: false, error: "Password must be at least 8 characters" });

    if (!["self_assessment", "landlords", "limited_company"].includes(businessType)) {
      return res.status(400).json({ ok: false, error: "Invalid businessType" });
    }

    if (businessType === "limited_company") {
      if (!companyName) return res.status(400).json({ ok: false, error: "Company name is required" });
    } else {
      if (!firstName || !lastName) return res.status(400).json({ ok: false, error: "First and last name are required" });
    }

    ensureDir(CLIENTS_DIR);
    ensureDir(USERS_DIR);

    const users = loadClientUsers();
    if (users.some((u) => u.email === email)) {
      return res.status(409).json({ ok: false, error: "This email is already registered" });
    }

    const clientName = clientDisplayName({ businessType, firstName, lastName, companyName });
    if (!clientName) return res.status(400).json({ ok: false, error: "Invalid client name" });

    let folderName = clientName;
    let i = 2;
    while (fs.existsSync(clientRoot(folderName))) {
      folderName = `${clientName} (${i})`;
      i += 1;
    }

    const finalServices = new Set(services);
    finalServices.add(businessType);
    const servicesArray = Array.from(finalServices);

    createClientStructure(folderName, servicesArray);

    const passwordHash = hashPassword(password);
    const newUser = {
      role: "client",
      email,
      passwordHash,
      client: folderName,
      businessType,
      firstName,
      lastName,
      companyName,
      services: servicesArray,
      createdAt: new Date().toISOString(),
      status: "active", // ✅ useful for your future active/archived
    };

    users.push(newUser);
    saveClientUsers(users);

    // ✅ Notify admin (Outlook)
    try {
      await sendAdminNewClientEmail(
        { email, businessType, firstName, lastName, companyName, services: servicesArray },
        folderName
      );
    } catch (e) {
      console.warn("Admin email failed:", e.message);
    }

    const user = { role: "client", email, client: folderName };
    const token = signToken(user);

    res.json({ ok: true, token, user });
  } catch (e) {
    res.status(500).json({ ok: false, error: e.message || "Server error" });
  }
});

// Current user (PROTECTED)
app.get("/api/me", authRequired, (req, res) => {
  res.json({ ok: true, user: req.user });
});

// List clients (ADMIN)
app.get("/api/clients", authRequired, adminOnly, (req, res) => {
  const users = loadClientUsers();
  const list = users.map((u) => ({
    email: u.email,
    client: u.client,
    businessType: u.businessType,
    createdAt: u.createdAt,
    status: u.status || "active",
  }));
  res.json({ ok: true, clients: list });
});

// =========================
// FILE BROWSER (PROTECTED)
// =========================
function resolveClientPath(requestingUser, clientParam, relPath = "") {
  const clientName = decodeURIComponent(clientParam || "");
  if (!clientName) throw new Error("Missing client");

  if (requestingUser.role === "client" && requestingUser.client !== clientName) {
    throw new Error("Forbidden: wrong client");
  }

  const root = clientRoot(clientName);
  const rel = safeRel(relPath || "");
  const abs = path.join(root, rel);

  const rootNorm = path.resolve(root);
  const absNorm = path.resolve(abs);
  if (!absNorm.startsWith(rootNorm)) throw new Error("Invalid path");

  return { root, abs, rel, clientName };
}

app.get("/api/clients/:client/files", authRequired, (req, res) => {
  try {
    const rel = req.query.path ? String(req.query.path) : "";
    const { abs } = resolveClientPath(req.user, req.params.client, rel);

    ensureDir(abs);
    const entries = fs.readdirSync(abs, { withFileTypes: true });
    const items = entries.map((d) => ({
      name: d.name,
      type: d.isDirectory() ? "dir" : "file",
    }));

    res.json({ ok: true, items });
  } catch (e) {
    res.status(400).json({ ok: false, error: e.message });
  }
});

app.post("/api/clients/:client/mkdir", authRequired, (req, res) => {
  try {
    const rel = req.query.path ? String(req.query.path) : "";
    const name = normalizeName(req.body?.name);
    if (!name) throw new Error("Missing folder name");

    const { abs } = resolveClientPath(req.user, req.params.client, rel);
    ensureDir(path.join(abs, name));
    res.json({ ok: true });
  } catch (e) {
    res.status(400).json({ ok: false, error: e.message });
  }
});

app.post("/api/clients/:client/writeText", authRequired, (req, res) => {
  try {
    const rel = req.query.path ? String(req.query.path) : "";
    const fileName = normalizeName(req.body?.fileName || "note.txt");
    const text = String(req.body?.text || "");

    const { abs } = resolveClientPath(req.user, req.params.client, rel);
    ensureDir(abs);

    fs.writeFileSync(path.join(abs, fileName), text, "utf8");
    res.json({ ok: true });
  } catch (e) {
    res.status(400).json({ ok: false, error: e.message });
  }
});

app.post("/api/clients/:client/uploadBase64", authRequired, (req, res) => {
  try {
    const rel = req.query.path ? String(req.query.path) : "";
    const fileName = normalizeName(req.body?.fileName);
    const base64 = String(req.body?.base64 || "");
    if (!fileName) throw new Error("Missing fileName");
    if (!base64.startsWith("data:")) throw new Error("Invalid base64 data URL");

    const { abs } = resolveClientPath(req.user, req.params.client, rel);
    ensureDir(abs);

    const comma = base64.indexOf(",");
    const raw = comma >= 0 ? base64.slice(comma + 1) : "";
    const buf = Buffer.from(raw, "base64");

    fs.writeFileSync(path.join(abs, fileName), buf);
    res.json({ ok: true });
  } catch (e) {
    res.status(400).json({ ok: false, error: e.message });
  }
});

app.get("/api/clients/:client/download", authRequired, (req, res) => {
  try {
    const rel = req.query.path ? String(req.query.path) : "";
    const file = String(req.query.file || "");
    if (!file) throw new Error("Missing file");

    const { abs } = resolveClientPath(req.user, req.params.client, rel);
    const fp = path.join(abs, file);

    if (!fs.existsSync(fp)) return res.status(404).send("Not found");
    res.download(fp);
  } catch (e) {
    res.status(400).send(e.message);
  }
});

// =========================
// TRASH (PROTECTED)
// =========================
const TRASH_ROOT_REL = "05 Downloads/_Trash";

function trashRootAbs(clientName) {
  return path.join(clientRoot(clientName), TRASH_ROOT_REL);
}

function stamp() {
  return new Date().toISOString().replace(/[:.]/g, "-");
}

app.post("/api/clients/:client/trash", authRequired, (req, res) => {
  try {
    const rel = req.query.path ? String(req.query.path) : "";
    const name = normalizeName(req.body?.name);
    if (!name) throw new Error("Missing name");

    const { abs, clientName } = resolveClientPath(req.user, req.params.client, rel);
    const src = path.join(abs, name);
    if (!fs.existsSync(src)) throw new Error("Not found");

    const trashRoot = trashRootAbs(clientName);
    ensureDir(trashRoot);

    const destName = `${stamp()}__${name}`;
    const dest = path.join(trashRoot, destName);

    fs.renameSync(src, dest);
    res.json({ ok: true });
  } catch (e) {
    res.status(400).json({ ok: false, error: e.message });
  }
});

app.post("/api/clients/:client/restore", authRequired, (req, res) => {
  try {
    const rel = req.query.path ? String(req.query.path) : "";
    const name = normalizeName(req.body?.name);
    if (!name) throw new Error("Missing name");

    const { clientName } = resolveClientPath(req.user, req.params.client, "");
    const trashRoot = trashRootAbs(clientName);
    const from = path.join(trashRoot, safeRel(rel), name);

    if (!fs.existsSync(from)) throw new Error("Not found in Trash");

    const restoreTo = path.join(clientRoot(clientName), "05 Downloads");
    ensureDir(restoreTo);

    const parts = name.split("__");
    const original = parts.length >= 2 ? parts.slice(1).join("__") : name;

    let target = path.join(restoreTo, original);
    let i = 2;
    while (fs.existsSync(target)) {
      const ext = path.extname(original);
      const base = ext ? original.slice(0, -ext.length) : original;
      target = path.join(restoreTo, `${base} (${i})${ext}`);
      i += 1;
    }

    fs.renameSync(from, target);
    res.json({ ok: true });
  } catch (e) {
    res.status(400).json({ ok: false, error: e.message });
  }
});

app.delete("/api/clients/:client/trash", authRequired, (req, res) => {
  try {
    const rel = req.query.path ? String(req.query.path) : "";
    const { clientName } = resolveClientPath(req.user, req.params.client, "");

    const trashRoot = trashRootAbs(clientName);
    const target = path.join(trashRoot, safeRel(rel));

    if (fs.existsSync(target)) {
      fs.rmSync(target, { recursive: true, force: true });
      ensureDir(target);
    } else {
      ensureDir(target);
    }

    res.json({ ok: true });
  } catch (e) {
    res.status(400).json({ ok: false, error: e.message });
  }
});

app.delete("/api/clients/:client/trashItem", authRequired, (req, res) => {
  try {
    const rel = req.query.path ? String(req.query.path) : "";
    const name = String(req.query.name || "").trim();
    if (!name) throw new Error("Missing name");

    const { clientName } = resolveClientPath(req.user, req.params.client, "");
    const trashRoot = trashRootAbs(clientName);
    const target = path.join(trashRoot, safeRel(rel), name);

    if (!fs.existsSync(target)) throw new Error("Not found");

    fs.rmSync(target, { recursive: true, force: true });
    res.json({ ok: true });
  } catch (e) {
    res.status(400).json({ ok: false, error: e.message });
  }
});

// =========================
// STARTUP
// =========================
function bootLog() {
  console.log("HabeshaWeb backend running on:", PORT);
  console.log("ALLOWED_ORIGINS:", ALLOWED_ORIGINS.join(", ") || "(none - allow all)");
  console.log("JWT_SECRET set:", JWT_SECRET ? "YES" : "NO");
  console.log("ADMIN_EMAIL set:", ADMIN_EMAIL ? "YES" : "NO");
  console.log("ADMIN_NOTIFY_EMAIL set:", ADMIN_NOTIFY_EMAIL ? "YES" : "NO");
  console.log("BASE_DIR:", BASE_DIR);
  console.log("CLIENTS_DIR:", CLIENTS_DIR);
  console.log("CLIENT_USERS_FILE:", CLIENT_USERS_FILE);

  const mailer = makeMailer();
  console.log("SMTP configured:", mailer ? "YES" : "NO");
}

ensureDir(BASE_DIR);
ensureDir(CLIENTS_DIR);
ensureDir(USERS_DIR);

app.listen(PORT, () => {
  bootLog();
});
