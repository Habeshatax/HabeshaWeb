// server.js
// Habesha Web Folder Manager (Windows + OneDrive folders)
// Run: npm i express
// Then: node server.js
// Open from PC: http://localhost:8787
// Open from phone/iPad (same WiFi): http://YOUR-PC-IP:8787

const express = require("express");
const fs = require("fs");
const fsp = fs.promises;
const path = require("path");
const { exec } = require("child_process");
const os = require("os");

const app = express();
app.use(express.json({ limit: "2mb" }));

/**
 * ========= CONFIG =========
 * Change this to your Habesha base folder.
 * (Matches your AHK script)
 */
const BASE = "C:\\Users\\wedaj\\OneDrive\\Documents\\Habesha";
const CLIENTS_BASE = path.join(BASE, "02 Clients");

// Simple “password” for your web page (protect from anyone on WiFi)
// Change it to something only you know
const AUTH_TOKEN = "CHANGE_ME_12345";

// Port
const PORT = 8787;

/**
 * ========= SECURITY =========
 * Every request must include:  X-Auth-Token: <AUTH_TOKEN>
 */
function requireAuth(req, res, next) {
  const token = req.headers["x-auth-token"];
  if (token !== AUTH_TOKEN) return res.status(401).json({ error: "Unauthorized" });
  next();
}

function ensureDir(p) {
  if (!fs.existsSync(p)) fs.mkdirSync(p, { recursive: true });
}

async function dirExists(p) {
  try {
    const st = await fsp.stat(p);
    return st.isDirectory();
  } catch {
    return false;
  }
}

async function fileExists(p) {
  try {
    const st = await fsp.stat(p);
    return st.isFile();
  } catch {
    return false;
  }
}

function openInExplorer(folderPath) {
  // Opens on the Windows PC where server runs
  const cmd = `explorer.exe "${folderPath}"`;
  exec(cmd, () => {});
}

async function writeTextFile(filePath, content) {
  await fsp.writeFile(filePath, content, { encoding: "utf8" });
}

async function readTextFile(filePath) {
  return fsp.readFile(filePath, { encoding: "utf8" });
}

function todayISO() {
  const d = new Date();
  const pad = (n) => String(n).padStart(2, "0");
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}`;
}

// Keep tax years in a settings file
const TAXYEARS_FILE = path.join(BASE, "_settings_taxyears.txt");

async function loadTaxYears() {
  try {
    const txt = await fsp.readFile(TAXYEARS_FILE, "utf8");
    const arr = txt
      .split(/\r?\n/)
      .map((s) => s.trim())
      .filter(Boolean);
    if (arr.length) return arr;
  } catch {}
  return ["2024-25", "2025-26"];
}

async function saveTaxYears(years) {
  await writeTextFile(TAXYEARS_FILE, years.join(os.EOL) + os.EOL);
}

function clientInfoTemplate(type) {
  return (
`Client Type: ${type}
Client Status: Active
Client Tag:
Directors Count: 1
Bookkeeping Required: No
VAT Registered: No
Payroll Required: No
MTD Required (ITSA): No
Other extra-service: No

UTR:
CRN:
VAT Number:
PAYE Reference:
Notes:
`
  );
}

function boolToYesNo(b) { return b ? "Yes" : "No"; }

function buildClientTag({ type, bk, vat, paye, mtd, extra, directors }) {
  let tag = `${type}`;
  tag += ` | BK:${bk ? "Y" : "N"}`;
  tag += ` | VAT:${vat ? "Y" : "N"}`;
  tag += ` | PAYE:${paye ? "Y" : "N"}`;
  tag += ` | MTD:${mtd ? "Y" : "N"}`;
  tag += ` | EXTRA:${extra ? "Y" : "N"}`;
  if (type === "Limited Company") tag += ` | DIR:${directors}`;
  return tag;
}

function setLine(txt, label, value) {
  const re = new RegExp(`^${label}:.*$`, "m");
  const line = `${label}: ${value}`;
  if (re.test(txt)) return txt.replace(re, line);
  return line + os.EOL + txt;
}

async function ensureClientInfo(clientPath, type) {
  const infoPath = path.join(clientPath, "Client Info.txt");
  if (await fileExists(infoPath)) return;
  await writeTextFile(infoPath, clientInfoTemplate(type));
}

async function updateClientInfo(clientPath, data) {
  const infoPath = path.join(clientPath, "Client Info.txt");
  await ensureClientInfo(clientPath, data.type);

  let txt = await readTextFile(infoPath);

  txt = setLine(txt, "Client Type", data.type);
  txt = setLine(txt, "Client Status", "Active");
  txt = setLine(txt, "Directors Count", String(data.directors || 1));
  txt = setLine(txt, "Bookkeeping Required", boolToYesNo(data.bk));
  txt = setLine(txt, "VAT Registered", boolToYesNo(data.vat));
  txt = setLine(txt, "Payroll Required", boolToYesNo(data.paye));
  txt = setLine(txt, "MTD Required (ITSA)", boolToYesNo(data.mtd));
  txt = setLine(txt, "Other extra-service", boolToYesNo(data.extra));

  const tag = buildClientTag(data);
  txt = setLine(txt, "Client Tag", tag);

  await writeTextFile(infoPath, txt);
}

async function listClients() {
  ensureDir(CLIENTS_BASE);
  const entries = await fsp.readdir(CLIENTS_BASE, { withFileTypes: true });
  return entries
    .filter((e) => e.isDirectory())
    .filter((e) => e.name !== "99 Archived Clients")
    .map((e) => e.name)
    .sort((a, b) => a.localeCompare(b));
}

/**
 * ========= Folder Structure Builders =========
 */

async function createTaxYearFolders(basePath, taxYears) {
  ensureDir(basePath);
  for (const y of taxYears) ensureDir(path.join(basePath, y));
}

function createIdPack(root) {
  ensureDir(path.join(root, "01 Passport - BRP - eVisa"));
  ensureDir(path.join(root, "02 Proof of Address"));
  ensureDir(path.join(root, "03 Signed Engagement Letter"));
}

function createSA_Subfolders(yearPath) {
  ensureDir(path.join(yearPath, "01 Income"));
  ensureDir(path.join(yearPath, "02 Expenses"));
  ensureDir(path.join(yearPath, "03 Bank"));
  ensureDir(path.join(yearPath, "04 CIS (if any)"));
  ensureDir(path.join(yearPath, "05 Pensions & Benefits"));
  ensureDir(path.join(yearPath, "06 Other Documents"));
  ensureDir(path.join(yearPath, "99 Final & Submitted"));
}

function createProperty_Subfolders(yearPath) {
  ensureDir(path.join(yearPath, "01 Rental Income"));
  ensureDir(path.join(yearPath, "02 Expenses"));
  ensureDir(path.join(yearPath, "03 Mortgage Interest"));
  ensureDir(path.join(yearPath, "04 Letting Agent"));
  ensureDir(path.join(yearPath, "99 Final & Submitted"));
}

function createCorpTax_Subfolders(yearPath) {
  ensureDir(path.join(yearPath, "01 Trial Balance"));
  ensureDir(path.join(yearPath, "02 Adjustments"));
  ensureDir(path.join(yearPath, "03 Computation"));
  ensureDir(path.join(yearPath, "04 CT600 & iXBRL"));
  ensureDir(path.join(yearPath, "99 Final & Submitted"));
}

function createAccounts_Subfolders(yearPath) {
  ensureDir(path.join(yearPath, "01 Bank"));
  ensureDir(path.join(yearPath, "02 Sales"));
  ensureDir(path.join(yearPath, "03 Purchases"));
  ensureDir(path.join(yearPath, "04 Payroll"));
  ensureDir(path.join(yearPath, "05 Fixed Assets"));
  ensureDir(path.join(yearPath, "99 Year End Pack"));
}

function ensureExtraService(clientPath) {
  const root = path.join(clientPath, "03 Other Services", "01 Other extra-service");
  ensureDir(root);
  ensureDir(path.join(root, "01 Client Documents"));
  ensureDir(path.join(root, "02 Our Work (Drafts)"));
  ensureDir(path.join(root, "03 Submitted"));
  ensureDir(path.join(root, "99 Outcome"));
}

async function deleteFolderIfExists(fullPath) {
  if (await dirExists(fullPath)) {
    await fsp.rm(fullPath, { recursive: true, force: true });
  }
}

async function applySelfEmployed(clientPath, flags, taxYears) {
  // Proof of ID
  const idRoot = path.join(clientPath, "00 Proof of ID");
  ensureDir(idRoot);
  createIdPack(idRoot);

  // Bookkeeping
  if (flags.bk) {
    const bkRoot = path.join(clientPath, "01 Bookkeeping");
    ensureDir(bkRoot);
    await createTaxYearFolders(path.join(bkRoot, "01 Source Documents"), taxYears);
    await createTaxYearFolders(path.join(bkRoot, "02 Bank"), taxYears);
    await createTaxYearFolders(path.join(bkRoot, "03 Income"), taxYears);
    await createTaxYearFolders(path.join(bkRoot, "04 Expenses"), taxYears);
  }

  // Compliance - Self Assessment
  const saRoot = path.join(clientPath, "02 Compliance", "01 Self Assessment");
  ensureDir(saRoot);
  for (const y of taxYears) {
    const yp = path.join(saRoot, y);
    ensureDir(yp);
    createSA_Subfolders(yp);
  }

  // MTD / VAT / PAYE
  if (flags.mtd) await createTaxYearFolders(path.join(clientPath, "02 Compliance", "02 MTD (ITSA)"), taxYears);
  if (flags.vat) await createTaxYearFolders(path.join(clientPath, "02 Compliance", "03 VAT"), taxYears);
  if (flags.paye) await createTaxYearFolders(path.join(clientPath, "02 Compliance", "04 PAYE"), taxYears);

  if (flags.extra) ensureExtraService(clientPath);
}

async function applyLandlord(clientPath, flags, taxYears) {
  const idRoot = path.join(clientPath, "00 Proof of ID");
  ensureDir(idRoot);
  createIdPack(idRoot);

  if (flags.bk) {
    const bkRoot = path.join(clientPath, "01 Bookkeeping");
    ensureDir(bkRoot);
    await createTaxYearFolders(path.join(bkRoot, "01 Bank"), taxYears);
    await createTaxYearFolders(path.join(bkRoot, "02 Rental Income"), taxYears);
    await createTaxYearFolders(path.join(bkRoot, "03 Expenses"), taxYears);
  }

  const saRoot = path.join(clientPath, "02 Compliance", "01 Self Assessment");
  ensureDir(saRoot);
  for (const y of taxYears) {
    const yp = path.join(saRoot, y);
    ensureDir(yp);
    createSA_Subfolders(yp);
  }

  const propRoot = path.join(clientPath, "02 Compliance", "02 Property Income");
  ensureDir(propRoot);
  for (const y of taxYears) {
    const yp = path.join(propRoot, y);
    ensureDir(yp);
    createProperty_Subfolders(yp);
  }

  if (flags.mtd) await createTaxYearFolders(path.join(clientPath, "02 Compliance", "03 MTD (ITSA)"), taxYears);

  if (flags.extra) ensureExtraService(clientPath);
}

function ensureDirectorFolders(clientPath, directors) {
  const root = path.join(clientPath, "00 Proof of ID - Directors");
  ensureDir(root);
  for (let i = 1; i <= directors; i++) {
    const name = `Director ${String(i).padStart(2, "0")}`;
    const dPath = path.join(root, name);
    ensureDir(dPath);
    createIdPack(dPath);
  }
}

async function deleteExtraDirectorFolders(clientPath, keepCount) {
  const root = path.join(clientPath, "00 Proof of ID - Directors");
  if (!(await dirExists(root))) return;
  const entries = await fsp.readdir(root, { withFileTypes: true });
  for (const e of entries) {
    if (!e.isDirectory()) continue;
    const m = e.name.match(/Director\s+(\d+)/i);
    if (!m) continue;
    const n = parseInt(m[1], 10);
    if (n > keepCount) await deleteFolderIfExists(path.join(root, e.name));
  }
}

async function applyLimitedCompany(clientPath, flags, taxYears) {
  ensureDirectorFolders(clientPath, flags.directors);

  if (flags.bk) {
    const bkRoot = path.join(clientPath, "01 Bookkeeping");
    ensureDir(bkRoot);
    await createTaxYearFolders(path.join(bkRoot, "01 Bank"), taxYears);
    await createTaxYearFolders(path.join(bkRoot, "02 Sales"), taxYears);
    await createTaxYearFolders(path.join(bkRoot, "03 Purchases"), taxYears);
  }

  const ctRoot = path.join(clientPath, "02 Compliance", "01 Corporation Tax");
  ensureDir(ctRoot);
  for (const y of taxYears) {
    const yp = path.join(ctRoot, y);
    ensureDir(yp);
    createCorpTax_Subfolders(yp);
  }

  const accRoot = path.join(clientPath, "02 Compliance", "02 Accounts");
  ensureDir(accRoot);
  for (const y of taxYears) {
    const yp = path.join(accRoot, y);
    ensureDir(yp);
    createAccounts_Subfolders(yp);
  }

  if (flags.vat) await createTaxYearFolders(path.join(clientPath, "02 Compliance", "03 VAT"), taxYears);
  if (flags.paye) await createTaxYearFolders(path.join(clientPath, "02 Compliance", "04 PAYE"), taxYears);

  if (flags.extra) ensureExtraService(clientPath);
}

async function applyOtherClient(clientPath, flags) {
  const idRoot = path.join(clientPath, "00 Proof of ID");
  ensureDir(idRoot);
  createIdPack(idRoot);
  if (flags.extra) ensureExtraService(clientPath);
}

async function applyClientStructure(clientPath, flags, taxYears) {
  // Handle opt-out deletes (only service areas)
  // Bookkeeping
  if (!flags.bk) await deleteFolderIfExists(path.join(clientPath, "01 Bookkeeping"));

  // Extra service
  if (!flags.extra) {
    await deleteFolderIfExists(path.join(clientPath, "03 Other Services", "01 Other extra-service"));
    // remove parent if empty-ish
    const otherRoot = path.join(clientPath, "03 Other Services");
    // ignore errors
    try { await fsp.rmdir(otherRoot); } catch {}
  }

  // Type-specific deletes for compliance services
  if (flags.type === "Self-Employed") {
    if (!flags.mtd) await deleteFolderIfExists(path.join(clientPath, "02 Compliance", "02 MTD (ITSA)"));
    if (!flags.vat) await deleteFolderIfExists(path.join(clientPath, "02 Compliance", "03 VAT"));
    if (!flags.paye) await deleteFolderIfExists(path.join(clientPath, "02 Compliance", "04 PAYE"));
  }

  if (flags.type === "Landlord") {
    if (!flags.mtd) await deleteFolderIfExists(path.join(clientPath, "02 Compliance", "03 MTD (ITSA)"));
  }

  if (flags.type === "Limited Company") {
    // No MTD for Ltd
    flags.mtd = false;
    if (!flags.vat) await deleteFolderIfExists(path.join(clientPath, "02 Compliance", "03 VAT"));
    if (!flags.paye) await deleteFolderIfExists(path.join(clientPath, "02 Compliance", "04 PAYE"));
    await deleteExtraDirectorFolders(clientPath, flags.directors);
  }

  // Apply structure
  if (flags.type === "Self-Employed") await applySelfEmployed(clientPath, flags, taxYears);
  else if (flags.type === "Landlord") await applyLandlord(clientPath, flags, taxYears);
  else if (flags.type === "Limited Company") await applyLimitedCompany(clientPath, flags, taxYears);
  else await applyOtherClient(clientPath, flags);
}

/**
 * ========= API =========
 */

app.get("/api/status", requireAuth, async (req, res) => {
  res.json({ ok: true, base: BASE, clientsBase: CLIENTS_BASE, today: todayISO() });
});

app.get("/api/folders", requireAuth, async (req, res) => {
  res.json({
    folders: [
      { name: "01 Work", path: path.join(BASE, "01 Work") },
      { name: "02 Clients", path: CLIENTS_BASE },
      { name: "03 Finance", path: path.join(BASE, "03 Finance") },
      { name: "04 Personal", path: path.join(BASE, "04 Personal") },
      { name: "05 Downloads", path: path.join(BASE, "05 Downloads") },
    ],
  });
});

app.post("/api/open", requireAuth, async (req, res) => {
  const p = req.body?.path;
  if (!p || typeof p !== "string") return res.status(400).json({ error: "path required" });

  // Safety: only allow opening inside BASE
  const resolved = path.resolve(p);
  const baseResolved = path.resolve(BASE);
  if (!resolved.startsWith(baseResolved)) return res.status(400).json({ error: "Path not allowed" });

  ensureDir(resolved);
  openInExplorer(resolved);
  res.json({ ok: true });
});

app.get("/api/clients", requireAuth, async (req, res) => {
  const clients = await listClients();
  res.json({ clients });
});

app.get("/api/taxyears", requireAuth, async (req, res) => {
  const years = await loadTaxYears();
  res.json({ years });
});

app.post("/api/taxyears/add", requireAuth, async (req, res) => {
  const y = String(req.body?.year || "").trim();
  if (!y) return res.status(400).json({ error: "year required" });

  const years = await loadTaxYears();
  if (years.includes(y)) return res.json({ ok: true, years });

  years.push(y);
  await saveTaxYears(years);

  // Create for all clients
  const clients = await listClients();
  for (const c of clients) {
    const p = path.join(CLIENTS_BASE, c);
    // We can’t safely detect flags without parsing Client Info fully here, but we still create year folders
    // by ensuring structures when client is updated/created.
    // For now just create skeleton Self Assessment year folders if exists:
    const sa = path.join(p, "02 Compliance", "01 Self Assessment", y);
    ensureDir(sa);
    createSA_Subfolders(sa);
    const prop = path.join(p, "02 Compliance", "02 Property Income", y);
    if (fs.existsSync(path.join(p, "02 Compliance", "02 Property Income"))) {
      ensureDir(prop);
      createProperty_Subfolders(prop);
    }
    const ct = path.join(p, "02 Compliance", "01 Corporation Tax", y);
    if (fs.existsSync(path.join(p, "02 Compliance", "01 Corporation Tax"))) {
      ensureDir(ct);
      createCorpTax_Subfolders(ct);
    }
    const acc = path.join(p, "02 Compliance", "02 Accounts", y);
    if (fs.existsSync(path.join(p, "02 Compliance", "02 Accounts"))) {
      ensureDir(acc);
      createAccounts_Subfolders(acc);
    }
  }

  res.json({ ok: true, years });
});

app.post("/api/base/create-missing", requireAuth, async (req, res) => {
  // Create base folders recommended
  ensureDir(path.join(BASE, "01 Work", "01 Admin & Compliance"));
  ensureDir(path.join(BASE, "01 Work", "02 Templates"));
  ensureDir(path.join(BASE, "01 Work", "03 Marketing"));
  ensureDir(path.join(BASE, "01 Work", "04 Projects"));
  ensureDir(path.join(BASE, "01 Work", "99 TEMP - Sort Later"));

  ensureDir(path.join(BASE, "03 Finance", "01 Bank"));
  ensureDir(path.join(BASE, "03 Finance", "02 Sales"));
  ensureDir(path.join(BASE, "03 Finance", "03 Expenses"));
  ensureDir(path.join(BASE, "03 Finance", "04 Tax"));
  ensureDir(path.join(BASE, "03 Finance", "05 Payroll"));
  ensureDir(path.join(BASE, "03 Finance", "06 Reports"));
  ensureDir(path.join(BASE, "03 Finance", "99 Year End Packs"));

  const people = ["Liyou", "Rediat", "Leul", "Barok", "Hosea", "Other"];
  for (const person of people) {
    ensureDir(path.join(BASE, "04 Personal", person, "Photo"));
    ensureDir(path.join(BASE, "04 Personal", person, "Documents"));
  }

  ensureDir(CLIENTS_BASE);

  res.json({ ok: true });
});

app.post("/api/client/create", requireAuth, async (req, res) => {
  const name = String(req.body?.name || "").trim();
  const type = String(req.body?.type || "").trim();
  if (!name) return res.status(400).json({ error: "name required" });
  if (!type) return res.status(400).json({ error: "type required" });

  const clientPath = path.join(CLIENTS_BASE, name);
  ensureDir(clientPath);

  await ensureClientInfo(clientPath, type);

  // Apply structure with flags
  const years = await loadTaxYears();
  const flags = {
    type,
    bk: !!req.body?.bk,
    vat: !!req.body?.vat,
    paye: !!req.body?.paye,
    mtd: !!req.body?.mtd,
    extra: !!req.body?.extra,
    directors: Math.max(1, parseInt(req.body?.directors || 1, 10) || 1),
  };

  await applyClientStructure(clientPath, flags, years);
  await updateClientInfo(clientPath, flags);

  res.json({ ok: true, path: clientPath });
});

app.post("/api/client/update", requireAuth, async (req, res) => {
  const name = String(req.body?.name || "").trim();
  const type = String(req.body?.type || "").trim();
  if (!name) return res.status(400).json({ error: "name required" });
  if (!type) return res.status(400).json({ error: "type required" });

  const clientPath = path.join(CLIENTS_BASE, name);
  ensureDir(clientPath);

  const years = await loadTaxYears();
  const flags = {
    type,
    bk: !!req.body?.bk,
    vat: !!req.body?.vat,
    paye: !!req.body?.paye,
    mtd: !!req.body?.mtd,
    extra: !!req.body?.extra,
    directors: Math.max(1, parseInt(req.body?.directors || 1, 10) || 1),
  };

  await applyClientStructure(clientPath, flags, years);
  await updateClientInfo(clientPath, flags);

  res.json({ ok: true });
});

/**
 * ========= UI =========
 */
app.get("/", (req, res) => {
  res.type("html").send(`
<!doctype html>
<html>
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width,initial-scale=1" />
  <title>Habesha Folder Manager</title>
  <style>
    body { font-family: system-ui, -apple-system, Segoe UI, Roboto, Arial; margin: 18px; }
    .card { border: 1px solid #ddd; border-radius: 12px; padding: 14px; margin: 12px 0; }
    button { padding: 10px 12px; border-radius: 10px; border: 1px solid #ccc; background: #fff; cursor: pointer; }
    button:hover { background: #f6f6f6; }
    .row { display: flex; gap: 10px; flex-wrap: wrap; }
    input, select { padding: 10px; border-radius: 10px; border: 1px solid #ccc; width: 100%; max-width: 420px; }
    label { display:block; margin-top: 10px; }
    .small { font-size: 13px; color: #666; }
    .ok { color: #0a7; }
    .err { color: #c00; }
    .pill { display:inline-block; padding: 2px 8px; border:1px solid #ddd; border-radius: 999px; font-size:12px; margin-left:6px; }
    .grid { display:grid; grid-template-columns: 1fr; gap: 10px; }
    @media(min-width: 900px){ .grid { grid-template-columns: 1fr 1fr; } }
  </style>
</head>
<body>
  <h2>Habesha Folder Manager <span class="pill">Web</span></h2>
  <p class="small">Runs on your Windows PC. Open this page from iPad/phone on the same WiFi.</p>

  <div class="card">
    <h3>1) Login</h3>
    <label>Token (X-Auth-Token)</label>
    <input id="token" placeholder="Enter token..." />
    <div class="row" style="margin-top:10px;">
      <button onclick="saveToken()">Save Token</button>
      <button onclick="loadAll()">Connect</button>
    </div>
    <div id="status" class="small"></div>
  </div>

  <div class="grid">
    <div class="card">
      <h3>2) Quick Open (opens on PC)</h3>
      <div id="folderBtns" class="row"></div>
      <div class="small">Tip: On mobile this triggers Explorer to open on your PC.</div>
      <div style="margin-top:10px;">
        <button onclick="createBase()">Create Missing Base Folders</button>
        <span id="baseMsg" class="small"></span>
      </div>
    </div>

    <div class="card">
      <h3>3) Tax Years</h3>
      <div id="years" class="small"></div>
      <div class="row" style="margin-top:10px;">
        <input id="newYear" placeholder="Add tax year e.g. 2026-27" />
        <button onclick="addYear()">Add</button>
      </div>
      <div id="yearMsg" class="small"></div>
    </div>
  </div>

  <div class="grid">
    <div class="card">
      <h3>4) Create New Client</h3>
      <label>Client name</label>
      <input id="cName" placeholder="e.g. Bright SG Ltd" />
      <label>Client type</label>
      <select id="cType" onchange="typeChanged()">
        <option>Self-Employed</option>
        <option>Landlord</option>
        <option>Limited Company</option>
        <option>Other Client</option>
      </select>

      <label>Directors (Limited Company)</label>
      <input id="directors" type="number" min="1" value="1" />

      <label><input type="checkbox" id="bk" /> Bookkeeping</label>
      <label><input type="checkbox" id="vat" /> VAT</label>
      <label><input type="checkbox" id="paye" /> Payroll (PAYE)</label>
      <label><input type="checkbox" id="mtd" /> MTD (ITSA)</label>
      <label><input type="checkbox" id="extra" /> Other extra-service</label>

      <div class="row" style="margin-top:10px;">
        <button onclick="createClient()">Create</button>
      </div>
      <div id="createMsg" class="small"></div>
    </div>

    <div class="card">
      <h3>5) Update Client Registration</h3>
      <label>Select client</label>
      <select id="uClient"></select>

      <label>Client type</label>
      <select id="uType" onchange="uTypeChanged()">
        <option>Self-Employed</option>
        <option>Landlord</option>
        <option>Limited Company</option>
        <option>Other Client</option>
      </select>

      <label>Directors (Limited Company)</label>
      <input id="uDirectors" type="number" min="1" value="1" />

      <label><input type="checkbox" id="uBK" /> Bookkeeping</label>
      <label><input type="checkbox" id="uVAT" /> VAT</label>
      <label><input type="checkbox" id="uPAYE" /> Payroll (PAYE)</label>
      <label><input type="checkbox" id="uMTD" /> MTD (ITSA)</label>
      <label><input type="checkbox" id="uExtra" /> Other extra-service</label>

      <div class="row" style="margin-top:10px;">
        <button onclick="updateClient()">Save / Apply</button>
      </div>
      <div id="updateMsg" class="small"></div>
      <p class="small">Note: unticking a service removes its folders (Bookkeeping / VAT / PAYE / MTD / Extra).</p>
    </div>
  </div>

<script>
  function getToken(){ return localStorage.getItem("habesha_token") || ""; }
  function setToken(t){ localStorage.setItem("habesha_token", t); }

  document.getElementById("token").value = getToken();

  function saveToken(){
    setToken(document.getElementById("token").value.trim());
    document.getElementById("status").innerHTML = "<span class='ok'>Saved.</span>";
  }

  async function api(path, options={}){
    const token = getToken();
    const headers = Object.assign({}, options.headers||{}, {
      "Content-Type":"application/json",
      "X-Auth-Token": token
    });
    const res = await fetch(path, Object.assign({}, options, { headers }));
    const data = await res.json().catch(()=> ({}));
    if(!res.ok) throw new Error(data.error || ("HTTP " + res.status));
    return data;
  }

  function typeChanged(){
    const t = document.getElementById("cType").value;
    document.getElementById("directors").disabled = (t !== "Limited Company");
    document.getElementById("mtd").disabled = (t === "Limited Company");
  }
  function uTypeChanged(){
    const t = document.getElementById("uType").value;
    document.getElementById("uDirectors").disabled = (t !== "Limited Company");
    document.getElementById("uMTD").disabled = (t === "Limited Company");
  }

  async function loadAll(){
    try{
      const st = await api("/api/status");
      document.getElementById("status").innerHTML = "<span class='ok'>Connected.</span> Base: " + st.base;

      const f = await api("/api/folders");
      const wrap = document.getElementById("folderBtns");
      wrap.innerHTML = "";
      f.folders.forEach(item=>{
        const b = document.createElement("button");
        b.textContent = item.name;
        b.onclick = ()=> openFolder(item.path);
        wrap.appendChild(b);
      });

      const y = await api("/api/taxyears");
      document.getElementById("years").textContent = "Tax years: " + y.years.join(", ");

      const c = await api("/api/clients");
      const ddl = document.getElementById("uClient");
      ddl.innerHTML = "";
      c.clients.forEach(name=>{
        const opt = document.createElement("option");
        opt.textContent = name;
        ddl.appendChild(opt);
      });

      typeChanged(); uTypeChanged();
    } catch(e){
      document.getElementById("status").innerHTML = "<span class='err'>"+e.message+"</span>";
    }
  }

  async function openFolder(p){
    try{
      await api("/api/open", { method:"POST", body: JSON.stringify({ path:p }) });
    }catch(e){
      alert(e.message);
    }
  }

  async function createBase(){
    const el = document.getElementById("baseMsg");
    el.textContent = "Working...";
    try{
      await api("/api/base/create-missing", { method:"POST", body:"{}" });
      el.innerHTML = "<span class='ok'>Done.</span>";
    }catch(e){
      el.innerHTML = "<span class='err'>"+e.message+"</span>";
    }
  }

  async function addYear(){
    const y = document.getElementById("newYear").value.trim();
    const el = document.getElementById("yearMsg");
    el.textContent = "Working...";
    try{
      const out = await api("/api/taxyears/add", { method:"POST", body: JSON.stringify({ year:y })});
      document.getElementById("years").textContent = "Tax years: " + out.years.join(", ");
      el.innerHTML = "<span class='ok'>Added.</span>";
      document.getElementById("newYear").value = "";
    }catch(e){
      el.innerHTML = "<span class='err'>"+e.message+"</span>";
    }
  }

  async function createClient(){
    const msg = document.getElementById("createMsg");
    msg.textContent = "Creating...";
    try{
      const body = {
        name: document.getElementById("cName").value.trim(),
        type: document.getElementById("cType").value,
        directors: parseInt(document.getElementById("directors").value || "1", 10),
        bk: document.getElementById("bk").checked,
        vat: document.getElementById("vat").checked,
        paye: document.getElementById("paye").checked,
        mtd: document.getElementById("mtd").checked,
        extra: document.getElementById("extra").checked,
      };
      const out = await api("/api/client/create", { method:"POST", body: JSON.stringify(body) });
      msg.innerHTML = "<span class='ok'>Created:</span> " + out.path;

      await loadAll();
      document.getElementById("cName").value = "";
    }catch(e){
      msg.innerHTML = "<span class='err'>"+e.message+"</span>";
    }
  }

  async function updateClient(){
    const msg = document.getElementById("updateMsg");
    msg.textContent = "Updating...";
    try{
      const body = {
        name: document.getElementById("uClient").value,
        type: document.getElementById("uType").value,
        directors: parseInt(document.getElementById("uDirectors").value || "1", 10),
        bk: document.getElementById("uBK").checked,
        vat: document.getElementById("uVAT").checked,
        paye: document.getElementById("uPAYE").checked,
        mtd: document.getElementById("uMTD").checked,
        extra: document.getElementById("uExtra").checked,
      };
      await api("/api/client/update", { method:"POST", body: JSON.stringify(body) });
      msg.innerHTML = "<span class='ok'>Updated.</span>";
    }catch(e){
      msg.innerHTML = "<span class='err'>"+e.message+"</span>";
    }
  }
</script>
</body>
</html>
  `);
});

/**
 * ========= Start =========
 */
ensureDir(BASE);
ensureDir(CLIENTS_BASE);

app.listen(PORT, "0.0.0.0", () => {
  console.log(`Habesha web running on http://localhost:${PORT}`);
  console.log(`Token (X-Auth-Token): ${AUTH_TOKEN}`);
});
