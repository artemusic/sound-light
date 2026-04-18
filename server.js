/**
 * Artemusic – Backend leggero con Node.js/Express
 * Gestione file riservata: admin può creare cartelle, caricare, rinominare, eliminare file.
 * Utente normale può solo scaricare/condividere.
 */

const express   = require('express');
const multer    = require('multer');
const archiver  = require('archiver');
const session   = require('express-session');
const path      = require('path');
const fs        = require('fs');
const crypto    = require('crypto');

const app  = express();
const PORT = 3000;

// ──────────────────────────────────────────────
// CONFIGURAZIONE PASSWORDS
// ──────────────────────────────────────────────
const ADMIN_PASSWORD    = '260264';       // admin: accesso totale + importo
const USER_PASSWORD     = 'ing260264';    // area riservata documenti
const CALENDAR_PASSWORD = 'tecnico260264'; // calendario tecnici (solo lettura)
const FRATELLI_PASSWORD = '260264';       // stessa del admin (stesso accesso)

// ──────────────────────────────────────────────
// CARTELLA DOCUMENTI (root del file manager)
// ──────────────────────────────────────────────
const DOCS_ROOT = path.join(__dirname, 'documenti');
if (!fs.existsSync(DOCS_ROOT)) fs.mkdirSync(DOCS_ROOT, { recursive: true });

// ──────────────────────────────────────────────
// MIDDLEWARE
// ──────────────────────────────────────────────
app.set('trust proxy', 1); // necessario dietro reverse proxy / sandbox

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(session({
  secret: crypto.randomBytes(32).toString('hex'),
  resave: false,
  saveUninitialized: false,
  cookie: {
    maxAge:   8 * 60 * 60 * 1000, // 8 ore
    sameSite: 'lax',
    secure:   false   // il proxy gestisce HTTPS, qui HTTP interno
  }
}));

// File statici (HTML, CSS, immagini, MP3…) serviti dalla root
app.use(express.static(__dirname, {
  index: 'index.html',
  // non indicizzare la cartella documenti via static (sarà gestita dall'API)
  setHeaders: (res, filePath) => {
    if (filePath.startsWith(DOCS_ROOT)) {
      res.status(403).end();
    }
  }
}));

// ──────────────────────────────────────────────
// HELPER: risolvi un path sicuro dentro DOCS_ROOT
// ──────────────────────────────────────────────
function safePath(relPath) {
  const full = path.resolve(DOCS_ROOT, relPath || '');
  if (!full.startsWith(DOCS_ROOT)) return null;   // path traversal guard
  return full;
}

function relToDocs(absPath) {
  return path.relative(DOCS_ROOT, absPath);
}

// ──────────────────────────────────────────────
// AUTH API
// ──────────────────────────────────────────────

// POST /api/login
app.post('/api/login', (req, res) => {
  const { password } = req.body;
  // Admin: accesso totale (file manager + calendario + importo)
  if (password === ADMIN_PASSWORD) {
    req.session.role = 'admin';
    return res.json({ ok: true, role: 'admin' });
  }
  // Tecnico calendario: vede solo il calendario (no importo, no file manager)
  if (password === CALENDAR_PASSWORD) {
    req.session.role = 'tecnico';
    return res.json({ ok: true, role: 'tecnico' });
  }
  // Ingegnere area riservata: accede ai documenti (no calendario admin, no importo)
  if (password === USER_PASSWORD) {
    req.session.role = 'user';
    return res.json({ ok: true, role: 'user' });
  }
  res.status(401).json({ ok: false, message: 'Password errata' });
});

// POST /api/logout
app.post('/api/logout', (req, res) => {
  req.session.destroy();
  res.json({ ok: true });
});

// GET /api/me
app.get('/api/me', (req, res) => {
  if (!req.session.role) return res.status(401).json({ ok: false });
  res.json({ ok: true, role: req.session.role });
});

// ──────────────────────────────────────────────
// MIDDLEWARE: controllo autenticazione
// ──────────────────────────────────────────────
function requireAuth(req, res, next) {
  if (!req.session.role) return res.status(401).json({ ok: false, message: 'Non autenticato' });
  next();
}

function requireAdmin(req, res, next) {
  if (req.session.role !== 'admin') return res.status(403).json({ ok: false, message: 'Solo admin' });
  next();
}

// Può accedere ai dati finanziari (importo): solo admin
function requireFinance(req, res, next) {
  const r = req.session.role;
  if (r !== 'admin') return res.status(403).json({ ok: false, message: 'Accesso negato' });
  next();
}

// Può creare/modificare eventi: solo admin
function requireEventManager(req, res, next) {
  const r = req.session.role;
  if (r !== 'admin') return res.status(403).json({ ok: false, message: 'Solo admin' });
  next();
}

// ──────────────────────────────────────────────
// FILE MANAGER API
// ──────────────────────────────────────────────

// GET /api/files?path=sottocartella
// Restituisce l'elenco di file e cartelle in un dato percorso
app.get('/api/files', requireAuth, (req, res) => {
  const folder = safePath(req.query.path || '');
  if (!folder) return res.status(400).json({ ok: false, message: 'Percorso non valido' });

  if (!fs.existsSync(folder)) return res.status(404).json({ ok: false, message: 'Cartella non trovata' });

  // File da nascondere (tecnici / helper)
  const HIDDEN = new Set(['.keep', 'keep', 'index.html', '.gitkeep', '.DS_Store', 'Thumbs.db']);

  const entries = fs.readdirSync(folder, { withFileTypes: true })
    .filter(e => !HIDDEN.has(e.name) && !e.name.startsWith('.'))
    .map(e => {
      const fullPath = path.join(folder, e.name);
      const stat     = fs.statSync(fullPath);
      return {
        name:     e.name,
        isDir:    e.isDirectory(),
        size:     stat.size,
        modified: stat.mtime.toISOString(),
        path:     relToDocs(fullPath)
      };
    });

  // Ordina: cartelle prima, poi file per nome
  entries.sort((a, b) => {
    if (a.isDir !== b.isDir) return a.isDir ? -1 : 1;
    return a.name.localeCompare(b.name, 'it');
  });

  res.json({ ok: true, path: relToDocs(folder), entries });
});

// ──────────────────────────────────────────────
// UPLOAD (solo admin)
// ──────────────────────────────────────────────
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    const folder = safePath(req.body.path || req.query.path || '');
    if (!folder) return cb(new Error('Percorso non valido'));
    fs.mkdirSync(folder, { recursive: true });
    cb(null, folder);
  },
  filename: (req, file, cb) => {
    // Mantieni il nome originale (sanitizzato)
    const safe = file.originalname.replace(/[^a-zA-Z0-9._\-àèìòùÀÈÌÒÙ ]/g, '_');
    cb(null, safe);
  }
});
const upload = multer({ storage, limits: { fileSize: 200 * 1024 * 1024 } }); // max 200 MB

// POST /api/upload?path=sottocartella
app.post('/api/upload', requireAdmin, upload.array('files'), (req, res) => {
  const uploaded = req.files.map(f => ({
    name:     f.filename,
    size:     f.size,
    path:     relToDocs(f.path)
  }));
  res.json({ ok: true, uploaded });
});

// ──────────────────────────────────────────────
// CREA CARTELLA (solo admin)
// ──────────────────────────────────────────────
// POST /api/mkdir  { path: "...", name: "NuovaCartella" }
app.post('/api/mkdir', requireAdmin, (req, res) => {
  const { name } = req.body;
  if (!name) return res.status(400).json({ ok: false, message: 'Nome cartella mancante' });
  const safeName = name.replace(/[^a-zA-Z0-9._\-àèìòùÀÈÌÒÙ &]/g, '_');
  const folder = safePath(path.join(req.body.path || '', safeName));
  if (!folder) return res.status(400).json({ ok: false, message: 'Percorso non valido' });

  if (fs.existsSync(folder)) return res.status(409).json({ ok: false, message: 'Cartella già esistente' });
  fs.mkdirSync(folder, { recursive: true });
  res.json({ ok: true, path: relToDocs(folder) });
});

// ──────────────────────────────────────────────
// RINOMINA (solo admin)
// ──────────────────────────────────────────────
// POST /api/rename  { path: "percorso/vecchioNome", newName: "nuovoNome" }
app.post('/api/rename', requireAdmin, (req, res) => {
  const { newName } = req.body;
  if (!newName) return res.status(400).json({ ok: false, message: 'Nuovo nome mancante' });
  const src  = safePath(req.body.path || '');
  if (!src)   return res.status(400).json({ ok: false, message: 'Percorso non valido' });
  const safeName = newName.replace(/[^a-zA-Z0-9._\-àèìòùÀÈÌÒÙ &]/g, '_');
  const dest = path.join(path.dirname(src), safeName);
  if (!dest.startsWith(DOCS_ROOT)) return res.status(400).json({ ok: false, message: 'Destinazione non valida' });

  if (!fs.existsSync(src))  return res.status(404).json({ ok: false, message: 'File/cartella non trovata' });
  if (fs.existsSync(dest))  return res.status(409).json({ ok: false, message: 'Esiste già un elemento con quel nome' });

  fs.renameSync(src, dest);
  res.json({ ok: true, path: relToDocs(dest) });
});

// ──────────────────────────────────────────────
// ELIMINA (solo admin)
// ──────────────────────────────────────────────
// DELETE /api/delete?path=...
app.delete('/api/delete', requireAdmin, (req, res) => {
  const target = safePath(req.query.path || '');
  if (!target) return res.status(400).json({ ok: false, message: 'Percorso non valido' });
  if (!fs.existsSync(target)) return res.status(404).json({ ok: false, message: 'Non trovato' });

  const stat = fs.statSync(target);
  if (stat.isDirectory()) {
    fs.rmSync(target, { recursive: true, force: true });
  } else {
    fs.unlinkSync(target);
  }
  res.json({ ok: true });
});

// ──────────────────────────────────────────────
// DOWNLOAD singolo file
// ──────────────────────────────────────────────
// GET /api/download?path=...
app.get('/api/download', requireAuth, (req, res) => {
  const target = safePath(req.query.path || '');
  if (!target) return res.status(400).json({ ok: false, message: 'Percorso non valido' });
  if (!fs.existsSync(target)) return res.status(404).json({ ok: false, message: 'File non trovato' });

  const stat = fs.statSync(target);
  if (stat.isDirectory()) {
    // Scarica cartella come .zip
    res.setHeader('Content-Type', 'application/zip');
    res.setHeader('Content-Disposition', `attachment; filename="${path.basename(target)}.zip"`);
    const archive = archiver('zip', { zlib: { level: 5 } });
    archive.on('error', err => { console.error(err); res.status(500).end(); });
    archive.pipe(res);
    archive.directory(target, path.basename(target));
    archive.finalize();
  } else {
    res.download(target, path.basename(target));
  }
});

// ──────────────────────────────────────────────
// SHARE LINK (token temporaneo 24h – utile per WA/mail senza login)
// ──────────────────────────────────────────────
const shareTokens = new Map(); // token -> { filePath, expires }

// POST /api/share  { path: "..." }   → richiede autenticazione
app.post('/api/share', requireAuth, (req, res) => {
  const target = safePath(req.body.path || '');
  if (!target || !fs.existsSync(target)) return res.status(404).json({ ok: false, message: 'File non trovato' });

  const token   = crypto.randomBytes(16).toString('hex');
  const expires = Date.now() + 24 * 60 * 60 * 1000; // 24 ore
  shareTokens.set(token, { filePath: target, expires });

  // Rimuovi token scaduti ogni tanto
  for (const [t, v] of shareTokens) {
    if (v.expires < Date.now()) shareTokens.delete(t);
  }

  const host = req.headers.host;
  const protocol = req.headers['x-forwarded-proto'] || 'http';
  const shareUrl = `${protocol}://${host}/api/shared/${token}`;
  res.json({ ok: true, url: shareUrl, expires: new Date(expires).toISOString() });
});

// GET /api/shared/:token  → download pubblico (no login richiesto)
app.get('/api/shared/:token', (req, res) => {
  const entry = shareTokens.get(req.params.token);
  if (!entry || entry.expires < Date.now()) {
    shareTokens.delete(req.params.token);
    return res.status(410).send('Link scaduto o non valido');
  }
  const { filePath } = entry;
  if (!fs.existsSync(filePath)) return res.status(404).send('File non trovato');

  const stat = fs.statSync(filePath);
  if (stat.isDirectory()) {
    res.setHeader('Content-Type', 'application/zip');
    res.setHeader('Content-Disposition', `attachment; filename="${path.basename(filePath)}.zip"`);
    const archive = archiver('zip', { zlib: { level: 5 } });
    archive.on('error', err => res.status(500).end());
    archive.pipe(res);
    archive.directory(filePath, path.basename(filePath));
    archive.finalize();
  } else {
    res.download(filePath, path.basename(filePath));
  }
});

// ══════════════════════════════════════════════
// CALENDARIO EVENTI
// ══════════════════════════════════════════════
const EVENTS_FILE = path.join(__dirname, 'data', 'eventi.json');

// Assicura che la cartella data esista
if (!fs.existsSync(path.join(__dirname, 'data'))) {
  fs.mkdirSync(path.join(__dirname, 'data'), { recursive: true });
}
if (!fs.existsSync(EVENTS_FILE)) {
  fs.writeFileSync(EVENTS_FILE, JSON.stringify([], null, 2), 'utf8');
}

function readEvents() {
  try { return JSON.parse(fs.readFileSync(EVENTS_FILE, 'utf8')); }
  catch(e) { return []; }
}
function writeEvents(events) {
  fs.writeFileSync(EVENTS_FILE, JSON.stringify(events, null, 2), 'utf8');
}
function newId() {
  return Date.now().toString(36) + crypto.randomBytes(4).toString('hex');
}

// GET /api/eventi — tutti gli eventi (auth richiesta)
// L'importo viene restituito solo all'admin
app.get('/api/eventi', requireAuth, (req, res) => {
  const canSeeFinance = (req.session.role === 'admin');
  const eventi = readEvents().map(e => {
    if (!canSeeFinance) {
      const { importo, ...rest } = e;
      return rest;
    }
    return e;
  });
  res.json({ ok: true, eventi });
});

// POST /api/eventi — crea evento (admin e fratelli)
app.post('/api/eventi', requireEventManager, (req, res) => {
  const {
    titolo, data, oraInizio, oraFine,
    luogo, indirizzo,
    orarioLavoro,           // ora inizio lavoro tecnici
    dipendenti,             // array o stringa nomi
    merce,                  // materiale da portare
    note, colore, importo   // importo: solo admin/fratelli possono inserirlo
  } = req.body;

  if (!titolo || !data) return res.status(400).json({ ok: false, message: 'Titolo e data sono obbligatori' });

  const canSeeFinance = (req.session.role === 'admin');

  const evento = {
    id:            newId(),
    titolo:        String(titolo).trim(),
    data:          String(data).trim(),
    oraInizio:     String(oraInizio    || '').trim(),
    oraFine:       String(oraFine      || '').trim(),
    luogo:         String(luogo        || '').trim(),
    indirizzo:     String(indirizzo    || '').trim(),
    orarioLavoro:  String(orarioLavoro || '').trim(),
    dipendenti:    String(dipendenti   || '').trim(),
    merce:         String(merce        || '').trim(),
    note:          String(note         || '').trim(),
    colore:        String(colore       || '#e81c2e').trim(),
    importo:       canSeeFinance ? String(importo || '').trim() : '',
    creatoIl:      new Date().toISOString()
  };

  const events = readEvents();
  events.push(evento);
  writeEvents(events);

  // Crea automaticamente la cartella dell'evento in documenti/
  const folderName = `${evento.data} – ${evento.titolo}`.replace(/[<>:"/\\|?*]/g, '_');
  const folderPath = path.join(DOCS_ROOT, folderName);
  if (!fs.existsSync(folderPath)) fs.mkdirSync(folderPath, { recursive: true });

  res.json({ ok: true, evento });
});

// PUT /api/eventi/:id — modifica evento (admin e fratelli)
app.put('/api/eventi/:id', requireEventManager, (req, res) => {
  const events = readEvents();
  const idx = events.findIndex(e => e.id === req.params.id);
  if (idx === -1) return res.status(404).json({ ok: false, message: 'Evento non trovato' });

  const {
    titolo, data, oraInizio, oraFine,
    luogo, indirizzo, orarioLavoro,
    dipendenti, merce, note, colore, importo
  } = req.body;

  if (!titolo || !data) return res.status(400).json({ ok: false, message: 'Titolo e data sono obbligatori' });

  const canSeeFinance = (req.session.role === 'admin');

  events[idx] = {
    ...events[idx],
    titolo:       String(titolo).trim(),
    data:         String(data).trim(),
    oraInizio:    String(oraInizio    || '').trim(),
    oraFine:      String(oraFine      || '').trim(),
    luogo:        String(luogo        || '').trim(),
    indirizzo:    String(indirizzo    || '').trim(),
    orarioLavoro: String(orarioLavoro || '').trim(),
    dipendenti:   String(dipendenti   || '').trim(),
    merce:        String(merce        || '').trim(),
    note:         String(note         || '').trim(),
    colore:       String(colore       || events[idx].colore).trim(),
    importo:      canSeeFinance
                    ? String(importo !== undefined ? importo : (events[idx].importo || '')).trim()
                    : (events[idx].importo || ''),
    aggiornatoIl: new Date().toISOString()
  };
  writeEvents(events);
  res.json({ ok: true, evento: events[idx] });
});

// DELETE /api/eventi/:id — elimina evento (admin e fratelli)
app.delete('/api/eventi/:id', requireEventManager, (req, res) => {
  const events = readEvents();
  const idx = events.findIndex(e => e.id === req.params.id);
  if (idx === -1) return res.status(404).json({ ok: false, message: 'Evento non trovato' });
  events.splice(idx, 1);
  writeEvents(events);
  res.json({ ok: true });
});

// ──────────────────────────────────────────────
// AVVIO SERVER
// ──────────────────────────────────────────────
app.listen(PORT, '0.0.0.0', () => {
  console.log(`✅ Artemusic server running → http://0.0.0.0:${PORT}`);
});
