const express = require('express');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const sqlite3 = require('sqlite3').verbose();
const cors = require('cors');

const UPLOAD_DIR = path.join(__dirname, 'uploads');
if (!fs.existsSync(UPLOAD_DIR)) fs.mkdirSync(UPLOAD_DIR);

const dbFile = path.join(__dirname, 'data.sqlite');
const db = new sqlite3.Database(dbFile);

db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS files (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    filename TEXT,
    originalname TEXT,
    mimetype TEXT,
    size INTEGER,
    path TEXT,
    title TEXT,
    description TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);
});

const app = express();
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));
app.use('/uploads', express.static(UPLOAD_DIR));

const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, UPLOAD_DIR),
  filename: (req, file, cb) => {
    const unique = Date.now() + '-' + Math.round(Math.random() * 1e9);
    const ext = path.extname(file.originalname);
    cb(null, unique + ext);
  }
});
const upload = multer({ storage, limits: { fileSize: 200 * 1024 * 1024 } });

app.post('/api/upload', upload.single('file'), (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'No file' });
  const stmt = db.prepare(`INSERT INTO files (filename, originalname, mimetype, size, path) VALUES (?, ?, ?, ?, ?)`);
  stmt.run(req.file.filename, req.file.originalname, req.file.mimetype, req.file.size, '/uploads/' + req.file.filename, function (err) {
    if (err) return res.status(500).json({ error: 'DB error' });
    const id = this.lastID;
    res.json({ id, url: `/file/${id}` });
  });
  stmt.finalize();
});

app.get('/file/:id', (req, res) => {
  const id = Number(req.params.id);
  db.get(`SELECT * FROM files WHERE id = ?`, [id], (err, row) => {
    if (err) return res.status(500).send('DB error');
    if (!row) return res.status(404).send('Not found');
    // Serve simple page with file info and direct link
    res.send(`<!doctype html><html><head><meta charset="utf-8"><title>${row.originalname}</title></head><body style="background:#111;color:#ddd;font-family:Arial"><h1>${row.originalname}</h1><p>Type: ${row.mimetype}</p><p>Size: ${row.size}</p><p><a href="${row.path}">Direct file link</a></p></body></html>`);
  });
});

app.get('/api/files', (req, res) => {
  db.all(`SELECT * FROM files ORDER BY created_at DESC LIMIT 100`, [], (err, rows) => {
    if (err) return res.status(500).json({ error: 'DB error' });
    res.json(rows);
  });
});

app.put('/api/files/:id', (req, res) => {
  const id = Number(req.params.id);
  const { title, description } = req.body;
  db.run(`UPDATE files SET title = ?, description = ? WHERE id = ?`, [title || null, description || null, id], function (err) {
    if (err) return res.status(500).json({ error: 'DB error' });
    if (this.changes === 0) return res.status(404).json({ error: 'Not found' });
    res.json({ success: true });
  });
});

app.delete('/api/files/:id', (req, res) => {
  const id = Number(req.params.id);
  db.get(`SELECT * FROM files WHERE id = ?`, [id], (err, row) => {
    if (err) return res.status(500).json({ error: 'DB error' });
    if (!row) return res.status(404).json({ error: 'Not found' });
    // row.path is a URL path like '/uploads/filename'. For filesystem operations
    // use the stored filename and the UPLOAD_DIR to build the actual path.
    const filepath = path.join(UPLOAD_DIR, row.filename);
    fs.unlink(filepath, (unlinkErr) => {
      // ignore unlink errors where file is already missing, but still remove DB entry
      db.run(`DELETE FROM files WHERE id = ?`, [id], function (err2) {
        if (err2) return res.status(500).json({ error: 'DB error' });
        if (unlinkErr) console.warn('Warning: unlink error', unlinkErr);
        res.json({ success: true });
      });
    });
  });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on http://localhost:${PORT}`));
