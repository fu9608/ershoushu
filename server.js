/**
 * 校园二手书回收发布平台后端
 * 功能：需求发布（管理员）、需求列表（公开）、用户投稿（用户登录）、图片上传（公开）
 *      审核投稿（管理员）、用户登录/注册、我的投稿、删除回收需求（管理员）
 */
const express = require('express');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const cors = require('cors');
const sqlite3 = require('sqlite3').verbose();
const crypto = require('crypto');

const app = express();
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// 静态文件目录（上传图片与前端页面）
const PUBLIC_DIR = path.join(__dirname, 'public');
const UPLOAD_DIR = path.join(PUBLIC_DIR, 'uploads');
if (!fs.existsSync(PUBLIC_DIR)) fs.mkdirSync(PUBLIC_DIR);
if (!fs.existsSync(UPLOAD_DIR)) fs.mkdirSync(UPLOAD_DIR);
app.use('/static', express.static(PUBLIC_DIR));

// 简易管理员认证中间件
function requireAdmin(req, res, next) {
  const token = req.headers['x-admin-token'] || req.query.admin_token || (req.body && req.body.admin_token);
  const ADMIN_TOKEN = process.env.ADMIN_TOKEN || 'dev-admin'; // 生产环境请在 Render 上配置更复杂的密钥
  if (token !== ADMIN_TOKEN) {
    return res.status(403).json({ error: 'forbidden: admin only' });
  }
  next();
}

// 简易用户认证中间件（从 header x-user-token 解析 user_id）
function requireUser(req, res, next) {
  const token = req.headers['x-user-token'];
  if (!token) return res.status(401).json({ error: 'unauthorized: user token required' });
  const parts = String(token).split('|');
  const user_id = Number(parts[0]);
  if (!user_id) return res.status(401).json({ error: 'invalid token' });
  req.user_id = user_id;
  next();
}

// 简易密码哈希函数（演示用；生产建议使用 bcrypt）
function hashPassword(pw) {
  return crypto.createHash('sha256').update(pw).digest('hex');
}

// 配置 multer 处理图片上传
const storage = multer.diskStorage({
  destination: (_req, _file, cb) => cb(null, UPLOAD_DIR),
  filename: (_req, file, cb) => {
    const ext = path.extname(file.originalname);
    const name = `${Date.now()}-${Math.random().toString(36).slice(2)}${ext}`;
    cb(null, name);
  },
});
const upload = multer({ storage });

// 初始化 SQLite
const db = new sqlite3.Database(path.join(__dirname, 'data.db'));
db.serialize(() => {
  db.run(`
    CREATE TABLE IF NOT EXISTS recycle_demands (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      title TEXT NOT NULL,
      isbn TEXT,
      publisher TEXT,
      edition TEXT,
      required_quantity INTEGER NOT NULL,
      unit_price_min REAL,
      unit_price_max REAL,
      theme_color TEXT DEFAULT '#FF7A00',
      condition_requirements TEXT,
      campus TEXT,
      deadline TEXT,
      cover_image_url TEXT,
      status TEXT DEFAULT 'online',
      created_at TEXT,
      updated_at TEXT
    )
  `);
  db.run(`
    CREATE TABLE IF NOT EXISTS user_submissions (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      demand_id INTEGER,
      title TEXT NOT NULL,
      isbn TEXT,
      quantity INTEGER NOT NULL,
      condition_grade TEXT,
      expected_price REAL,
      images TEXT, -- JSON 数组字符串
      contact TEXT,
      status TEXT DEFAULT 'pending', -- pending/approved/rejected
      auto_quote REAL,
      final_quote REAL,
      reviewer_id TEXT,
      created_at TEXT,
      updated_at TEXT,
      user_id INTEGER
    )
  `);
  db.run(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      created_at TEXT
    )
  `);
});

// 工具函数
const now = () => new Date().toISOString();

// API: 用户注册
app.post('/api/auth/register', (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'username 与 password 为必填' });
  const stmt = db.prepare(`INSERT INTO users (username, password_hash, created_at) VALUES (?, ?, ?)`);
  stmt.run(username, hashPassword(password), now(), function (err) {
    if (err) {
      if (String(err.message).includes('UNIQUE')) return res.status(409).json({ error: '用户名已存在' });
      return res.status(500).json({ error: err.message });
    }
    res.json({ id: this.lastID, username });
  });
});

// API: 用户登录（返回简易 token，演示用）
app.post('/api/auth/login', (req, res) => {
  const { username, password } = req.body;
  db.get(`SELECT * FROM users WHERE username=?`, [username], (err, user) => {
    if (err) return res.status(500).json({ error: err.message });
    if (!user) return res.status(401).json({ error: '用户不存在' });
    if (user.password_hash !== hashPassword(password)) return res.status(401).json({ error: '密码错误' });
    const token = `${user.id}|${crypto.createHash('md5').update(user.username).digest('hex')}`; // 简单 token
    res.json({ token, user_id: user.id, username: user.username });
  });
});

// API: 创建回收需求（管理员专用）
app.post('/api/demands', requireAdmin, (req, res) => {
  const {
    title, isbn, publisher, edition,
    required_quantity, unit_price_min, unit_price_max,
    theme_color = '#FF7A00', condition_requirements,
    campus, deadline, cover_image_url, status = 'online'
  } = req.body;

  if (!title || !required_quantity) {
    return res.status(400).json({ error: 'title 与 required_quantity 为必填' });
  }

  const stmt = db.prepare(`
    INSERT INTO recycle_demands
    (title, isbn, publisher, edition, required_quantity, unit_price_min, unit_price_max,
     theme_color, condition_requirements, campus, deadline, cover_image_url, status, created_at, updated_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `);

  stmt.run(
    title, isbn || null, publisher || null, edition || null,
    Number(required_quantity), unit_price_min || null, unit_price_max || null,
    theme_color, condition_requirements || null, campus || null, deadline || null,
    cover_image_url || null, status, now(), now(),
    function (err) {
      if (err) return res.status(500).json({ error: err.message });
      res.json({ id: this.lastID });
    }
  );
});

// API: 删除回收需求（管理员专用）
app.delete('/api/demands/:id', requireAdmin, (req, res) => {
  const id = Number(req.params.id);
  if (!id) return res.status(400).json({ error: 'invalid demand id' });

  // 直接物理删除；如果你更偏好下线，可改为更新 status='offline'
  const stmt = db.prepare(`DELETE FROM recycle_demands WHERE id=?`);
  stmt.run(id, function (err) {
    if (err) return res.status(500).json({ error: err.message });
    res.json({ deleted: this.changes });
  });
});

// API: 回收需求列表（公开）
app.get('/api/demands', (_req, res) => {
  db.all(`SELECT * FROM recycle_demands WHERE status='online' ORDER BY created_at DESC`, (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(rows);
  });
});

// API: 上传图片（多图，公开）
app.post('/api/upload', upload.array('images', 6), (req, res) => {
  const files = (req.files || []).map(f => `/static/uploads/${f.filename}`);
  res.json({ files });
});

// 自动估价（简单规则）
function autoQuote(unitMin, unitMax, conditionGrade = '九成新') {
  const base = unitMax ?? unitMin ?? 0;
  const factor = conditionGrade.includes('九成') ? 1.0
    : conditionGrade.includes('八成') ? 0.85
    : conditionGrade.includes('七成') ? 0.7
    : conditionGrade.includes('有笔记') ? 0.75
    : 0.6;
  return Number((base * factor).toFixed(2));
}

// API: 用户投稿（需登录）
app.post('/api/submissions', requireUser, (req, res) => {
  const { demand_id, title, isbn, quantity, condition_grade, expected_price, images, contact } = req.body;
  if (!title || !quantity) return res.status(400).json({ error: 'title 与 quantity 为必填' });
  const user_id = req.user_id;

  const doInsert = (auto_quote) => {
    const stmt = db.prepare(`
      INSERT INTO user_submissions
      (demand_id, title, isbn, quantity, condition_grade, expected_price, images, contact,
       status, auto_quote, final_quote, reviewer_id, created_at, updated_at, user_id)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'pending', ?, NULL, NULL, ?, ?, ?)
    `);
    stmt.run(
      demand_id || null, title, isbn || null, Number(quantity), condition_grade || null,
      expected_price || null, JSON.stringify(images || []), contact || null,
      auto_quote || null, now(), now(), user_id,
      function (err2) {
        if (err2) return res.status(500).json({ error: err2.message });
        res.json({ id: this.lastID, auto_quote });
      }
    );
  };

  if (demand_id) {
    db.get(`SELECT unit_price_min, unit_price_max FROM recycle_demands WHERE id=?`, [demand_id], (err, row) => {
      if (err) return res.status(500).json({ error: err.message });
      const auto_quote = row ? autoQuote(row.unit_price_min, row.unit_price_max, condition_grade) : null;
      doInsert(auto_quote);
    });
  } else {
    doInsert(null);
  }
});

// API: 获取某需求下的投稿列表（公开，用于详情页）
app.get('/api/demands/:id/submissions', (req, res) => {
  db.all(`SELECT * FROM user_submissions WHERE demand_id=? ORDER BY created_at DESC`, [req.params.id], (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(rows);
  });
});

// API: 管理员查看所有投稿（全部）
app.get('/api/submissions', requireAdmin, (req, res) => {
  db.all(`SELECT * FROM user_submissions ORDER BY created_at DESC`, (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(rows);
  });
});

// API: 管理员查看待审核投稿（仅 pending）
app.get('/api/submissions/pending', requireAdmin, (req, res) => {
  db.all(`SELECT * FROM user_submissions WHERE status='pending' ORDER BY created_at DESC`, (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(rows);
  });
});

// API: 审核投稿（通过/驳回/报价）
app.post('/api/submissions/:id/review', requireAdmin, (req, res) => {
  const { status, final_quote, reviewer_id } = req.body;
  const stmt = db.prepare(`
    UPDATE user_submissions SET status=?, final_quote=?, reviewer_id=?, updated_at=?
    WHERE id=?
  `);
  stmt.run(status || 'approved', final_quote || null, reviewer_id || 'admin', now(), req.params.id, function (err) {
    if (err) return res.status(500).json({ error: err.message });
    res.json({ updated: this.changes });
  });
});

// API: 用户查看自己的投稿（需登录）
app.get('/api/me/submissions', requireUser, (req, res) => {
  db.all(`SELECT * FROM user_submissions WHERE user_id=? ORDER BY created_at DESC`, [req.user_id], (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(rows);
  });
});

// 简单首页路由
app.get('/', (_req, res) => {
  res.redirect('/static/index.html');
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`server started http://localhost:${PORT}`);
});
