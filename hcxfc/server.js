// 校服之家 - server.js
// Node.js + Express + better-sqlite3(WAL) + JWT + bcryptjs + multer/sharp
// 架构参考简铺：单表 merchants，shop_data 存 JSON（店铺信息 + 商品数组）

const express = require('express');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const sharp = require('sharp');
const Database = require('better-sqlite3');

const APP_NAME = '校服之家';
const DAY = 24 * 60 * 60 * 1000;
const FREE_BUILD_DAYS = 3;     // 免费搭建期
const PAID_TRIAL_DAYS = 14;    // 付费试用期（20元/2周）
const GRACE_DAYS = 30;         // 到期后数据保留宽限期
const PORT = process.env.PORT || 4100;
const JWT_SECRET = process.env.JWT_SECRET || 'hcxfc-dev-secret-change-me';
const JWT_EXPIRES = '30d';
const DB_PATH = path.join(__dirname, 'hcxfc.db');
const UPLOAD_DIR = path.join(__dirname, 'public', 'uploads');

fs.mkdirSync(UPLOAD_DIR, { recursive: true });

// ---------- 数据库 ----------
const db = new Database(DB_PATH);
db.pragma('journal_mode = WAL');

db.exec(`
CREATE TABLE IF NOT EXISTS merchants (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  phone TEXT UNIQUE NOT NULL,
  password TEXT NOT NULL,
  shop_id TEXT UNIQUE NOT NULL,
  role TEXT NOT NULL DEFAULT 'merchant',
  status TEXT NOT NULL DEFAULT 'active',
  shop_data TEXT NOT NULL DEFAULT '{}',
  created_at INTEGER NOT NULL
);
`);

// 试用/订阅相关字段（老库可能没有，自动补上）
function addColumnIfMissing(table, col, def) {
  const cols = db.prepare(`PRAGMA table_info(${table})`).all().map(c => c.name);
  if (!cols.includes(col)) db.exec(`ALTER TABLE ${table} ADD COLUMN ${col} ${def}`);
}
addColumnIfMissing('merchants', 'trial_started_at', 'INTEGER');
addColumnIfMissing('merchants', 'trial_paid_at', 'INTEGER');
addColumnIfMissing('merchants', 'active_until', 'INTEGER');
addColumnIfMissing('merchants', 'closed_at', 'INTEGER');

// 手机号注册次数计数表：即使商家注销/被清理，这张表也不删，保证"同一手机号最多注册2次"
db.exec(`
CREATE TABLE IF NOT EXISTS phone_registrations (
  phone TEXT PRIMARY KEY,
  count INTEGER NOT NULL DEFAULT 0,
  last_registered_at INTEGER
);
`);

// ---------- 启动引导：没有管理员就创建一个 ----------
function bootstrapAdmin() {
  const existing = db.prepare("SELECT id FROM merchants WHERE role = 'admin' LIMIT 1").get();
  if (existing) return;
  const phone = process.env.ADMIN_PHONE || '13800000000';
  const rawPassword = process.env.ADMIN_PASSWORD || crypto.randomBytes(4).toString('hex');
  const hash = bcrypt.hashSync(rawPassword, 10);
  const shopId = genShopId();
  db.prepare(`INSERT INTO merchants (phone, password, shop_id, role, status, shop_data, created_at)
    VALUES (?, ?, ?, 'admin', 'active', ?, ?)`).run(
    phone, hash, shopId, JSON.stringify({ shopName: '总后台' }), Date.now()
  );
  console.log('========================================');
  console.log('[首次启动] 已创建管理员账号：');
  console.log('手机号: ' + phone);
  console.log('密码: ' + rawPassword);
  console.log('请登录总后台后尽快妥善保管此密码（当前版本暂无改密功能，如需修改请联系开发者或直接改数据库）。');
  console.log('========================================');
}
bootstrapAdmin();

// ---------- 工具函数 ----------
function genShopId() {
  // 6位短码，避免跟已有的撞
  for (;;) {
    const id = Math.random().toString(36).slice(2, 8).toUpperCase();
    const hit = db.prepare('SELECT id FROM merchants WHERE shop_id = ?').get(id);
    if (!hit) return id;
  }
}

function genProductId() {
  return Date.now().toString(36) + Math.random().toString(36).slice(2, 6);
}

function genOrderId() {
  return 'o_' + Date.now().toString(36) + Math.random().toString(36).slice(2, 6);
}

function genRenewalId() {
  return 'r_' + Date.now().toString(36) + Math.random().toString(36).slice(2, 6);
}

// ---------- 续费定价 ----------
// 首月15元仅限从未付费过的商家（首次续费），之后统一按月费率计算：1/3/6/12个月
const RENEWAL_FIRST_MONTH_PRICE = 15;
const RENEWAL_PRICING = { 1: 30, 3: 90, 6: 180, 12: 360 };

// ---------- 试用/订阅状态机 ----------
// 流程：注册即进入"免费搭建期"(3天) → 商家付20元后由管理员标记"付费试用"(14天)
// → 到期后由管理员"正式开通"(设到期日) 或商家"注销"；任何到期状态都有30天数据宽限期，
// 宽限期过后管理员才能手动清理数据。手机号单独计数，注销/清理都不影响这个计数。
function computeAccessState(row) {
  if (row.role === 'admin') return { phase: 'admin', label: '管理员', accessible: true };
  const now = Date.now();
  const startedAt = row.trial_started_at || row.created_at;

  if (row.closed_at) {
    const purgeAt = row.closed_at + GRACE_DAYS * DAY;
    return { phase: 'closed', label: '已注销', accessible: false, purgeEligible: now > purgeAt, purgeAt };
  }
  if (row.status === 'banned') {
    return { phase: 'banned', label: '已封禁', accessible: false };
  }
  if (row.active_until) {
    if (now < row.active_until) {
      return { phase: 'active', label: '已开通', accessible: true, daysLeft: Math.ceil((row.active_until - now) / DAY), expiresAt: row.active_until };
    }
    const purgeAt = row.active_until + GRACE_DAYS * DAY;
    return { phase: 'active_expired', label: '开通已到期', accessible: false, purgeEligible: now > purgeAt, purgeAt, expiredAt: row.active_until };
  }
  if (row.trial_paid_at) {
    const paidEnd = row.trial_paid_at + PAID_TRIAL_DAYS * DAY;
    if (now < paidEnd) {
      return { phase: 'paid_trial', label: '付费试用中', accessible: true, daysLeft: Math.ceil((paidEnd - now) / DAY), expiresAt: paidEnd };
    }
    const purgeAt = paidEnd + GRACE_DAYS * DAY;
    return { phase: 'paid_trial_expired', label: '付费试用已到期', accessible: false, purgeEligible: now > purgeAt, purgeAt, expiredAt: paidEnd };
  }
  const freeEnd = startedAt + FREE_BUILD_DAYS * DAY;
  if (now < freeEnd) {
    return { phase: 'free_build', label: '免费搭建期', accessible: true, daysLeft: Math.ceil((freeEnd - now) / DAY), expiresAt: freeEnd };
  }
  const purgeAt = freeEnd + GRACE_DAYS * DAY;
  return { phase: 'free_expired', label: '免费期已到期', accessible: false, purgeEligible: now > purgeAt, purgeAt, expiredAt: freeEnd };
}

function parseShopData(row) {
  try {
    const d = JSON.parse(row.shop_data || '{}');
    if (!Array.isArray(d.products)) d.products = [];
    if (!Array.isArray(d.orders)) d.orders = [];
    if (!Array.isArray(d.renewalRequests)) d.renewalRequests = [];
    if (!Array.isArray(d.shopPhotos)) d.shopPhotos = [];
    return d;
  } catch (e) {
    return { products: [], orders: [], renewalRequests: [], shopPhotos: [] };
  }
}

function publicShopInfo(row) {
  const d = parseShopData(row);
  return {
    shopId: row.shop_id,
    shopName: d.shopName || '未命名店铺',
    banner: d.banner || '',
    intro: d.intro || '',
    address: d.address || '',
    contactWechat: d.contactWechat || '',
    contactPhone: d.contactPhone || '',
    shopPhotos: d.shopPhotos || []
  };
}

function publicProduct(row, p) {
  const shop = publicShopInfo(row);
  return {
    id: p.id,
    shopId: shop.shopId,
    shopName: shop.shopName,
    school: p.school || '',
    season: p.season || '',
    category: p.category || '',
    name: p.name || '',
    price: p.price || '',
    sizes: Array.isArray(p.sizes) ? p.sizes : [],
    images: Array.isArray(p.images) ? p.images : [],
    desc: p.desc || '',
    status: p.status || 'active',
    shipping: !!p.shipping,
    shippingNote: p.shippingNote || '',
    contactWechat: shop.contactWechat,
    contactPhone: shop.contactPhone
  };
}

// ---------- 鉴权中间件 ----------
function auth(req, res, next) {
  const h = req.headers.authorization || '';
  const token = h.startsWith('Bearer ') ? h.slice(7) : null;
  if (!token) return res.status(401).json({ ok: false, msg: '未登录' });
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    const row = db.prepare('SELECT * FROM merchants WHERE id = ?').get(payload.id);
    if (!row) return res.status(401).json({ ok: false, msg: '账号不存在' });
    if (row.status === 'banned') return res.status(403).json({ ok: false, msg: '账号已被封禁' });
    req.merchant = row;
    next();
  } catch (e) {
    return res.status(401).json({ ok: false, msg: '登录已过期，请重新登录' });
  }
}

function requireAdmin(req, res, next) {
  if (req.merchant.role !== 'admin') return res.status(403).json({ ok: false, msg: '无权限' });
  next();
}

// ---------- Express ----------
const app = express();
app.use(express.json({ limit: '2mb' }));
app.use(express.static(path.join(__dirname, 'public')));

// ===== 注册 / 登录 =====
app.post('/api/register', (req, res) => {
  const { phone, password, shopName } = req.body || {};
  if (!phone || !/^1[3-9]\d{9}$/.test(phone)) return res.status(400).json({ ok: false, msg: '手机号格式不对' });
  if (!password || password.length < 6) return res.status(400).json({ ok: false, msg: '密码至少6位' });
  const exist = db.prepare('SELECT id FROM merchants WHERE phone = ?').get(phone);
  if (exist) return res.status(400).json({ ok: false, msg: '该手机号已注册' });

  const regRow = db.prepare('SELECT * FROM phone_registrations WHERE phone = ?').get(phone);
  if (regRow && regRow.count >= 2) {
    return res.status(400).json({ ok: false, msg: '该手机号注册次数已达上限（最多2次），无法再次注册开店' });
  }

  const hash = bcrypt.hashSync(password, 10);
  const shopId = genShopId();
  const now = Date.now();
  const shopData = JSON.stringify({
    shopName: shopName || ('校服店-' + phone.slice(-4)),
    banner: '', intro: '', address: '', contactWechat: '', contactPhone: phone, products: []
  });
  const info = db.prepare(`INSERT INTO merchants (phone, password, shop_id, role, status, shop_data, created_at, trial_started_at)
    VALUES (?, ?, ?, 'merchant', 'active', ?, ?, ?)`).run(phone, hash, shopId, shopData, now, now);

  if (regRow) {
    db.prepare('UPDATE phone_registrations SET count = count + 1, last_registered_at = ? WHERE phone = ?').run(now, phone);
  } else {
    db.prepare('INSERT INTO phone_registrations (phone, count, last_registered_at) VALUES (?, 1, ?)').run(phone, now);
  }

  const token = jwt.sign({ id: info.lastInsertRowid }, JWT_SECRET, { expiresIn: JWT_EXPIRES });
  res.json({ ok: true, token, shopId });
});

app.post('/api/login', (req, res) => {
  const { phone, password } = req.body || {};
  const row = db.prepare('SELECT * FROM merchants WHERE phone = ?').get(phone);
  if (!row) return res.status(400).json({ ok: false, msg: '账号或密码错误' });
  if (!bcrypt.compareSync(password || '', row.password)) return res.status(400).json({ ok: false, msg: '账号或密码错误' });
  if (row.status === 'banned') return res.status(403).json({ ok: false, msg: '账号已被封禁' });
  const token = jwt.sign({ id: row.id }, JWT_SECRET, { expiresIn: JWT_EXPIRES });
  res.json({ ok: true, token, role: row.role, shopId: row.shop_id });
});

// ===== 商家自己：店铺信息 =====
app.get('/api/me', auth, (req, res) => {
  const d = parseShopData(req.merchant);
  const everPaid = !!(req.merchant.trial_paid_at || req.merchant.active_until || d.everPaid);
  const pendingRenewal = d.renewalRequests.find(r => r.status === 'pending') || null;
  res.json({
    ok: true,
    phone: req.merchant.phone,
    shopId: req.merchant.shop_id,
    role: req.merchant.role,
    shopName: d.shopName || '',
    banner: d.banner || '',
    intro: d.intro || '',
    address: d.address || '',
    contactWechat: d.contactWechat || '',
    contactPhone: d.contactPhone || '',
    shopPhotos: d.shopPhotos || [],
    access: computeAccessState(req.merchant),
    renewal: {
      firstMonthEligible: !everPaid,
      firstMonthPrice: RENEWAL_FIRST_MONTH_PRICE,
      pricing: RENEWAL_PRICING,
      pending: pendingRenewal
    }
  });
});

// 商家自助注销（数据保留30天宽限期，期满后由管理员清理）
app.post('/api/account/close', auth, (req, res) => {
  if (req.merchant.role !== 'merchant') return res.status(400).json({ ok: false, msg: '仅商家账号可注销' });
  db.prepare('UPDATE merchants SET closed_at = ? WHERE id = ?').run(Date.now(), req.merchant.id);
  res.json({ ok: true });
});

app.put('/api/shop', auth, (req, res) => {
  const d = parseShopData(req.merchant);
  const { shopName, banner, intro, address, contactWechat, contactPhone, shopPhotos } = req.body || {};
  if (shopName !== undefined) d.shopName = String(shopName).slice(0, 60);
  if (banner !== undefined) d.banner = banner;
  if (intro !== undefined) d.intro = String(intro).slice(0, 300);
  if (address !== undefined) d.address = String(address).slice(0, 120);
  if (contactWechat !== undefined) d.contactWechat = String(contactWechat).slice(0, 60);
  if (contactPhone !== undefined) d.contactPhone = String(contactPhone).slice(0, 30);
  if (shopPhotos !== undefined) d.shopPhotos = Array.isArray(shopPhotos) ? shopPhotos.slice(0, 4).map(s => String(s).slice(0, 300)) : [];
  db.prepare('UPDATE merchants SET shop_data = ? WHERE id = ?').run(JSON.stringify(d), req.merchant.id);
  res.json({ ok: true });
});

// ===== 商家自己：商品管理 =====
app.get('/api/my/products', auth, (req, res) => {
  const d = parseShopData(req.merchant);
  res.json({ ok: true, products: d.products });
});

app.post('/api/my/products', auth, (req, res) => {
  const d = parseShopData(req.merchant);
  const { school, season, category, name, price, sizes, images, desc, shipping, shippingNote } = req.body || {};
  if (!school || !name) return res.status(400).json({ ok: false, msg: '学校和商品名必填' });
  const p = {
    id: genProductId(),
    school: String(school).slice(0, 40),
    season: season === '夏季款' ? '夏季款' : '冬季款',
    category: category ? String(category).slice(0, 20) : '',
    name: String(name).slice(0, 60),
    price: price !== undefined ? String(price).slice(0, 20) : '',
    sizes: Array.isArray(sizes) ? sizes.slice(0, 20).map(s => String(s).slice(0, 10)) : [],
    images: Array.isArray(images) ? images.slice(0, 4) : [],
    desc: desc ? String(desc).slice(0, 300) : '',
    status: 'active',
    shipping: !!shipping,
    shippingNote: shippingNote ? String(shippingNote).slice(0, 100) : '',
    createdAt: Date.now()
  };
  d.products.unshift(p);
  db.prepare('UPDATE merchants SET shop_data = ? WHERE id = ?').run(JSON.stringify(d), req.merchant.id);
  res.json({ ok: true, product: p });
});

app.put('/api/my/products/:id', auth, (req, res) => {
  const d = parseShopData(req.merchant);
  const idx = d.products.findIndex(p => p.id === req.params.id);
  if (idx === -1) return res.status(404).json({ ok: false, msg: '商品不存在' });
  const p = d.products[idx];
  const { school, season, category, name, price, sizes, images, desc, status, shipping, shippingNote } = req.body || {};
  if (school !== undefined) p.school = String(school).slice(0, 40);
  if (season !== undefined) p.season = season === '夏季款' ? '夏季款' : '冬季款';
  if (category !== undefined) p.category = String(category).slice(0, 20);
  if (name !== undefined) p.name = String(name).slice(0, 60);
  if (price !== undefined) p.price = String(price).slice(0, 20);
  if (sizes !== undefined) p.sizes = Array.isArray(sizes) ? sizes.slice(0, 20).map(s => String(s).slice(0, 10)) : [];
  if (images !== undefined) p.images = Array.isArray(images) ? images.slice(0, 4) : [];
  if (desc !== undefined) p.desc = String(desc).slice(0, 300);
  if (status !== undefined) p.status = status === 'off' ? 'off' : 'active';
  if (shipping !== undefined) p.shipping = !!shipping;
  if (shippingNote !== undefined) p.shippingNote = String(shippingNote).slice(0, 100);
  db.prepare('UPDATE merchants SET shop_data = ? WHERE id = ?').run(JSON.stringify(d), req.merchant.id);
  res.json({ ok: true, product: p });
});

app.delete('/api/my/products/:id', auth, (req, res) => {
  const d = parseShopData(req.merchant);
  const before = d.products.length;
  d.products = d.products.filter(p => p.id !== req.params.id);
  if (d.products.length === before) return res.status(404).json({ ok: false, msg: '商品不存在' });
  db.prepare('UPDATE merchants SET shop_data = ? WHERE id = ?').run(JSON.stringify(d), req.merchant.id);
  res.json({ ok: true });
});

// ===== 商家自己：订单（微信付款截图下单）=====
app.get('/api/my/orders', auth, (req, res) => {
  const d = parseShopData(req.merchant);
  res.json({ ok: true, orders: d.orders });
});

app.put('/api/my/orders/:id/status', auth, (req, res) => {
  const d = parseShopData(req.merchant);
  const o = d.orders.find(x => x.id === req.params.id);
  if (!o) return res.status(404).json({ ok: false, msg: '订单不存在' });
  const status = (req.body || {}).status === 'shipped' ? 'shipped' : 'pending';
  o.status = status;
  o.shippedAt = status === 'shipped' ? Date.now() : null;
  db.prepare('UPDATE merchants SET shop_data = ? WHERE id = ?').run(JSON.stringify(d), req.merchant.id);
  res.json({ ok: true, order: o });
});

// ===== 商家自己：自助续费申请（微信转账截图，提交后等待平台审核）=====
app.post('/api/my/renewal', auth, (req, res) => {
  const d = parseShopData(req.merchant);
  const existingPending = d.renewalRequests.find(r => r.status === 'pending');
  if (existingPending) return res.status(400).json({ ok: false, msg: '已有一条续费申请在审核中，请等待处理' });

  const { months, screenshot } = req.body || {};
  const m = parseInt(months, 10);
  if (!screenshot) return res.status(400).json({ ok: false, msg: '请上传微信付款截图' });

  const everPaid = !!(req.merchant.trial_paid_at || req.merchant.active_until || d.everPaid);
  let amount, label;
  if (m === 1 && !everPaid) {
    amount = RENEWAL_FIRST_MONTH_PRICE;
    label = '首月（优惠价）';
  } else if (RENEWAL_PRICING[m]) {
    amount = RENEWAL_PRICING[m];
    label = m === 1 ? '1个月' : (m === 3 ? '3个月' : (m === 6 ? '半年' : '1年'));
  } else {
    return res.status(400).json({ ok: false, msg: '续费时长不对' });
  }

  const req_ = {
    id: genRenewalId(),
    months: m,
    amount,
    label,
    screenshot: String(screenshot).slice(0, 300),
    status: 'pending',
    createdAt: Date.now()
  };
  d.renewalRequests.unshift(req_);
  db.prepare('UPDATE merchants SET shop_data = ? WHERE id = ?').run(JSON.stringify(d), req.merchant.id);
  res.json({ ok: true, request: req_ });
});

// ===== 图片上传 =====
const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 8 * 1024 * 1024 } });
app.post('/api/upload', auth, upload.single('file'), async (req, res) => {
  if (!req.file) return res.status(400).json({ ok: false, msg: '没有文件' });
  try {
    const filename = 'p_' + Date.now() + '_' + Math.random().toString(36).slice(2, 8) + '.webp';
    const outPath = path.join(UPLOAD_DIR, filename);
    await sharp(req.file.buffer)
      .resize({ width: 800, height: 800, fit: 'inside', withoutEnlargement: true })
      .webp({ quality: 82 })
      .toFile(outPath);
    res.json({ ok: true, url: '/uploads/' + filename });
  } catch (e) {
    res.status(500).json({ ok: false, msg: '图片处理失败' });
  }
});

// 买家上传微信付款截图用（下单时不要求登录，走独立的公开上传接口，限制同/api/upload）
app.post('/api/public-upload', upload.single('file'), async (req, res) => {
  if (!req.file) return res.status(400).json({ ok: false, msg: '没有文件' });
  try {
    const filename = 'o_' + Date.now() + '_' + Math.random().toString(36).slice(2, 8) + '.webp';
    const outPath = path.join(UPLOAD_DIR, filename);
    await sharp(req.file.buffer)
      .resize({ width: 1000, height: 1000, fit: 'inside', withoutEnlargement: true })
      .webp({ quality: 85 })
      .toFile(outPath);
    res.json({ ok: true, url: '/uploads/' + filename });
  } catch (e) {
    res.status(500).json({ ok: false, msg: '图片处理失败' });
  }
});

// ===== 前台公开接口 =====
// 注意：刻意不提供"跨商家汇总浏览"的接口（比如全平台按学校列出所有商家），
// 每个店铺都是独立入口，避免同校多商家被摆在一起比价竞争。

// 买家下单：留联系方式+收货地址+选尺码+微信付款截图，不走在线支付，
// 商家在后台"订单"里看到截图自行核实到账后发货。
app.post('/api/order', (req, res) => {
  const { shopId, productId, size, contactPhone, address, note, screenshot } = req.body || {};
  if (!shopId || !productId) return res.status(400).json({ ok: false, msg: '参数缺失' });
  if (!contactPhone || !String(contactPhone).trim()) return res.status(400).json({ ok: false, msg: '请留下联系方式' });
  if (!address || !String(address).trim()) return res.status(400).json({ ok: false, msg: '请填写收货地址' });
  if (!screenshot) return res.status(400).json({ ok: false, msg: '请上传微信付款截图' });

  const row = db.prepare("SELECT * FROM merchants WHERE shop_id = ? AND role = 'merchant'").get(shopId);
  if (!row) return res.status(404).json({ ok: false, msg: '店铺不存在' });
  if (!computeAccessState(row).accessible) return res.status(403).json({ ok: false, msg: '该店铺已下线，暂不可下单' });

  const d = parseShopData(row);
  const p = d.products.find(x => x.id === productId);
  if (!p) return res.status(404).json({ ok: false, msg: '商品不存在' });

  const order = {
    id: genOrderId(),
    productId: p.id,
    productName: p.name || '',
    productImage: (p.images && p.images[0]) || '',
    size: size ? String(size).slice(0, 10) : '',
    contactPhone: String(contactPhone).trim().slice(0, 30),
    address: String(address).trim().slice(0, 200),
    note: note ? String(note).trim().slice(0, 200) : '',
    screenshot: String(screenshot).slice(0, 300),
    status: 'pending',
    createdAt: Date.now()
  };
  d.orders.unshift(order);
  db.prepare('UPDATE merchants SET shop_data = ? WHERE id = ?').run(JSON.stringify(d), row.id);
  res.json({ ok: true, orderId: order.id });
});

app.get('/api/product/:shopId/:id', (req, res) => {
  const row = db.prepare("SELECT * FROM merchants WHERE shop_id = ? AND role = 'merchant'").get(req.params.shopId);
  if (!row) return res.status(404).json({ ok: false, msg: '店铺不存在' });
  if (!computeAccessState(row).accessible) return res.status(403).json({ ok: false, msg: '该店铺已下线，暂不可访问' });
  const d = parseShopData(row);
  const p = d.products.find(x => x.id === req.params.id);
  if (!p) return res.status(404).json({ ok: false, msg: '商品不存在' });
  res.json({ ok: true, product: publicProduct(row, p) });
});

app.get('/api/shop/:shopId', (req, res) => {
  const row = db.prepare("SELECT * FROM merchants WHERE shop_id = ? AND role = 'merchant'").get(req.params.shopId);
  if (!row) return res.status(404).json({ ok: false, msg: '店铺不存在' });
  if (!computeAccessState(row).accessible) return res.status(403).json({ ok: false, msg: '该店铺已下线，暂不可访问' });
  const d = parseShopData(row);
  const products = d.products.filter(p => p.status === 'active').map(p => publicProduct(row, p));
  const schools = Array.from(new Set(products.map(p => p.school).filter(Boolean)));
  const categories = Array.from(new Set(products.map(p => p.category).filter(Boolean)));
  res.json({ ok: true, shop: publicShopInfo(row), schools, categories, products });
});

// ===== 总后台（管理员）=====
app.get('/api/admin/merchants', auth, requireAdmin, (req, res) => {
  const rows = db.prepare("SELECT * FROM merchants WHERE role = 'merchant' ORDER BY created_at DESC").all();
  const list = rows.map(row => {
    const d = parseShopData(row);
    return {
      id: row.id,
      phone: row.phone,
      shopId: row.shop_id,
      shopName: d.shopName || '',
      status: row.status,
      productCount: d.products.length,
      createdAt: row.created_at,
      access: computeAccessState(row),
      pendingRenewal: d.renewalRequests.find(r => r.status === 'pending') || null
    };
  });
  res.json({ ok: true, merchants: list });
});

// 续费审核：列出所有商家的待审核续费申请
app.get('/api/admin/renewal-requests', auth, requireAdmin, (req, res) => {
  const rows = db.prepare("SELECT * FROM merchants WHERE role = 'merchant' ORDER BY created_at DESC").all();
  const list = [];
  for (const row of rows) {
    const d = parseShopData(row);
    for (const r of d.renewalRequests) {
      if (r.status === 'pending') {
        list.push({
          merchantId: row.id,
          shopId: row.shop_id,
          shopName: d.shopName || '',
          phone: row.phone,
          access: computeAccessState(row),
          request: r
        });
      }
    }
  }
  list.sort((a, b) => b.request.createdAt - a.request.createdAt);
  res.json({ ok: true, requests: list });
});

// 通过续费申请：按申请的月数延长到期日（如仍在有效期内则在原到期日基础上累加，否则从现在起算）
app.put('/api/admin/merchants/:id/approve-renewal', auth, requireAdmin, (req, res) => {
  const row = db.prepare("SELECT * FROM merchants WHERE id = ? AND role = 'merchant'").get(req.params.id);
  if (!row) return res.status(404).json({ ok: false, msg: '商家不存在' });
  const d = parseShopData(row);
  const { requestId } = req.body || {};
  const r = d.renewalRequests.find(x => x.id === requestId && x.status === 'pending');
  if (!r) return res.status(404).json({ ok: false, msg: '续费申请不存在或已处理' });

  const now = Date.now();
  const base = (row.active_until && row.active_until > now) ? row.active_until : now;
  const until = base + r.months * DAY * 30;

  r.status = 'approved';
  r.approvedAt = now;
  d.everPaid = true;
  db.prepare('UPDATE merchants SET shop_data = ?, active_until = ?, closed_at = NULL WHERE id = ?').run(JSON.stringify(d), until, row.id);
  res.json({ ok: true, activeUntil: until });
});

// 拒绝续费申请
app.put('/api/admin/merchants/:id/reject-renewal', auth, requireAdmin, (req, res) => {
  const row = db.prepare("SELECT * FROM merchants WHERE id = ? AND role = 'merchant'").get(req.params.id);
  if (!row) return res.status(404).json({ ok: false, msg: '商家不存在' });
  const d = parseShopData(row);
  const { requestId } = req.body || {};
  const r = d.renewalRequests.find(x => x.id === requestId && x.status === 'pending');
  if (!r) return res.status(404).json({ ok: false, msg: '续费申请不存在或已处理' });
  r.status = 'rejected';
  r.rejectedAt = Date.now();
  db.prepare('UPDATE merchants SET shop_data = ? WHERE id = ?').run(JSON.stringify(d), row.id);
  res.json({ ok: true });
});

app.put('/api/admin/merchants/:id/status', auth, requireAdmin, (req, res) => {
  const { status } = req.body || {};
  if (!['active', 'banned'].includes(status)) return res.status(400).json({ ok: false, msg: '状态不对' });
  const info = db.prepare('UPDATE merchants SET status = ? WHERE id = ? AND role = \'merchant\'').run(status, req.params.id);
  if (info.changes === 0) return res.status(404).json({ ok: false, msg: '商家不存在' });
  res.json({ ok: true });
});

// 标记商家已线下付20元，进入14天付费试用
app.put('/api/admin/merchants/:id/mark-paid', auth, requireAdmin, (req, res) => {
  const info = db.prepare("UPDATE merchants SET trial_paid_at = ?, closed_at = NULL WHERE id = ? AND role = 'merchant'").run(Date.now(), req.params.id);
  if (info.changes === 0) return res.status(404).json({ ok: false, msg: '商家不存在' });
  res.json({ ok: true });
});

// 正式开通：设置到期天数（从现在起算）
app.put('/api/admin/merchants/:id/activate', auth, requireAdmin, (req, res) => {
  const days = parseInt((req.body || {}).days, 10);
  if (!days || days <= 0) return res.status(400).json({ ok: false, msg: '请提供有效的开通天数' });
  const until = Date.now() + days * DAY;
  const info = db.prepare("UPDATE merchants SET active_until = ?, closed_at = NULL WHERE id = ? AND role = 'merchant'").run(until, req.params.id);
  if (info.changes === 0) return res.status(404).json({ ok: false, msg: '商家不存在' });
  res.json({ ok: true, activeUntil: until });
});

// 清理过期数据：只有宽限期已过的到期/注销商家才能清理（手机号注册计数不受影响）
app.delete('/api/admin/merchants/:id/purge', auth, requireAdmin, (req, res) => {
  const row = db.prepare("SELECT * FROM merchants WHERE id = ? AND role = 'merchant'").get(req.params.id);
  if (!row) return res.status(404).json({ ok: false, msg: '商家不存在' });
  const access = computeAccessState(row);
  if (access.accessible || !access.purgeEligible) {
    return res.status(400).json({ ok: false, msg: '该商家还在有效期或30天数据宽限期内，暂不能清理' });
  }
  db.prepare('DELETE FROM merchants WHERE id = ?').run(row.id);
  res.json({ ok: true });
});

app.get('/api/admin/stats', auth, requireAdmin, (req, res) => {
  const rows = db.prepare("SELECT * FROM merchants WHERE role = 'merchant'").all();
  let productCount = 0;
  let activeProductCount = 0;
  const schoolSet = new Set();
  for (const row of rows) {
    const d = parseShopData(row);
    productCount += d.products.length;
    for (const p of d.products) {
      if (p.status === 'active') { activeProductCount++; if (p.school) schoolSet.add(p.school); }
    }
  }
  res.json({
    ok: true,
    stats: {
      merchantCount: rows.length,
      activeMerchantCount: rows.filter(r => r.status === 'active').length,
      productCount,
      activeProductCount,
      schoolCount: schoolSet.size
    }
  });
});

app.listen(PORT, () => {
  console.log(APP_NAME + ' 已启动: http://0.0.0.0:' + PORT);
});
