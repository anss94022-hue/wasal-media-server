// ============================================================================
// Wasal — خادم الحسابات والمراسلات
// Express + Socket.IO + SQLite (better-sqlite3)
//
// المبادئ:
//  - لا حذف ولا إعادة إنشاء لقاعدة البيانات الموجودة.
//  - لا تغيير تلقائي لرموز وصال الحالية.
//  - إضافة الأعمدة والجداول الجديدة بطريقة آمنة وقابلة لإعادة التنفيذ.
//  - الاستجابات متوافقة مع تطبيق Android الحالي (أسماء الحقول كما يقرأها).
//  - خادم رفع الوسائط يبقى منفصلًا (wasal-server-production).
// ============================================================================

import 'dotenv/config';
import express from 'express';
import cors from 'cors';
import jwt from 'jsonwebtoken';
import multer from 'multer';
import fs from 'fs';
import path from 'path';
import { createServer } from 'http';
import { randomInt, randomBytes, randomUUID, createHash } from 'node:crypto';
import { Server } from 'socket.io';
import Database from 'better-sqlite3';

// --------------------------------------------------
// الثوابت والإعداد
// --------------------------------------------------
const PORT = Number(process.env.PORT || 3000);
const JWT_SECRET = process.env.JWT_SECRET;

if (!JWT_SECRET) {
  console.error('CRITICAL ERROR: JWT_SECRET environment variable is not defined.');
  process.exit(1);
}

const SERVICE_NAME = 'wasal-account-messaging-server';
const SERVICE_VERSION = '5.0.0';

const ACCESS_TOKEN_TTL = '15m';
const REFRESH_TOKEN_TTL = '30d';
const MAX_DISPLAY_NAME = 40;
const WASAL_CODE_LENGTH = 15;

// المجلدات: قابلة للتوجيه إلى Volume دائم (Railway) دون تغيير المسار الافتراضي.
const DATA_DIR = process.env.DATA_DIR || './data';
const MEDIA_DIR = process.env.MEDIA_DIR || './media';
const DB_FILE = path.join(DATA_DIR, 'wasal.db');

// المضيفات المسموح بها لروابط الوسائط (خادم الوسائط المنفصل + خادم المراسلات نفسه).
const DEFAULT_MEDIA_HOSTS = [
  'wasal-server-production.up.railway.app',
  'wasal-media-server-production.up.railway.app'
];
const MEDIA_ALLOWED_HOSTS = String(
  process.env.MEDIA_ALLOWED_HOSTS || DEFAULT_MEDIA_HOSTS.join(',')
)
  .split(',')
  .map(h => h.trim().toLowerCase())
  .filter(Boolean);

const ALLOWED_MESSAGE_TYPES = ['text', 'image', 'video', 'voice', 'audio', 'file', 'link'];
const MEDIA_MESSAGE_TYPES = ['image', 'video', 'voice', 'audio', 'file'];

const app = express();
const httpServer = createServer(app);

// خلف وكيل الاستضافة: بدون هذا يبقى req.protocol = http فيُبنى رابط http مرفوض داخل التطبيق.
app.set('trust proxy', 1);

const io = new Server(httpServer, {
  cors: {
    origin: process.env.CORS_ORIGIN || '*',
    methods: ['GET', 'POST']
  },
  // ✅ دعم تعدد الاتصالات لنفس المستخدم (أكثر من جهاز)
  pingInterval: 25000,
  pingTimeout: 20000
});

app.use(cors({ origin: process.env.CORS_ORIGIN || '*' }));
app.use(express.json({ limit: '5mb' }));

// --------------------------------------------------
// المجلدات
// --------------------------------------------------
fs.mkdirSync(DATA_DIR, { recursive: true });
fs.mkdirSync(MEDIA_DIR, { recursive: true });

// --------------------------------------------------
// قاعدة البيانات
// --------------------------------------------------
const db = new Database(DB_FILE);

db.pragma('journal_mode = WAL');
db.pragma('busy_timeout = 5000');
db.pragma('foreign_keys = ON');

function tableExists(name) {
  return Boolean(
    db
      .prepare("SELECT name FROM sqlite_master WHERE type = 'table' AND name = ?")
      .get(name)
  );
}

function columnExists(tableName, columnName) {
  try {
    const columns = db.prepare(`PRAGMA table_info(${tableName})`).all();
    return columns.some(column => column.name === columnName);
  } catch {
    return false;
  }
}

// --------------------------------------------------
// المخطط الأساسي (إنشاء فقط عند الغياب — لا حذف ولا إعادة إنشاء)
// --------------------------------------------------
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    code TEXT NOT NULL UNIQUE,
    phone TEXT,
    name TEXT NOT NULL,
    email TEXT,
    password TEXT,
    created_at TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS conversations (
    id TEXT PRIMARY KEY,
    user1_code TEXT NOT NULL,
    user2_code TEXT NOT NULL,
    created_at TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    sender_code TEXT NOT NULL,
    receiver_code TEXT NOT NULL,
    type TEXT NOT NULL,
    text TEXT,
    media_url TEXT,
    created_at TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS statuses (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_code TEXT NOT NULL,
    type TEXT NOT NULL,
    text TEXT,
    media_url TEXT,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS status_views (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    status_id INTEGER NOT NULL,
    viewer_code TEXT NOT NULL,
    viewed_at TEXT NOT NULL,
    UNIQUE(status_id, viewer_code)
  );

  CREATE INDEX IF NOT EXISTS idx_messages_conversation
  ON messages(sender_code, receiver_code, created_at);

  CREATE INDEX IF NOT EXISTS idx_conversations_users
  ON conversations(user1_code, user2_code);

  CREATE INDEX IF NOT EXISTS idx_statuses_user
  ON statuses(user_code, created_at);

  CREATE INDEX IF NOT EXISTS idx_statuses_expiry
  ON statuses(expires_at);

  CREATE UNIQUE INDEX IF NOT EXISTS ux_users_code ON users(code);

  CREATE UNIQUE INDEX IF NOT EXISTS ux_conversations_pair
  ON conversations(user1_code, user2_code);
`);

// --------------------------------------------------
// جدول الجلسات (لدعم الإبطال الحقيقي لرموز التجديد)
// --------------------------------------------------
db.exec(`
  CREATE TABLE IF NOT EXISTS sessions (
    id TEXT PRIMARY KEY,
    user_code TEXT NOT NULL,
    refresh_token_hash TEXT NOT NULL,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    last_used_at TEXT,
    revoked_at TEXT,
    user_agent TEXT,
    ip TEXT
  );

  CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_code);
  CREATE INDEX IF NOT EXISTS idx_sessions_active ON sessions(user_code, revoked_at);
`);

// --------------------------------------------------
// الترحيل الآمن: إضافة أعمدة فقط عند غيابها (لا حذف، ولا تغيير رموز)
// --------------------------------------------------
function ensureColumn(tableName, columnName, definition) {
  if (!tableExists(tableName)) return;
  if (columnExists(tableName, columnName)) return;
  db.exec(`ALTER TABLE ${tableName} ADD COLUMN ${columnName} ${definition}`);
  console.log(`[migrate] added column ${tableName}.${columnName}`);
}

ensureColumn('users', 'phone', 'TEXT');
ensureColumn('users', 'email', 'TEXT');
ensureColumn('users', 'password', 'TEXT');
ensureColumn('users', 'last_seen_at', 'TEXT');
ensureColumn('users', 'is_online', 'INTEGER NOT NULL DEFAULT 0');
ensureColumn('messages', 'client_id', 'TEXT');
ensureColumn('messages', 'conversation_id', 'TEXT');
ensureColumn('conversations', 'last_message_id', 'INTEGER');
ensureColumn('conversations', 'last_message_at', 'TEXT');
ensureColumn('conversations', 'updated_at', 'TEXT');

// فهارس إضافية (آمنة ومتكررة التنفيذ)
db.exec(`
  CREATE INDEX IF NOT EXISTS idx_messages_pair
  ON messages(sender_code, receiver_code, id);

  CREATE INDEX IF NOT EXISTS idx_messages_conversation_id
  ON messages(conversation_id, id);

  CREATE UNIQUE INDEX IF NOT EXISTS ux_messages_client_dedup
  ON messages(sender_code, client_id)
  WHERE client_id IS NOT NULL;
`);

// --------------------------------------------------
// تعبئة غير مدمِّرة: إنشاء صفوف المحادثات الناقصة للرسائل القديمة،
// ثم تعبئة conversation_id حيث كان فارغًا فقط. لا حذف ولا تعديل لمحتوى الرسائل.
// --------------------------------------------------
const pairKeyA = `CASE WHEN sender_code < receiver_code THEN sender_code ELSE receiver_code END`;
const pairKeyB = `CASE WHEN sender_code < receiver_code THEN receiver_code ELSE sender_code END`;

const backfillConversations = db.prepare(`
  INSERT OR IGNORE INTO conversations (id, user1_code, user2_code, created_at, updated_at)
  SELECT
    ${pairKeyA} || '_' || ${pairKeyB},
    ${pairKeyA},
    ${pairKeyB},
    MIN(created_at),
    MAX(created_at)
  FROM messages
  GROUP BY ${pairKeyA}, ${pairKeyB}
  HAVING ${pairKeyA} <> '' AND ${pairKeyB} <> ''
`).run();

const backfillConversationIds = db.prepare(`
  UPDATE messages
  SET conversation_id = ${pairKeyA} || '_' || ${pairKeyB}
  WHERE conversation_id IS NULL
`).run();

const syncConversationCounters = db.prepare(`
  UPDATE conversations
  SET
    last_message_id = (
      SELECT MAX(m.id) FROM messages m
      WHERE m.sender_code = conversations.user1_code AND m.receiver_code = conversations.user2_code
         OR m.sender_code = conversations.user2_code AND m.receiver_code = conversations.user1_code
    ),
    last_message_at = (
      SELECT MAX(m.created_at) FROM messages m
      WHERE m.sender_code = conversations.user1_code AND m.receiver_code = conversations.user2_code
         OR m.sender_code = conversations.user2_code AND m.receiver_code = conversations.user1_code
    ),
    updated_at = COALESCE(
      (SELECT MAX(m.created_at) FROM messages m
       WHERE m.sender_code = conversations.user1_code AND m.receiver_code = conversations.user2_code
          OR m.sender_code = conversations.user2_code AND m.receiver_code = conversations.user1_code),
      conversations.created_at
    )
  WHERE updated_at IS NULL OR last_message_id IS NULL
`).run();

console.log(
  `[migrate] conversations +${backfillConversations.changes}, ` +
  `conversation_id filled ${backfillConversationIds.changes}, ` +
  `counters synced ${syncConversationCounters.changes}`
);

// --------------------------------------------------
// الوسائط (يبقى المسار للتوافق، لكن الرفع المعتمد على الخادم المنفصل)
// --------------------------------------------------
app.use('/media', express.static(MEDIA_DIR));

const storage = multer.diskStorage({
  destination: (_, __, cb) => cb(null, MEDIA_DIR),
  filename: (_, file, cb) => {
    const ext = path.extname(file.originalname).toLowerCase();
    cb(null, `${Date.now()}-${randomBytes(8).toString('hex')}${ext}`);
  }
});

const upload = multer({
  storage,
  limits: { fileSize: 100 * 1024 * 1024 },
  fileFilter: (_, file, cb) => {
    const allowedMimes = [
      'image/jpeg', 'image/png', 'image/webp', 'image/gif', 'image/heic', 'image/heif',
      'video/mp4', 'video/webm', 'video/quicktime', 'video/3gpp',
      'audio/mpeg', 'audio/mp4', 'audio/aac', 'audio/ogg', 'audio/webm',
      'audio/wav', 'audio/x-wav', 'audio/3gpp', 'audio/amr',
      'application/pdf', 'application/zip', 'application/msword',
      'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
      'application/vnd.ms-excel',
      'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
      'application/octet-stream', 'text/plain'
    ];
    if (allowedMimes.includes(file.mimetype)) cb(null, true);
    else cb(new Error('INVALID_FILE_TYPE'));
  }
});

// فحص البايتات السحرية (لا نعتمد على MIME المعلن وحده)
function verifyFileMagicBytes(filePath, mimetype) {
  try {
    const buffer = Buffer.alloc(16);
    const fd = fs.openSync(filePath, 'r');
    fs.readSync(fd, buffer, 0, 16, 0);
    fs.closeSync(fd);

    if (mimetype.startsWith('image/jpeg')) return buffer[0] === 0xFF && buffer[1] === 0xD8 && buffer[2] === 0xFF;
    if (mimetype.startsWith('image/png')) return buffer[0] === 0x89 && buffer[1] === 0x50 && buffer[2] === 0x4E && buffer[3] === 0x47;
    if (mimetype.startsWith('image/gif')) return buffer.toString('ascii', 0, 3) === 'GIF';
    if (mimetype.startsWith('image/webp')) return buffer.toString('ascii', 0, 4) === 'RIFF' && buffer.toString('ascii', 8, 12) === 'WEBP';
    if (mimetype.startsWith('video/mp4') || mimetype === 'video/quicktime') return buffer.toString('ascii', 4, 8) === 'ftyp';
    if (mimetype.startsWith('video/webm') || mimetype.startsWith('audio/webm')) return buffer[0] === 0x1A && buffer[1] === 0x45 && buffer[2] === 0xDF && buffer[3] === 0xA3;
    if (mimetype === 'audio/mpeg') return (buffer[0] === 0x49 && buffer[1] === 0x44 && buffer[2] === 0x33) || (buffer[0] === 0xFF && (buffer[1] & 0xE0) === 0xE0);
    if (mimetype === 'audio/ogg') return buffer.toString('ascii', 0, 4) === 'OggS';
    if (mimetype === 'audio/aac') return buffer[0] === 0xFF && (buffer[1] & 0xF0) === 0xF0;
    if (mimetype.startsWith('audio/mp4') || mimetype === 'audio/3gpp' || mimetype === 'audio/amr') {
      if (buffer.toString('ascii', 4, 8) === 'ftyp') return true;
      return buffer[0] === 0xFF && (buffer[1] & 0xF0) === 0xF0;
    }
    if (mimetype === 'audio/wav' || mimetype === 'audio/x-wav') return buffer.toString('ascii', 0, 4) === 'RIFF' && buffer.toString('ascii', 8, 12) === 'WAVE';
    if (mimetype === 'application/pdf') return buffer.toString('ascii', 0, 4) === '%PDF';
    return true;
  } catch {
    return false;
  }
}

// --------------------------------------------------
// توليد رمز وصال (15 خانة، حرف + رقم إلزاميًا)
// --------------------------------------------------
const WASAL_CODE_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
const WASAL_CODE_REGEX = /^(?=.*[A-Za-z])(?=.*[0-9])[A-Za-z0-9]{15}$/;

function generateUserCode() {
  const letters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz';
  const digits = '0123456789';

  for (let attempt = 0; attempt < 25; attempt++) {
    const characters = [
      letters[randomInt(0, letters.length)],
      digits[randomInt(0, digits.length)]
    ];
    while (characters.length < WASAL_CODE_LENGTH) {
      characters.push(WASAL_CODE_ALPHABET[randomInt(0, WASAL_CODE_ALPHABET.length)]);
    }
    for (let i = characters.length - 1; i > 0; i -= 1) {
      const j = randomInt(0, i + 1);
      [characters[i], characters[j]] = [characters[j], characters[i]];
    }
    const code = characters.join('');
    if (WASAL_CODE_REGEX.test(code) && !userExists(code)) {
      return code;
    }
  }
  throw new Error('FAILED_TO_GENERATE_UNIQUE_CODE');
}

// --------------------------------------------------
// الرموز (JWT) — مدة الوصول 15 دقيقة، التجديد 30 يومًا
// --------------------------------------------------
function createAccessToken(user) {
  return jwt.sign(
    { sub: String(user.id), code: user.code, name: user.name, type: 'access' },
    JWT_SECRET,
    { expiresIn: ACCESS_TOKEN_TTL }
  );
}

function hashToken(token) {
  return createHash('sha256').update(String(token)).digest('hex');
}

function createRefreshToken(user, sessionId) {
  return jwt.sign(
    { sub: String(user.id), code: user.code, type: 'refresh' },
    JWT_SECRET,
    { expiresIn: REFRESH_TOKEN_TTL, jwtid: sessionId }
  );
}

function verifyAccessToken(token) {
  const payload = jwt.verify(token, JWT_SECRET);
  if (
    !payload ||
    typeof payload !== 'object' ||
    payload.type !== 'access' ||
    !payload.code ||
    !payload.sub
  ) {
    throw new Error('INVALID_TOKEN');
  }
  return payload;
}

function verifyRefreshToken(token) {
  const payload = jwt.verify(token, JWT_SECRET);
  if (
    !payload ||
    typeof payload !== 'object' ||
    payload.type !== 'refresh' ||
    !payload.code ||
    !payload.sub ||
    !payload.jti
  ) {
    throw new Error('INVALID_REFRESH_TOKEN');
  }
  return payload;
}

function createSession(userCode, refreshToken, req) {
  const decoded = jwt.decode(refreshToken);
  const sessionId = decoded.jti;
  const expiresAt = new Date(decoded.exp * 1000).toISOString();

  db.prepare(`
    INSERT INTO sessions (id, user_code, refresh_token_hash, created_at, expires_at, last_used_at, user_agent, ip)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
  `).run(
    sessionId,
    userCode,
    hashToken(refreshToken),
    new Date().toISOString(),
    expiresAt,
    new Date().toISOString(),
    String(req?.headers?.['user-agent'] || '').slice(0, 300),
    String(req?.ip || '').slice(0, 60)
  );

  return sessionId;
}

function revokeSession(sessionId) {
  db.prepare('UPDATE sessions SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL')
    .run(new Date().toISOString(), sessionId);
}

function getActiveSession(sessionId, userCode) {
  return db.prepare(`
    SELECT id, user_code, expires_at, revoked_at
    FROM sessions
    WHERE id = ? AND user_code = ?
  `).get(sessionId, userCode);
}

function issueTokenPair(user, req) {
  const accessToken = createAccessToken(user);
  const sessionId = randomUUID();
  const refreshToken = createRefreshToken(user, sessionId);
  createSession(user.code, refreshToken, req);
  return { accessToken, refreshToken, sessionId };
}

// --------------------------------------------------
// تحديد معدل الطلبات (ذاكرة داخلية — بلا اعتماديات خارجية)
// --------------------------------------------------
function makeRateLimiter({ windowMs, max, name }) {
  const buckets = new Map();

  const timer = setInterval(() => {
    const now = Date.now();
    for (const [key, times] of buckets.entries()) {
      const kept = times.filter(t => now - t < windowMs);
      if (kept.length === 0) buckets.delete(key);
      else buckets.set(key, kept);
    }
  }, Math.max(windowMs, 30000));
  if (typeof timer.unref === 'function') timer.unref();

  return (req, res, next) => {
    const key = `${name}:${req.ip}`;
    const now = Date.now();
    const times = (buckets.get(key) || []).filter(t => now - t < windowMs);
    times.push(now);
    buckets.set(key, times);

    if (times.length > max) {
      return res.status(429).json({
        error: 'تم تجاوز عدد الطلبات المسموح به، حاول بعد قليل',
        code: 'RATE_LIMITED'
      });
    }
    return next();
  };
}

const registerLimiter = makeRateLimiter({ windowMs: 60_000, max: 20, name: 'register' });
const refreshLimiter = makeRateLimiter({ windowMs: 60_000, max: 60, name: 'refresh' });
const searchLimiter = makeRateLimiter({ windowMs: 60_000, max: 120, name: 'search' });
const messageLimiter = makeRateLimiter({ windowMs: 60_000, max: 240, name: 'messages' });
const uploadLimiter = makeRateLimiter({ windowMs: 60_000, max: 60, name: 'upload' });

// --------------------------------------------------
// المصادقة
// --------------------------------------------------
function auth(req, res, next) {
  const authorization = req.headers.authorization || '';
  const token = authorization.replace(/^Bearer\s+/i, '').trim();

  if (!token) {
    return res.status(401).json({ error: 'رمز الدخول مطلوب', code: 'TOKEN_REQUIRED' });
  }

  try {
    const payload = verifyAccessToken(token);
    const dbUser = db
      .prepare('SELECT id, code, name FROM users WHERE code = ? AND id = ?')
      .get(payload.code, payload.sub);

    if (!dbUser) {
      return res.status(401).json({ error: 'المستخدم غير موجود', code: 'USER_NOT_FOUND' });
    }

    req.user = payload;
    return next();
  } catch {
    return res.status(401).json({
      error: 'رمز الدخول غير صالح أو منتهي',
      code: 'INVALID_OR_EXPIRED_TOKEN'
    });
  }
}

// --------------------------------------------------
// المساعدات وتنسيق البيانات
// --------------------------------------------------
const onlineUsers = new Map(); // code -> Set(socketId)

function isUserOnline(code) {
  const set = onlineUsers.get(code);
  return Boolean(set && set.size > 0);
}

function formatUser(userFromDb) {
  if (!userFromDb) return null;
  return {
    id: userFromDb.id,
    code: userFromDb.code,
    wasalCode: userFromDb.code,
    phone: userFromDb.phone ?? null,
    name: userFromDb.name,
    displayName: userFromDb.name,
    email: userFromDb.email ?? null,
    avatarUrl: null,
    isOnline: isUserOnline(userFromDb.code),
    lastSeenAt: userFromDb.lastSeenAt ?? null,
    createdAt: userFromDb.createdAt ?? null,
    updatedAt: userFromDb.createdAt ?? null
  };
}

function getUser(codeOrId) {
  const paramStr = String(codeOrId || '').trim();
  let row = null;

  if (/^\d+$/.test(paramStr)) {
    row = db.prepare(`
      SELECT id, code, phone, name, email, created_at AS createdAt, last_seen_at AS lastSeenAt
      FROM users WHERE id = ?
    `).get(Number(paramStr));
  } else if (WASAL_CODE_REGEX.test(paramStr)) {
    row = db.prepare(`
      SELECT id, code, phone, name, email, created_at AS createdAt, last_seen_at AS lastSeenAt
      FROM users WHERE code = ?
    `).get(paramStr);
  }

  return formatUser(row);
}

function userExists(code) {
  if (!code || !WASAL_CODE_REGEX.test(code)) return false;
  return Boolean(db.prepare('SELECT id FROM users WHERE code = ?').get(code));
}

function canonicalConversationId(codeA, codeB) {
  const [u1, u2] = [codeA, codeB].sort();
  return `${u1}_${u2}`;
}

function ensureConversation(codeA, codeB) {
  const [u1, u2] = [codeA, codeB].sort();
  const conversationId = `${u1}_${u2}`;
  const now = new Date().toISOString();

  db.prepare(`
    INSERT OR IGNORE INTO conversations (id, user1_code, user2_code, created_at, updated_at)
    VALUES (?, ?, ?, ?, ?)
  `).run(conversationId, u1, u2, now, now);

  const check = db.prepare(`
    SELECT id FROM conversations WHERE id = ? AND user1_code = ? AND user2_code = ?
  `).get(conversationId, u1, u2);

  if (!check) throw new Error('FAILED_TO_ENSURE_CONVERSATION');
  return conversationId;
}

// قراءة فقط: لا تنشئ محادثة (تُستخدم للقراءة والقوائم)
function getExistingConversation(identifier, currentCode) {
  const cleanId = String(identifier || '').trim();

  if (cleanId.includes('_')) {
    const parts = cleanId.split('_');
    if (parts.length === 2 && (parts[0] === currentCode || parts[1] === currentCode)) {
      const otherCode = parts[0] === currentCode ? parts[1] : parts[0];
      const sorted = [parts[0], parts[1]].sort();
      const canonicalId = `${sorted[0]}_${sorted[1]}`;

      if (cleanId === canonicalId) {
        const conv = db.prepare(`
          SELECT id FROM conversations WHERE id = ? AND user1_code = ? AND user2_code = ?
        `).get(canonicalId, sorted[0], sorted[1]);
        if (conv && userExists(otherCode)) {
          return { id: canonicalId, otherCode };
        }
      }
    }
  } else if (WASAL_CODE_REGEX.test(cleanId) && userExists(cleanId) && cleanId !== currentCode) {
    const canonicalId = canonicalConversationId(currentCode, cleanId);
    const conv = db.prepare('SELECT id FROM conversations WHERE id = ?').get(canonicalId);
    if (conv) return { id: canonicalId, otherCode: cleanId };
  }

  return null;
}

// إنشاء عند الحاجة (للبدء الصريح بالمحادثة أو الإرسال)
function getValidatedConversation(identifier, currentCode) {
  const cleanId = String(identifier || '').trim();

  if (cleanId.includes('_')) {
    const existing = getExistingConversation(cleanId, currentCode);
    if (existing) return existing;
  } else if (WASAL_CODE_REGEX.test(cleanId) && userExists(cleanId) && cleanId !== currentCode) {
    const conversationId = ensureConversation(currentCode, cleanId);
    return { id: conversationId, otherCode: cleanId };
  }

  return null;
}

function formatMessage(msgFromDb, senderNumericId) {
  const resolvedSenderId = senderNumericId === undefined
    ? (db.prepare('SELECT id FROM users WHERE code = ?').get(msgFromDb.sender_code) || {}).id
    : senderNumericId;

  const isMedia = ['image', 'video', 'voice', 'audio', 'file', 'link'].includes(msgFromDb.type);

  let resolvedContent = msgFromDb.text;
  if (isMedia && !resolvedContent && msgFromDb.media_url) {
    resolvedContent = msgFromDb.media_url;
  }

  return {
    id: msgFromDb.id,
    clientId: msgFromDb.client_id ?? null,
    conversationId: msgFromDb.conversation_id ?? null,
    senderCode: msgFromDb.sender_code,
    senderId: resolvedSenderId || msgFromDb.sender_code,
    receiverCode: msgFromDb.receiver_code,
    type: msgFromDb.type,
    text: resolvedContent,
    content: resolvedContent,
    mediaUrl: msgFromDb.media_url,
    createdAt: msgFromDb.created_at
  };
}

function conversationMessages(a, b, limit = 50) {
  const safeLimit = Math.max(1, Math.min(100, Number(limit) || 50));
  const rows = db.prepare(`
    SELECT
      m.id, m.sender_code, m.receiver_code, m.type, m.text, m.media_url, m.created_at,
      m.client_id, m.conversation_id, u.id AS sender_numeric_id
    FROM messages m
    LEFT JOIN users u ON u.code = m.sender_code
    WHERE (m.sender_code = ? AND m.receiver_code = ?)
       OR (m.sender_code = ? AND m.receiver_code = ?)
    ORDER BY m.id DESC
    LIMIT ?
  `).all(a, b, b, a, safeLimit);

  return rows.reverse().map(row => formatMessage(row, row.sender_numeric_id));
}

function findMessageByClientId(senderCode, clientId) {
  if (!clientId) return null;
  const row = db.prepare(`
    SELECT id, sender_code, receiver_code, type, text, media_url, created_at, client_id, conversation_id
    FROM messages WHERE sender_code = ? AND client_id = ?
  `).get(senderCode, String(clientId));
  return row ? formatMessage(row) : null;
}

function saveMessage({ senderCode, receiverCode, type, text = null, mediaUrl = null, clientId = null }) {
  const conversationId = ensureConversation(senderCode, receiverCode);
  const createdAt = new Date().toISOString();

  if (clientId) {
    const existing = findMessageByClientId(senderCode, clientId);
    if (existing) return { message: existing, deduplicated: true, conversationId };
  }

  const result = db.prepare(`
    INSERT INTO messages (sender_code, receiver_code, type, text, media_url, created_at, client_id, conversation_id)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
  `).run(senderCode, receiverCode, type, text, mediaUrl, createdAt, clientId, conversationId);

  db.prepare(`
    UPDATE conversations
    SET last_message_id = ?, last_message_at = ?, updated_at = ?
    WHERE id = ?
  `).run(Number(result.lastInsertRowid), createdAt, createdAt, conversationId);

  const senderRow = db.prepare('SELECT id FROM users WHERE code = ?').get(senderCode);

  return {
    message: formatMessage({
      id: Number(result.lastInsertRowid),
      sender_code: senderCode,
      receiver_code: receiverCode,
      type,
      text,
      media_url: mediaUrl,
      created_at: createdAt,
      client_id: clientId,
      conversation_id: conversationId
    }, senderRow ? senderRow.id : null),
    deduplicated: false,
    conversationId
  };
}

// --------------------------------------------------
// التحقق من رابط الوسائط (سياسة المضيفات المسموح بها + منع النص الصريح)
// --------------------------------------------------
function validateMediaUrl(rawUrl, ownHost) {
  const value = String(rawUrl || '').trim();

  if (!value) return { ok: false, code: 'MEDIA_URL_REQUIRED' };

  let parsed;
  try {
    parsed = new URL(value);
  } catch {
    return { ok: false, code: 'INVALID_MEDIA_URL' };
  }

  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    return { ok: false, code: 'INVALID_MEDIA_URL' };
  }

  const host = parsed.hostname.toLowerCase();
  const own = String(ownHost || '').split(':')[0].toLowerCase();
  const isLocal = host === 'localhost' || host === '127.0.0.1';
  const allowed = MEDIA_ALLOWED_HOSTS.includes(host) || (own && host === own) || isLocal;

  if (!allowed) return { ok: false, code: 'MEDIA_HOST_NOT_ALLOWED' };

  if (parsed.protocol === 'http:' && !isLocal) {
    return { ok: false, code: 'MEDIA_URL_NOT_SECURE' };
  }

  return { ok: true, url: parsed.toString() };
}

// --------------------------------------------------
// مسارات الصحة
// --------------------------------------------------
app.get('/health', (_, res) => {
  let dbOk = false;
  try {
    db.prepare('SELECT 1 AS ok').get();
    dbOk = true;
  } catch {
    dbOk = false;
  }

  res.status(dbOk ? 200 : 503).json({
    ok: dbOk,
    service: SERVICE_NAME,
    version: SERVICE_VERSION,
    database: dbOk ? 'ok' : 'error'
  });
});

app.get('/', (_, res) => {
  res.json({ ok: true, service: SERVICE_NAME, version: SERVICE_VERSION });
});

// --------------------------------------------------
// تجديد الجلسة (+ تدوير وإبطال الرمز القديم)
// --------------------------------------------------
app.post('/api/auth/refresh', refreshLimiter, (req, res) => {
  const refreshToken = String(req.body?.refreshToken || req.body?.refresh_token || '').trim();

  if (!refreshToken) {
    return res.status(400).json({ error: 'Refresh Token مطلوب', code: 'REFRESH_TOKEN_REQUIRED' });
  }

  try {
    const payload = verifyRefreshToken(refreshToken);
    const user = getUser(payload.code);

    if (!user || String(user.id) !== String(payload.sub)) {
      return res.status(401).json({
        error: 'المستخدم غير موجود أو غير صالح',
        code: 'INVALID_OR_EXPIRED_REFRESH_TOKEN'
      });
    }

    const session = getActiveSession(payload.jti, payload.code);
    if (!session || session.revoked_at) {
      return res.status(401).json({
        error: 'جلسة التجديد ملغاة أو غير موجودة',
        code: 'REFRESH_SESSION_REVOKED'
      });
    }
    if (new Date(session.expires_at).getTime() <= Date.now()) {
      return res.status(401).json({
        error: 'Refresh Token غير صالح أو منتهي',
        code: 'INVALID_OR_EXPIRED_REFRESH_TOKEN'
      });
    }

    // تدوير: إبطال القديم وإصدار جديد
    revokeSession(payload.jti);
    const pair = issueTokenPair(user, req);

    return res.json({
      ok: true,
      tokens: {
        accessToken: pair.accessToken,
        refreshToken: pair.refreshToken,
        token: pair.accessToken
      },
      accessToken: pair.accessToken,
      refreshToken: pair.refreshToken,
      token: pair.accessToken
    });
  } catch {
    return res.status(401).json({
      error: 'Refresh Token غير صالح أو منتهي',
      code: 'INVALID_OR_EXPIRED_REFRESH_TOKEN'
    });
  }
});

// --------------------------------------------------
// إبطال الجلسات (تسجيل خروج حقيقي)
// --------------------------------------------------
app.post('/api/auth/logout', auth, (req, res) => {
  const refreshToken = String(req.body?.refreshToken || '').trim();

  if (!refreshToken) {
    return res.status(400).json({ error: 'Refresh Token مطلوب', code: 'REFRESH_TOKEN_REQUIRED' });
  }

  try {
    const payload = verifyRefreshToken(refreshToken);
    if (payload.code !== req.user.code) {
      return res.status(403).json({ error: 'الرمز لا يخص هذه الجلسة', code: 'TOKEN_OWNER_MISMATCH' });
    }
    revokeSession(payload.jti);
    return res.json({ ok: true, revoked: true });
  } catch {
    return res.status(401).json({
      error: 'Refresh Token غير صالح أو منتهي',
      code: 'INVALID_OR_EXPIRED_REFRESH_TOKEN'
    });
  }
});

app.post('/api/auth/logout-all', auth, (req, res) => {
  const result = db.prepare(`
    UPDATE sessions SET revoked_at = ?
    WHERE user_code = ? AND revoked_at IS NULL
  `).run(new Date().toISOString(), req.user.code);

  return res.json({ ok: true, revokedSessions: result.changes });
});

// --------------------------------------------------
// التسجيل (اسم العرض فقط) + الواجهة البديلة /api/users/create
// --------------------------------------------------
const registerHandler = (req, res) => {
  try {
    const name = String(
      req.body?.displayName ||
      req.body?.display_name ||
      req.body?.name ||
      req.body?.username ||
      ''
    ).trim();

    if (!name) {
      return res.status(400).json({ error: 'اسم المستخدم مطلوب', code: 'NAME_REQUIRED' });
    }
    if (name.length > MAX_DISPLAY_NAME) {
      return res.status(400).json({
        error: `اسم المستخدم يجب ألا يتجاوز ${MAX_DISPLAY_NAME} حرفاً`,
        code: 'NAME_TOO_LONG'
      });
    }

    // إنشاء الحساب والرموز داخل معاملة واحدة حتى لا ينتج حساب ناقص بلا جلسة.
    const createAccount = db.transaction(() => {
      let code = null;
      for (let i = 0; i < 5; i += 1) {
        try {
          const candidate = generateUserCode();
          db.prepare('INSERT INTO users (code, name, created_at) VALUES (?, ?, ?)')
            .run(candidate, name, new Date().toISOString());
          code = candidate;
          break;
        } catch (err) {
          if (i === 4) throw err;
        }
      }

      if (!code) throw new Error('REGISTRATION_FAILED');

      const user = getUser(code);
      if (!user) throw new Error('USER_LOOKUP_FAILED');

      return { code, user };
    });

    const { user } = createAccount();
    const pair = issueTokenPair(user, req);

    return res.status(201).json({
      ok: true,
      user,
      tokens: {
        accessToken: pair.accessToken,
        refreshToken: pair.refreshToken,
        token: pair.accessToken
      },
      token: pair.accessToken,
      accessToken: pair.accessToken,
      refreshToken: pair.refreshToken
    });
  } catch (error) {
    console.error('Registration error:', error.message);
    return res.status(500).json({ error: 'تعذر إنشاء الحساب', code: 'INTERNAL_SERVER_ERROR' });
  }
};

app.post('/api/auth/register', registerLimiter, registerHandler);
app.post('/api/users/create', registerLimiter, registerHandler);

// --------------------------------------------------
// الملف الشخصي
// --------------------------------------------------
app.get('/api/users/me', auth, (req, res) => {
  const user = getUser(req.user.code);
  if (!user) {
    return res.status(404).json({ error: 'المستخدم غير موجود', code: 'USER_NOT_FOUND' });
  }
  res.json({ ok: true, user });
});

app.put('/api/users/me/display-name', auth, (req, res) => {
  const newName = String(
    req.body?.displayName || req.body?.display_name || req.body?.name || ''
  ).trim();

  if (!newName) {
    return res.status(400).json({ error: 'اسم العرض مطلوب', code: 'NAME_REQUIRED' });
  }
  if (newName.length > MAX_DISPLAY_NAME) {
    return res.status(400).json({
      error: `اسم العرض يجب ألا يتجاوز ${MAX_DISPLAY_NAME} حرفاً`,
      code: 'NAME_TOO_LONG'
    });
  }

  db.prepare('UPDATE users SET name = ? WHERE code = ?').run(newName, req.user.code);
  const user = getUser(req.user.code);
  res.json({ ok: true, user });
});

// --------------------------------------------------
// البحث عن المستخدمين (قبل /:code حتى لا يتعارض)
// --------------------------------------------------
app.get('/api/users/search/wasal-code', auth, searchLimiter, (req, res) => {
  const code = String(req.query.wasalCode || req.query.code || req.query.q || '').trim();

  if (!WASAL_CODE_REGEX.test(code)) {
    return res.status(400).json({ error: 'رمز وصال غير صالح', code: 'INVALID_WASAL_CODE' });
  }

  const user = getUser(code);
  if (!user) {
    return res.status(404).json({ error: 'المستخدم غير موجود', code: 'USER_NOT_FOUND' });
  }

  res.json({ ok: true, user });
});

app.get('/api/users/:code', auth, (req, res) => {
  const user = getUser(String(req.params.code || '').trim());
  if (!user) {
    return res.status(404).json({ error: 'المستخدم غير موجود', code: 'USER_NOT_FOUND' });
  }
  res.json({ ok: true, user });
});

// --------------------------------------------------
// المحادثات
// --------------------------------------------------
app.post('/api/conversations', auth, (req, res) => {
  const receiverCode = String(
    req.body?.wasalCode ||
    req.body?.recipientCode ||
    req.body?.receiverCode ||
    req.body?.code ||
    ''
  ).trim();

  if (!WASAL_CODE_REGEX.test(receiverCode)) {
    return res.status(400).json({ error: 'رمز وصال غير صالح', code: 'INVALID_WASAL_CODE' });
  }

  if (receiverCode === req.user.code) {
    return res.status(400).json({
      error: 'لا يمكن بدء محادثة مع نفسك',
      code: 'CANNOT_CHAT_WITH_SELF'
    });
  }

  const user = getUser(receiverCode);
  if (!user) {
    return res.status(404).json({ error: 'المستخدم غير موجود', code: 'USER_NOT_FOUND' });
  }

  const conversationId = ensureConversation(req.user.code, receiverCode);

  const lastMessage = conversationMessages(req.user.code, receiverCode, 1).slice(-1)[0] || null;
  const title = user.displayName || user.name || 'محادثة وصال';

  res.status(201).json({
    ok: true,
    conversation: {
      id: conversationId,
      title,
      name: title,
      lastMessage: lastMessage ? (lastMessage.content || '') : '',
      lastMessageAt: lastMessage ? lastMessage.createdAt : null,
      updatedAt: lastMessage ? lastMessage.createdAt : null,
      unreadCount: 0,
      otherCode: receiverCode,
      user,
      lastMessageObject: lastMessage
    }
  });
});

const listConversationsHandler = (req, res) => {
  const rows = db.prepare(`
    SELECT
      c.id AS conversationId,
      CASE WHEN c.user1_code = ? THEN c.user2_code ELSE c.user1_code END AS otherCode,
      c.created_at AS createdAt,
      c.last_message_id AS lastMessageId,
      c.last_message_at AS lastMessageAt
    FROM conversations c
    WHERE c.user1_code = ? OR c.user2_code = ?
    ORDER BY COALESCE(c.last_message_at, c.created_at) DESC, c.created_at DESC
  `).all(req.user.code, req.user.code, req.user.code);

  const otherCodes = [...new Set(rows.map(r => r.otherCode))];
  const usersByCode = new Map();
  if (otherCodes.length > 0) {
    const placeholders = otherCodes.map(() => '?').join(', ');
    const userRows = db.prepare(`
      SELECT id, code, phone, name, email, created_at AS createdAt, last_seen_at AS lastSeenAt
      FROM users WHERE code IN (${placeholders})
    `).all(...otherCodes);
    for (const row of userRows) usersByCode.set(row.code, formatUser(row));
  }

  const messageIds = rows.map(r => r.lastMessageId).filter(Boolean);
  const messagesById = new Map();
  if (messageIds.length > 0) {
    const placeholders = messageIds.map(() => '?').join(', ');
    const messageRows = db.prepare(`
      SELECT id, sender_code, receiver_code, type, text, media_url, created_at, client_id, conversation_id
      FROM messages WHERE id IN (${placeholders})
    `).all(...messageIds);
    for (const row of messageRows) messagesById.set(row.id, formatMessage(row));
  }

  const conversations = rows.map(row => {
    const other = usersByCode.get(row.otherCode) || null;
    const lastMessageObject = row.lastMessageId ? (messagesById.get(row.lastMessageId) || null) : null;
    const title = other?.displayName || other?.name || 'محادثة وصال';
    const lastMessageText = lastMessageObject
      ? (lastMessageObject.content || lastMessageObject.text || '')
      : '';
    const lastMessageAt = lastMessageObject ? lastMessageObject.createdAt : null;

    return {
      id: row.conversationId,
      title,
      name: title,
      lastMessage: lastMessageText,
      lastMessageAt,
      updatedAt: lastMessageAt || row.createdAt,
      unreadCount: 0,
      otherCode: row.otherCode,
      user: other,
      lastMessageObject
    };
  });

  res.json({ ok: true, conversations, chats: conversations });
};

app.get('/api/conversations', auth, listConversationsHandler);
app.get('/api/chats', auth, listConversationsHandler);

const handleGetMessages = (req, res) => {
  const identifier = String(req.params.code || req.params.conversationId || '').trim();
  const limit = req.query.limit || 50;

  // صارم: قراءة فقط بلا إنشاء محادثة
  const convInfo = getExistingConversation(identifier, req.user.code);
  if (!convInfo) {
    return res.status(403).json({
      error: 'غير مسموح بالوصول إلى هذه المحادثة أو أنها غير موجودة',
      code: 'INVALID_CONVERSATION'
    });
  }

  const messages = conversationMessages(req.user.code, convInfo.otherCode, limit);
  res.json({ ok: true, messages });
};

app.get('/api/conversations/:code/messages', auth, handleGetMessages);
app.get('/api/messages/conversation/:conversationId', auth, handleGetMessages);

// --------------------------------------------------
// الإرسال (REST) — يُحفظ قبل تأكيد النجاح
// --------------------------------------------------
const handleSendMessage = (req, res) => {
  let receiverCode = String(req.body?.receiverCode || req.body?.recipientCode || '').trim();
  const conversationId = String(req.body?.conversationId || '').trim();
  const clientId = req.body?.clientId ? String(req.body.clientId).slice(0, 120) : null;

  if (conversationId) {
    const convInfo = getExistingConversation(conversationId, req.user.code);
    if (!convInfo) {
      return res.status(403).json({
        error: 'معرّف المحادثة غير صالح أو غير موجود',
        code: 'INVALID_CONVERSATION'
      });
    }
    if (receiverCode && convInfo.otherCode !== receiverCode) {
      return res.status(403).json({
        error: 'معرّف المحادثة غير مطابق للمستقبِل',
        code: 'CONVERSATION_MISMATCH'
      });
    }
    receiverCode = convInfo.otherCode;
  }

  const type = String(req.body?.type || 'text').trim();

  // التطبيق يضع رابط الوسائط داخل content وليس mediaUrl
  let mediaUrl = String(req.body?.mediaUrl || req.body?.media_url || '').trim();
  const rawContent = String(req.body?.content ?? req.body?.text ?? '').trim();

  if (!mediaUrl && MEDIA_MESSAGE_TYPES.includes(type) && rawContent) {
    mediaUrl = rawContent;
  }

  const text = type === 'text' ? rawContent : (rawContent && rawContent !== mediaUrl ? rawContent : '');

  if (!WASAL_CODE_REGEX.test(receiverCode)) {
    return res.status(400).json({ error: 'رمز وصال المستقبِل غير صالح', code: 'INVALID_RECEIVER' });
  }
  if (receiverCode === req.user.code) {
    return res.status(400).json({ error: 'لا يمكن الإرسال لنفسك', code: 'SELF_MESSAGE_NOT_ALLOWED' });
  }
  if (!userExists(receiverCode)) {
    return res.status(404).json({ error: 'المستخدم المستقبِل غير موجود', code: 'USER_NOT_FOUND' });
  }
  if (!ALLOWED_MESSAGE_TYPES.includes(type)) {
    return res.status(400).json({ error: 'نوع الرسالة غير صالح', code: 'INVALID_MESSAGE_TYPE' });
  }
  if (type === 'text' && !rawContent) {
    return res.status(400).json({ error: 'نص الرسالة مطلوب', code: 'TEXT_REQUIRED' });
  }
  if (MEDIA_MESSAGE_TYPES.includes(type) && !mediaUrl) {
    return res.status(400).json({ error: 'رابط الوسائط مطلوب', code: 'MEDIA_URL_REQUIRED' });
  }
  if (type === 'link' && !rawContent && !mediaUrl) {
    return res.status(400).json({ error: 'رابط الموقع مطلوب', code: 'LINK_REQUIRED' });
  }

  let safeMediaUrl = null;
  if (MEDIA_MESSAGE_TYPES.includes(type) || type === 'link') {
    const candidate = mediaUrl || rawContent;
    const check = validateMediaUrl(candidate, req.get('host'));
    if (!check.ok) {
      return res.status(400).json({
        error: 'رابط الوسائط غير مسموح أو غير آمن',
        code: check.code
      });
    }
    safeMediaUrl = check.url;
  }

  const convInfo = getValidatedConversation(receiverCode, req.user.code);
  if (!convInfo) {
    return res.status(403).json({
      error: 'غير مسموح بإنشاء محادثة مع هذا المستخدم',
      code: 'INVALID_CONVERSATION'
    });
  }

  const saved = saveMessage({
    senderCode: req.user.code,
    receiverCode,
    type,
    text: text || safeMediaUrl,
    mediaUrl: safeMediaUrl,
    clientId
  });

  io.to(`user:${receiverCode}`).emit('message', saved.message);

  return res.status(201).json({
    ok: true,
    message: saved.message,
    conversationId: saved.conversationId,
    deduplicated: saved.deduplicated
  });
};

app.post('/api/messages', auth, messageLimiter, handleSendMessage);
app.post('/api/messages/media', auth, messageLimiter, handleSendMessage);
app.post('/api/messages/link', auth, messageLimiter, (req, res) => {
  req.body = req.body || {};
  req.body.type = 'link';
  if (!req.body.content && !req.body.text && req.body.url) req.body.content = req.body.url;
  return handleSendMessage(req, res);
});

// --------------------------------------------------
// المكالمات: واجهة توافقية (التنفيذ في الخادم المنفصل)
// --------------------------------------------------
app.get('/api/calls', auth, (_, res) => {
  res.json({ ok: true, calls: [] });
});

// --------------------------------------------------
// رفع الوسائط (للتوافق — الرفع المعتمد على الخادم المنفصل)
// --------------------------------------------------
app.post('/api/media/upload', auth, uploadLimiter, upload.single('file'), (req, res) => {
  if (!req.file) {
    return res.status(400).json({ error: 'لم يتم إرسال ملف', code: 'FILE_REQUIRED' });
  }

  if (!verifyFileMagicBytes(req.file.path, req.file.mimetype)) {
    try { fs.unlinkSync(req.file.path); } catch {}
    return res.status(400).json({
      error: 'محتوى الملف لا يتطابق مع نوعه المعلن',
      code: 'INVALID_FILE_SIGNATURE'
    });
  }

  const mime = req.file.mimetype;
  let type = 'file';
  if (mime.startsWith('image/')) type = 'image';
  else if (mime.startsWith('video/')) type = 'video';
  else if (mime.startsWith('audio/')) type = 'audio';

  const relativeUrl = `/media/${req.file.filename}`;
  const forwardedProto = String(req.headers['x-forwarded-proto'] || '').split(',')[0].trim();
  const protocol = forwardedProto || 'https';
  const url = `${protocol}://${req.get('host')}${relativeUrl}`;

  res.status(201).json({
    ok: true,
    type,
    filename: req.file.filename,
    url,
    absoluteUrl: url,
    mediaUrl: url,
    relativeUrl
  });
});

// --------------------------------------------------
// Socket.IO — مصادقة برمز الوصول فقط
// --------------------------------------------------
io.use((socket, next) => {
  const token = socket.handshake.auth?.token;
  if (!token) return next(new Error('TOKEN_REQUIRED'));

  try {
    const payload = verifyAccessToken(token);
    const dbUser = db
      .prepare('SELECT id, code FROM users WHERE code = ? AND id = ?')
      .get(payload.code, payload.sub);

    if (!dbUser) return next(new Error('USER_NOT_FOUND'));

    socket.user = payload;
    return next();
  } catch {
    return next(new Error('INVALID_OR_EXPIRED_TOKEN'));
  }
});

io.on('connection', socket => {
  const code = socket.user.code;

  socket.join(`user:${code}`);

  // حالة الاتصال: تُحدَّث لجميع الأجهزة النشطة
  if (!onlineUsers.has(code)) onlineUsers.set(code, new Set());
  onlineUsers.get(code).add(socket.id);
  db.prepare('UPDATE users SET is_online = 1, last_seen_at = ? WHERE code = ?')
    .run(new Date().toISOString(), code);
  io.emit('presence', { code, isOnline: true });

  socket.on('send_message', (data, callback) => {
    try {
      let receiverCode = String(data?.receiverCode || '').trim();
      const conversationId = String(data?.conversationId || '').trim();
      const clientId = data?.clientId ? String(data.clientId).slice(0, 120) : null;

      if (conversationId) {
        const convInfo = getExistingConversation(conversationId, code);
        if (!convInfo) throw new Error('INVALID_CONVERSATION');
        if (receiverCode && convInfo.otherCode !== receiverCode) {
          throw new Error('CONVERSATION_MISMATCH');
        }
        receiverCode = convInfo.otherCode;
      }

      const type = String(data?.type || 'text').trim();
      const rawContent = String(data?.content ?? data?.text ?? '').trim();
      let mediaUrl = data?.mediaUrl == null ? '' : String(data.mediaUrl).trim();

      if (!mediaUrl && MEDIA_MESSAGE_TYPES.includes(type) && rawContent) mediaUrl = rawContent;

      if (!WASAL_CODE_REGEX.test(receiverCode) || receiverCode === code || !userExists(receiverCode)) {
        throw new Error('INVALID_RECEIVER');
      }
      if (!ALLOWED_MESSAGE_TYPES.includes(type)) throw new Error('INVALID_MESSAGE_TYPE');
      if (type === 'text' && !rawContent) throw new Error('TEXT_REQUIRED');
      if (MEDIA_MESSAGE_TYPES.includes(type) && !mediaUrl) throw new Error('MEDIA_URL_REQUIRED');

      let safeMediaUrl = null;
      if (MEDIA_MESSAGE_TYPES.includes(type) || type === 'link') {
        const check = validateMediaUrl(mediaUrl || rawContent, socket.handshake.headers.host);
        if (!check.ok) throw new Error(check.code);
        safeMediaUrl = check.url;
      }

      const convInfo = getValidatedConversation(receiverCode, code);
      if (!convInfo) throw new Error('INVALID_CONVERSATION');

      const saved = saveMessage({
        senderCode: code,
        receiverCode,
        type,
        text: (type === 'text' ? rawContent : (rawContent && rawContent !== safeMediaUrl ? rawContent : '')) || safeMediaUrl,
        mediaUrl: safeMediaUrl,
        clientId
      });

      // الغرفة تضمن وصول الرسالة إلى جميع أجهزة المستقبِل المتصلة
      io.to(`user:${receiverCode}`).emit('message', saved.message);
      socket.emit('message_sent', saved.message);

      if (typeof callback === 'function') {
        callback({ ok: true, message: saved.message, deduplicated: saved.deduplicated });
      }
    } catch (error) {
      if (typeof callback === 'function') {
        callback({ ok: false, error: error.message });
      }
    }
  });

  socket.on('disconnect', () => {
    const set = onlineUsers.get(code);
    if (set) {
      set.delete(socket.id);
      if (set.size === 0) {
        onlineUsers.delete(code);
        db.prepare('UPDATE users SET is_online = 0, last_seen_at = ? WHERE code = ?')
          .run(new Date().toISOString(), code);
        io.emit('presence', { code, isOnline: false });
      }
    }
  });
});

// --------------------------------------------------
// 404 بصيغة JSON لكل مسارات API
// --------------------------------------------------
app.use('/api', (_, res) => {
  res.status(404).json({ error: 'المسار غير موجود', code: 'NOT_FOUND' });
});

// --------------------------------------------------
// معالج الأخطاء
// --------------------------------------------------
app.use((err, _, res, __) => {
  console.error('Server error:', err?.message || err);

  if (err instanceof multer.MulterError) {
    if (err.code === 'LIMIT_FILE_SIZE') {
      return res.status(413).json({ error: 'حجم الملف أكبر من الحد المسموح', code: 'FILE_TOO_LARGE' });
    }
    if (err.code === 'LIMIT_UNEXPECTED_FILE') {
      return res.status(400).json({ error: 'اسم حقل الملف يجب أن يكون file', code: 'UNEXPECTED_FILE_FIELD' });
    }
    return res.status(400).json({ error: err.message, code: err.code || 'UPLOAD_ERROR' });
  }

  if (err?.message === 'INVALID_FILE_TYPE') {
    return res.status(400).json({ error: 'نوع الملف غير مسموح', code: 'INVALID_FILE_TYPE' });
  }

  if (err instanceof SyntaxError && 'body' in err) {
    return res.status(400).json({ error: 'صيغة JSON غير صالحة', code: 'INVALID_JSON' });
  }

  res.status(500).json({
    error: err?.message || 'حدث خطأ في الخادم',
    code: 'INTERNAL_SERVER_ERROR'
  });
});

// --------------------------------------------------
// الإيقاف الآمن
// --------------------------------------------------
let shuttingDown = false;

function shutdown(signal) {
  if (shuttingDown) return;
  shuttingDown = true;
  console.log(`${signal} received, shutting down...`);

  try { io.close(); } catch {}

  httpServer.close(() => {
    try { db.pragma('wal_checkpoint(TRUNCATE)'); } catch {}
    try { db.close(); } catch {}
    console.log('shutdown complete');
    process.exit(0);
  });

  setTimeout(() => process.exit(0), 10000).unref();
}

process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT', () => shutdown('SIGINT'));

// --------------------------------------------------
// التشغيل
// --------------------------------------------------
httpServer.listen(PORT, '0.0.0.0', () => {
  console.log(`${SERVICE_NAME} v${SERVICE_VERSION} running on port ${PORT}`);
  console.log(`database: ${path.resolve(DB_FILE)}`);
  console.log(`media dir: ${path.resolve(MEDIA_DIR)}`);
  console.log(`allowed media hosts: ${MEDIA_ALLOWED_HOSTS.join(', ')}`);
});

export { app, httpServer, io, db };
