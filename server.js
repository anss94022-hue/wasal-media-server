import 'dotenv/config';
import express from 'express';
import cors from 'cors';
import jwt from 'jsonwebtoken';
import multer from 'multer';
import fs from 'fs';
import path from 'path';
import { createServer } from 'http';
import { randomInt } from 'node:crypto';
import { Server } from 'socket.io';
import Database from 'better-sqlite3';

const PORT = Number(process.env.PORT || 3000);
const JWT_SECRET =
  process.env.JWT_SECRET ||
  'WASAL_CHANGE_THIS_SECRET';

const app = express();
const httpServer = createServer(app);

const io = new Server(httpServer, {
  cors: {
    origin: '*',
    methods: ['GET', 'POST']
  }
});

app.use(cors());
app.use(express.json({ limit: '5mb' }));

// --------------------------------------------------
// Directories
// --------------------------------------------------
const DATA_DIR = './data';
const MEDIA_DIR = './media';

fs.mkdirSync(DATA_DIR, { recursive: true });
fs.mkdirSync(MEDIA_DIR, { recursive: true });

// --------------------------------------------------
// Database
// --------------------------------------------------
const db = new Database(
  path.join(DATA_DIR, 'wasal.db')
);

db.pragma('journal_mode = WAL');

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    code TEXT NOT NULL UNIQUE,
    pin_code TEXT,
    phone TEXT,
    name TEXT NOT NULL,
    email TEXT,
    password TEXT,
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

  CREATE INDEX IF NOT EXISTS idx_statuses_user
  ON statuses(user_code, created_at);

  CREATE INDEX IF NOT EXISTS idx_statuses_expiry
  ON statuses(expires_at);
`);

// --------------------------------------------------
// Database migrations
// --------------------------------------------------
function ensureColumn(
  tableName,
  columnName,
  definition
) {
  const columns = db
    .prepare(`PRAGMA table_info(${tableName})`)
    .all();

  const exists = columns.some(
    column => column.name === columnName
  );

  if (!exists) {
    db.exec(
      `ALTER TABLE ${tableName} ADD COLUMN ${columnName} ${definition}`
    );
  }
}

ensureColumn('users', 'pin_code', 'TEXT');
ensureColumn('users', 'phone', 'TEXT');

// --------------------------------------------------
// Media
// --------------------------------------------------
app.use(
  '/media',
  express.static(MEDIA_DIR)
);

const storage = multer.diskStorage({
  destination: (_, __, cb) =>
    cb(null, MEDIA_DIR),

  filename: (_, file, cb) => {
    const ext = path.extname(
      file.originalname
    ).toLowerCase();

    const safeName =
      `${Date.now()}-${Math.random()
        .toString(36)
        .substring(2, 10)}${ext}`;

    cb(null, safeName);
  }
});

const upload = multer({
  storage,

  limits: {
    fileSize: 100 * 1024 * 1024
  },

  fileFilter: (_, file, cb) => {
    const allowed = [
      'image/jpeg',
      'image/png',
      'image/webp',
      'image/gif',
      'video/mp4',
      'video/webm',
      'video/quicktime'
    ];

    if (allowed.includes(file.mimetype)) {
      cb(null, true);
    } else {
      cb(new Error('نوع الملف غير مسموح'));
    }
  }
});

// --------------------------------------------------
// Helpers
// --------------------------------------------------
const WASAL_CODE_LENGTH = 15;
const WASAL_CODE_ALPHABET =
  'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';

const WASAL_CODE_REGEX = /^[A-Za-z0-9]{15}$/;

function generateUserCode() {
  for (;;) {
    let code = '';

    for (let i = 0; i < WASAL_CODE_LENGTH; i += 1) {
      code += WASAL_CODE_ALPHABET[
        randomInt(0, WASAL_CODE_ALPHABET.length)
      ];
    }

    const exists = db
      .prepare('SELECT id FROM users WHERE code = ?')
      .get(code);

    if (!exists) {
      return code;
    }
  }
}

// --------------------------------------------------
// Migrate old user codes to 15 alphanumeric characters
// --------------------------------------------------
// This changes legacy codes. Users with old codes must
// sign in again. Message and status references are updated.
const migrateLegacyUserCodes = db.transaction(() => {
  const legacyUsers = db
    .prepare('SELECT id, code FROM users')
    .all()
    .filter(
      user =>
        !WASAL_CODE_REGEX.test(
          String(user.code || '')
        )
    );

  const updateUserCode = db.prepare(
    'UPDATE users SET code = ? WHERE id = ?'
  );

  const updateSentMessages = db.prepare(
    'UPDATE messages SET sender_code = ? WHERE sender_code = ?'
  );

  const updateReceivedMessages = db.prepare(
    'UPDATE messages SET receiver_code = ? WHERE receiver_code = ?'
  );

  const updateStatuses = db.prepare(
    'UPDATE statuses SET user_code = ? WHERE user_code = ?'
  );

  const updateStatusViews = db.prepare(
    'UPDATE status_views SET viewer_code = ? WHERE viewer_code = ?'
  );

  for (const user of legacyUsers) {
    const oldCode = String(user.code);
    const newCode = generateUserCode();

    updateUserCode.run(newCode, user.id);
    updateSentMessages.run(newCode, oldCode);
    updateReceivedMessages.run(newCode, oldCode);
    updateStatuses.run(newCode, oldCode);
    updateStatusViews.run(newCode, oldCode);
  }

  return legacyUsers.length;
});

const migratedUserCodes = migrateLegacyUserCodes();

if (migratedUserCodes > 0) {
  console.log(
    `Migrated ${migratedUserCodes} legacy user code(s) to 15 characters.`
  );
}

function generatePinCode() {
  return String(
    Math.floor(1000 + Math.random() * 9000)
  );
}

// --------------------------------------------------
// Access Token
// --------------------------------------------------
function createAccessToken(user) {
  return jwt.sign(
    {
      code: user.code,
      name: user.name,
      type: 'access'
    },
    JWT_SECRET,
    {
      expiresIn: '15m'
    }
  );
}

// --------------------------------------------------
// Refresh Token
// --------------------------------------------------
function createRefreshToken(user) {
  return jwt.sign(
    {
      code: user.code,
      type: 'refresh'
    },
    JWT_SECRET,
    {
      expiresIn: '30d'
    }
  );
}

// --------------------------------------------------
// Backward compatibility
// --------------------------------------------------
function createToken(user) {
  return createAccessToken(user);
}

// --------------------------------------------------
// Verify Access Token
// --------------------------------------------------
function verifyAccessToken(token) {
  const payload = jwt.verify(token, JWT_SECRET);

  if (
    !payload ||
    typeof payload !== 'object'
  ) {
    throw new Error('INVALID_TOKEN');
  }

  if (
    typeof payload.code !== 'string' ||
    !payload.code
  ) {
    throw new Error('INVALID_TOKEN');
  }

  if (payload.type === 'refresh') {
    throw new Error('REFRESH_TOKEN_NOT_ALLOWED');
  }

  return payload;
}

// --------------------------------------------------
// Authentication Middleware
// --------------------------------------------------
function auth(req, res, next) {
  const authorization =
    req.headers.authorization || '';

  const token = authorization
    .replace(/^Bearer\s+/i, '')
    .trim();

  if (!token) {
    return res.status(401).json({
      error: 'رمز الدخول مطلوب'
    });
  }

  try {
    req.user = verifyAccessToken(token);
    next();
  } catch {
    return res.status(401).json({
      error: 'رمز الدخول غير صالح أو منتهي'
    });
  }
}

// --------------------------------------------------
// User Helpers
// --------------------------------------------------
function getUser(codeOrId) {
  return db.prepare(`
    SELECT
      id,
      code,
      pin_code AS pinCode,
      pin_code,
      phone,
      name,
      email,
      created_at AS createdAt
    FROM users
    WHERE code = ? OR id = ?
  `).get(codeOrId, codeOrId);
}

function userExists(code) {
  return Boolean(
    db
      .prepare('SELECT id FROM users WHERE code = ?')
      .get(code)
  );
}

function conversationMessages(a, b) {
  return db.prepare(`
    SELECT
      id,
      sender_code AS senderCode,
      receiver_code AS receiverCode,
      type,
      text,
      media_url AS mediaUrl,
      created_at AS createdAt
    FROM messages
    WHERE
      (sender_code = ? AND receiver_code = ?)
      OR
      (sender_code = ? AND receiver_code = ?)
    ORDER BY id ASC
  `).all(a, b, b, a);
}

function saveMessage({
  senderCode,
  receiverCode,
  type,
  text = null,
  mediaUrl = null
}) {
  const createdAt = new Date().toISOString();

  const result = db.prepare(`
    INSERT INTO messages (
      sender_code,
      receiver_code,
      type,
      text,
      media_url,
      created_at
    )
    VALUES (?, ?, ?, ?, ?, ?)
  `).run(
    senderCode,
    receiverCode,
    type,
    text,
    mediaUrl,
    createdAt
  );

  return {
    id: Number(result.lastInsertRowid),
    senderCode,
    receiverCode,
    type,
    text,
    mediaUrl,
    createdAt
  };
}

// --------------------------------------------------
// Health
// --------------------------------------------------
app.get('/health', (_, res) => {
  res.json({
    ok: true,
    service: 'wasal-server',
    version: '3.7.0'
  });
});

app.get('/', (_, res) => {
  res.json({
    ok: true,
    service: 'wasal-server',
    version: '3.7.0'
  });
});

// --------------------------------------------------
// Refresh Access Token
// --------------------------------------------------
app.post('/api/auth/refresh', (req, res) => {
  const refreshToken = String(
    req.body?.refreshToken ||
    req.body?.refresh_token ||
    ''
  ).trim();

  if (!refreshToken) {
    return res.status(400).json({
      error: 'Refresh Token مطلوب'
    });
  }

  try {
    const payload = jwt.verify(
      refreshToken,
      JWT_SECRET
    );

    if (
      !payload ||
      typeof payload !== 'object' ||
      typeof payload.code !== 'string' ||
      !payload.code
    ) {
      return res.status(401).json({
        error: 'Refresh Token غير صالح'
      });
    }

    if (
      payload.type !== 'refresh' &&
      payload.type != null
    ) {
      return res.status(401).json({
        error: 'Refresh Token غير صالح'
      });
    }

    const user = getUser(payload.code);

    if (!user) {
      return res.status(401).json({
        error: 'المستخدم غير موجود'
      });
    }

    return res.json({
      ok: true,
      accessToken: createAccessToken(user)
    });
  } catch {
    return res.status(401).json({
      error: 'Refresh Token غير صالح أو منتهي'
    });
  }
});

// --------------------------------------------------
// Registration
// --------------------------------------------------
app.post(
  ['/api/users/create', '/api/auth/register'],
  (req, res) => {
    try {
      const name = String(
        req.body?.displayName ||
        req.body?.display_name ||
        req.body?.name ||
        req.body?.username ||
        ''
      ).trim();

      const email = String(
        req.body?.email || ''
      ).trim();

      const password = String(
        req.body?.password || ''
      ).trim();

      const phone = String(
        req.body?.phone ||
        req.body?.phoneNumber ||
        ''
      ).trim();

      if (!name) {
        return res.status(400).json({
          error: 'اسم المستخدم مطلوب'
        });
      }

      const code = generateUserCode();
      const pinCode = generatePinCode();

      const result = db.prepare(`
        INSERT INTO users (
          code,
          pin_code,
          phone,
          name,
          email,
          password,
          created_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?)
      `).run(
        code,
        pinCode,
        phone || null,
        name,
        email || null,
        password || null,
        new Date().toISOString()
      );

      const user = {
        id: Number(result.lastInsertRowid),
        code,
        pin_code: pinCode,
        pinCode,
        phone: phone || null,
        name,
        email: email || null
      };

      const accessToken = createAccessToken(user);
      const refreshToken = createRefreshToken(user);

      return res.json({
        ok: true,
        pin_code: pinCode,
        pinCode,
        user,
        token: accessToken,
        accessToken,
        refreshToken
      });
    } catch (error) {
      console.error('Registration error:', error);

      return res.status(500).json({
        error: 'تعذر إنشاء الحساب',
        details: error.message
      });
    }
  }
);

// --------------------------------------------------
// Current User
// --------------------------------------------------
app.get('/api/users/me', auth, (req, res) => {
  const user = getUser(req.user.code);

  if (!user) {
    return res.status(404).json({
      error: 'المستخدم غير موجود'
    });
  }

  res.json({
    ok: true,
    user
  });
});

// --------------------------------------------------
// User By Code
// --------------------------------------------------
app.get('/api/users/:code', auth, (req, res) => {
  const code = String(
    req.params.code || ''
  ).trim();

  if (!WASAL_CODE_REGEX.test(code)) {
    return res.status(400).json({
      error: 'رمز وصال يجب أن يتكون من 15 حرفًا إنجليزيًا أو رقمًا'
    });
  }

  const user = getUser(code);

  if (!user) {
    return res.status(404).json({
      error: 'المستخدم غير موجود'
    });
  }

  res.json({
    ok: true,
    user
  });
});

// --------------------------------------------------
// Conversation Messages
// --------------------------------------------------
app.get(
  '/api/conversations/:code/messages',
  auth,
  (req, res) => {
    const otherCode = String(
      req.params.code || ''
    ).trim();

    if (!WASAL_CODE_REGEX.test(otherCode)) {
      return res.status(400).json({
        error: 'رمز وصال يجب أن يتكون من 15 حرفًا إنجليزيًا أو رقمًا'
      });
    }

    if (!userExists(otherCode)) {
      return res.status(404).json({
        error: 'المستخدم غير موجود'
      });
    }

    const messages = conversationMessages(
      req.user.code,
      otherCode
    );

    res.json({
      ok: true,
      messages
    });
  }
);

// --------------------------------------------------
// Conversations List
// --------------------------------------------------
const getConversationsHandler = (req, res) => {
  const rows = db.prepare(`
    SELECT
      CASE
        WHEN sender_code = ?
        THEN receiver_code
        ELSE sender_code
      END AS otherCode,
      MAX(id) AS lastMessageId
    FROM messages
    WHERE
      sender_code = ?
      OR receiver_code = ?
    GROUP BY otherCode
    ORDER BY lastMessageId DESC
  `).all(
    req.user.code,
    req.user.code,
    req.user.code
  );

  const chats = rows.map(row => {
    const user = getUser(row.otherCode);

    const lastMessage = db.prepare(`
      SELECT
        id,
        sender_code AS senderCode,
        receiver_code AS receiverCode,
        type,
        text,
        media_url AS mediaUrl,
        created_at AS createdAt
      FROM messages
      WHERE id = ?
    `).get(row.lastMessageId);

    return {
      user,
      lastMessage
    };
  });

  res.json(chats);
};

app.get('/api/chats', auth, getConversationsHandler);
app.get('/api/conversations', auth, getConversationsHandler);

// --------------------------------------------------
// Text Messages
// --------------------------------------------------
app.post('/api/messages', auth, (req, res) => {
  const receiverCode = String(
    req.body?.receiverCode || ''
  ).trim();

  const text = String(
    req.body?.text || ''
  ).trim();

  if (!WASAL_CODE_REGEX.test(receiverCode)) {
    return res.status(400).json({
      error: 'رمز وصال يجب أن يتكون من 15 حرفًا إنجليزيًا أو رقمًا'
    });
  }

  if (!text) {
    return res.status(400).json({
      error: 'نص الرسالة مطلوب'
    });
  }

  if (receiverCode === req.user.code) {
    return res.status(400).json({
      error: 'لا يمكن إرسال رسالة إلى نفسك'
    });
  }

  if (!userExists(receiverCode)) {
    return res.status(404).json({
      error: 'المستخدم غير موجود'
    });
  }

  const message = saveMessage({
    senderCode: req.user.code,
    receiverCode,
    type: 'text',
    text
  });

  io.to(`user:${receiverCode}`).emit(
    'message',
    message
  );

  res.json({
    ok: true,
    message
  });
});

// --------------------------------------------------
// Media Upload
// --------------------------------------------------
app.post(
  '/api/media/upload',
  auth,
  upload.single('file'),
  (req, res) => {
    if (!req.file) {
      return res.status(400).json({
        error: 'لم يتم إرسال ملف'
      });
    }

    const isVideo = req.file.mimetype.startsWith('video/');
    const type = isVideo ? 'video' : 'image';

    const url =
      `${req.protocol}://${req.get('host')}/media/${req.file.filename}`;

    res.json({
      ok: true,
      type,
      filename: req.file.filename,
      url
    });
  }
);

// --------------------------------------------------
// Media Messages
// --------------------------------------------------
app.post('/api/messages/media', auth, (req, res) => {
  const receiverCode = String(
    req.body?.receiverCode || ''
  ).trim();

  const type = String(
    req.body?.type || ''
  ).trim();

  const mediaUrl = String(
    req.body?.mediaUrl || ''
  ).trim();

  if (!WASAL_CODE_REGEX.test(receiverCode)) {
    return res.status(400).json({
      error: 'رمز وصال يجب أن يتكون من 15 حرفًا إنجليزيًا أو رقمًا'
    });
  }

  if (!['image', 'video'].includes(type)) {
    return res.status(400).json({
      error: 'نوع الوسائط غير صالح'
    });
  }

  if (!mediaUrl) {
    return res.status(400).json({
      error: 'رابط الوسائط مطلوب'
    });
  }

  if (!userExists(receiverCode)) {
    return res.status(404).json({
      error: 'المستخدم غير موجود'
    });
  }

  const message = saveMessage({
    senderCode: req.user.code,
    receiverCode,
    type,
    mediaUrl
  });

  io.to(`user:${receiverCode}`).emit(
    'message',
    message
  );

  res.json({
    ok: true,
    message
  });
});

// --------------------------------------------------
// Link Messages
// --------------------------------------------------
app.post('/api/messages/link', auth, (req, res) => {
  const receiverCode = String(
    req.body?.receiverCode || ''
  ).trim();

  const url = String(
    req.body?.url || ''
  ).trim();

  if (!WASAL_CODE_REGEX.test(receiverCode)) {
    return res.status(400).json({
      error: 'رمز وصال يجب أن يتكون من 15 حرفًا إنجليزيًا أو رقمًا'
    });
  }

  if (!/^https?:\/\/\S+$/i.test(url)) {
    return res.status(400).json({
      error: 'الرابط غير صالح'
    });
  }

  if (!userExists(receiverCode)) {
    return res.status(404).json({
      error: 'المستخدم غير موجود'
    });
  }

  const message = saveMessage({
    senderCode: req.user.code,
    receiverCode,
    type: 'link',
    text: url
  });

  io.to(`user:${receiverCode}`).emit(
    'message',
    message
  );

  res.json({
    ok: true,
    message
  });
});

// --------------------------------------------------
// Socket.io Authentication
// --------------------------------------------------
io.use((socket, next) => {
  const token = socket.handshake.auth?.token;

  if (!token) {
    return next(
      new Error('Authentication required')
    );
  }

  try {
    socket.user = verifyAccessToken(token);
    next();
  } catch {
    next(
      new Error('INVALID_OR_EXPIRED_TOKEN')
    );
  }
});

// --------------------------------------------------
// Socket.io Connection
// --------------------------------------------------
io.on('connection', socket => {
  const code = socket.user.code;

  socket.join(`user:${code}`);

  socket.on('send_message', (data, callback) => {
    try {
      const receiverCode = String(
        data?.receiverCode || ''
      ).trim();

      const type = String(
        data?.type || 'text'
      ).trim();

      const text =
        data?.text == null
          ? null
          : String(data.text).trim();

      const mediaUrl =
        data?.mediaUrl == null
          ? null
          : String(data.mediaUrl).trim();

      if (!WASAL_CODE_REGEX.test(receiverCode)) {
        throw new Error('رمز المستخدم غير صالح');
      }

      if (receiverCode === code) {
        throw new Error('لا يمكن الإرسال لنفسك');
      }

      if (!userExists(receiverCode)) {
        throw new Error('المستخدم غير موجود');
      }

      if (!['text', 'image', 'video', 'link'].includes(type)) {
        throw new Error('نوع الرسالة غير صالح');
      }

      if (type === 'text' && !text) {
        throw new Error('نص الرسالة مطلوب');
      }

      if (
        ['image', 'video'].includes(type) &&
        !mediaUrl
      ) {
        throw new Error('رابط الوسائط مطلوب');
      }

      const message = saveMessage({
        senderCode: code,
        receiverCode,
        type,
        text,
        mediaUrl
      });

      io.to(`user:${receiverCode}`).emit(
        'message',
        message
      );

      socket.emit('message_sent', message);

      if (typeof callback === 'function') {
        callback({
          ok: true,
          message
        });
      }
    } catch (error) {
      if (typeof callback === 'function') {
        callback({
          ok: false,
          error: error.message
        });
      }
    }
  });
});

// --------------------------------------------------
// Error Handler
// --------------------------------------------------
app.use((err, _, res, __) => {
  console.error('Server error:', err);

  if (
    err instanceof multer.MulterError &&
    err.code === 'LIMIT_FILE_SIZE'
  ) {
    return res.status(413).json({
      error: 'حجم الملف أكبر من الحد المسموح'
    });
  }

  res.status(400).json({
    error: err.message || 'حدث خطأ في الخادم'
  });
});

// --------------------------------------------------
// Start Server
// --------------------------------------------------
httpServer.listen(PORT, '0.0.0.0', () => {
  console.log(
    `Wasal server running on port ${PORT}`
  );
});
