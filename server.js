import 'dotenv/config';
import express from 'express';
import cors from 'cors';
import jwt from 'jsonwebtoken';
import multer from 'multer';
import fs from 'fs';
import path from 'path';
import { createServer } from 'http';
import { Server } from 'socket.io';
import Database from 'better-sqlite3';

const PORT = Number(process.env.PORT || 3000);

const JWT_SECRET =
  process.env.JWT_SECRET || 'WASAL_CHANGE_THIS_SECRET';

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
    name TEXT NOT NULL,
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
// Media
// --------------------------------------------------

app.use(
  '/media',
  express.static(MEDIA_DIR)
);

const storage = multer.diskStorage({
  destination: (_, __, cb) => {
    cb(null, MEDIA_DIR);
  },

  filename: (_, file, cb) => {
    const ext = path
      .extname(file.originalname)
      .toLowerCase();

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
      cb(
        new Error('نوع الملف غير مسموح')
      );
    }
  }
});

// --------------------------------------------------
// Helpers
// --------------------------------------------------

function generateUserCode() {
  for (;;) {
    const code = String(
      Math.floor(
        10000 + Math.random() * 90000
      )
    );

    const exists = db
      .prepare(
        'SELECT id FROM users WHERE code = ?'
      )
      .get(code);

    if (!exists) {
      return code;
    }
  }
}

function createToken(user) {
  return jwt.sign(
    {
      code: user.code,
      name: user.name
    },
    JWT_SECRET,
    {
      expiresIn: '365d'
    }
  );
}

function auth(req, res, next) {
  try {
    const token =
      (req.headers.authorization || '')
        .replace(
          /^Bearer\s+/i,
          ''
        );

    const user =
      jwt.verify(
        token,
        JWT_SECRET
      );

    req.user = user;

    next();
  } catch {
    res.status(401).json({
      error:
        'رمز الدخول غير صالح أو منتهي'
    });
  }
}

function getUser(code) {
  return db
    .prepare(
      `
      SELECT
        code,
        name,
        created_at AS createdAt
      FROM users
      WHERE code = ?
      `
    )
    .get(code);
}

function userExists(code) {
  return Boolean(
    db
      .prepare(
        'SELECT id FROM users WHERE code = ?'
      )
      .get(code)
  );
}

function conversationMessages(
  a,
  b
) {
  return db
    .prepare(
      `
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
      `
    )
    .all(a, b, b, a);
}

function saveMessage({
  senderCode,
  receiverCode,
  type,
  text = null,
  mediaUrl = null
}) {
  const createdAt =
    new Date().toISOString();

  const result = db
    .prepare(
      `
      INSERT INTO messages
      (
        sender_code,
        receiver_code,
        type,
        text,
        media_url,
        created_at
      )
      VALUES (?, ?, ?, ?, ?, ?)
      `
    )
    .run(
      senderCode,
      receiverCode,
      type,
      text,
      mediaUrl,
      createdAt
    );

  return {
    id: Number(
      result.lastInsertRowid
    ),
    senderCode,
    receiverCode,
    type,
    text,
    mediaUrl,
    createdAt
  };
}

function removeExpiredStatuses() {
  const now =
    new Date().toISOString();

  db.prepare(
    'DELETE FROM statuses WHERE expires_at <= ?'
  ).run(now);
}

// --------------------------------------------------
// Health
// --------------------------------------------------

app.get(
  '/health',
  (_, res) => {
    res.json({
      ok: true,
      service: 'wasal-server',
      version: '3.0.0',
      features: [
        'text',
        'images',
        'videos',
        'links',
        'realtime-messaging',
        'voice-calls',
        'video-calls',
        'statuses'
      ],
      time:
        new Date().toISOString()
    });
  }
);

// --------------------------------------------------
// Root
// --------------------------------------------------

app.get(
  '/',
  (_, res) => {
    res.json({
      ok: true,
      service: 'wasal-server',
      version: '3.0.0'
    });
  }
);

// --------------------------------------------------
// Users
// --------------------------------------------------

app.post(
  '/api/users/create',
  (req, res) => {
    const name =
      String(
        req.body?.name || ''
      ).trim();

    if (!name) {
      return res.status(400).json({
        error:
          'اسم المستخدم مطلوب'
      });
    }

    if (name.length > 50) {
      return res.status(400).json({
        error:
          'اسم المستخدم طويل جدًا'
      });
    }

    const code =
      generateUserCode();

    db.prepare(
      `
      INSERT INTO users
      (code, name, created_at)
      VALUES (?, ?, ?)
      `
    ).run(
      code,
      name,
      new Date().toISOString()
    );

    const user = {
      code,
      name
    };

    res.json({
      ok: true,
      user,
      token:
        createToken(user)
    });
  }
);

app.get(
  '/api/users/:code',
  auth,
  (req, res) => {
    const user =
      getUser(
        req.params.code
      );

    if (!user) {
      return res.status(404).json({
        error:
          'المستخدم غير موجود'
      });
    }

    res.json({
      ok: true,
      user
    });
  }
);

// --------------------------------------------------
// Conversations
// --------------------------------------------------

app.get(
  '/api/conversations/:code/messages',
  auth,
  (req, res) => {
    const otherCode =
      String(
        req.params.code
      );

    if (!userExists(otherCode)) {
      return res.status(404).json({
        error:
          'المستخدم غير موجود'
      });
    }

    const messages =
      conversationMessages(
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
// Conversation list
// --------------------------------------------------

app.get(
  '/api/conversations',
  auth,
  (req, res) => {
    const rows = db
      .prepare(
        `
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
        `
      )
      .all(
        req.user.code,
        req.user.code,
        req.user.code
      );

    const conversations =
      rows.map(row => {
        const user =
          getUser(
            row.otherCode
          );

        const lastMessage =
          db
            .prepare(
              `
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
              `
            )
            .get(
              row.lastMessageId
            );

        return {
          user,
          lastMessage
        };
      });

    res.json({
      ok: true,
      conversations
    });
  }
);

// --------------------------------------------------
// Text messages
// --------------------------------------------------

app.post(
  '/api/messages',
  auth,
  (req, res) => {
    const receiverCode =
      String(
        req.body?.receiverCode || ''
      ).trim();

    const text =
      String(
        req.body?.text || ''
      ).trim();

    if (
      !/^\d{5}$/.test(
        receiverCode
      )
    ) {
      return res.status(400).json({
        error:
          'رمز المستخدم يجب أن يتكون من 5 أرقام'
      });
    }

    if (!text) {
      return res.status(400).json({
        error:
          'نص الرسالة مطلوب'
      });
    }

    if (
      receiverCode ===
      req.user.code
    ) {
      return res.status(400).json({
        error:
          'لا يمكن إرسال رسالة إلى نفسك'
      });
    }

    if (
      !userExists(receiverCode)
    ) {
      return res.status(404).json({
        error:
          'المستخدم غير موجود'
      });
    }

    const message =
      saveMessage({
        senderCode:
          req.user.code,
        receiverCode,
        type: 'text',
        text
      });

    io.to(
      `user:${receiverCode}`
    ).emit(
      'message',
      message
    );

    res.json({
      ok: true,
      message
    });
  }
);

// --------------------------------------------------
// Media upload
// --------------------------------------------------

app.post(
  '/api/media/upload',
  auth,
  upload.single('file'),
  (req, res) => {
    if (!req.file) {
      return res.status(400).json({
        error:
          'لم يتم إرسال ملف'
      });
    }

    const isVideo =
      req.file.mimetype.startsWith(
        'video/'
      );

    const type =
      isVideo
        ? 'video'
        : 'image';

    const url =
      `${req.protocol}://${req.get(
        'host'
      )}/media/${req.file.filename}`;

    res.json({
      ok: true,
      type,
      filename:
        req.file.filename,
      url
    });
  }
);

// --------------------------------------------------
// Media messages
// --------------------------------------------------

app.post(
  '/api/messages/media',
  auth,
  (req, res) => {
    const receiverCode =
      String(
        req.body?.receiverCode || ''
      ).trim();

    const type =
      String(
        req.body?.type || ''
      ).trim();

    const mediaUrl =
      String(
        req.body?.mediaUrl || ''
      ).trim();

    if (
      !/^\d{5}$/.test(
        receiverCode
      )
    ) {
      return res.status(400).json({
        error:
          'رمز المستخدم يجب أن يتكون من 5 أرقام'
      });
    }

    if (
      !['image', 'video']
        .includes(type)
    ) {
      return res.status(400).json({
        error:
          'نوع الوسائط غير صالح'
      });
    }

    if (!mediaUrl) {
      return res.status(400).json({
        error:
          'رابط الوسائط مطلوب'
      });
    }

    if (
      !userExists(receiverCode)
    ) {
      return res.status(404).json({
        error:
          'المستخدم غير موجود'
      });
    }

    const message =
      saveMessage({
        senderCode:
          req.user.code,
        receiverCode,
        type,
        mediaUrl
      });

    io.to(
      `user:${receiverCode}`
    ).emit(
      'message',
      message
    );

    res.json({
      ok: true,
      message
    });
  }
);

// --------------------------------------------------
// Link messages
// --------------------------------------------------

app.post(
  '/api/messages/link',
  auth,
  (req, res) => {
    const receiverCode =
      String(
        req.body?.receiverCode || ''
      ).trim();

    const url =
      String(
        req.body?.url || ''
      ).trim();

    if (
      !/^\d{5}$/.test(
        receiverCode
      )
    ) {
      return res.status(400).json({
        error:
          'رمز المستخدم يجب أن يتكون من 5 أرقام'
      });
    }

    if (
      !/^https?:\/\/\S+$/i.test(
        url
      )
    ) {
      return res.status(400).json({
        error:
          'الرابط غير صالح'
      });
    }

    if (
      !userExists(receiverCode)
    ) {
      return res.status(404).json({
        error:
          'المستخدم غير موجود'
      });
    }

    const message =
      saveMessage({
        senderCode:
          req.user.code,
        receiverCode,
        type: 'link',
        text: url
      });

    io.to(
      `user:${receiverCode}`
    ).emit(
      'message',
      message
    );

    res.json({
      ok: true,
      message
    });
  }
);

// ==================================================
// STATUS / STORIES
// ==================================================

// إنشاء حالة نصية
app.post(
  '/api/statuses',
  auth,
  (req, res) => {
    removeExpiredStatuses();

    const type =
      String(
        req.body?.type || 'text'
      ).trim();

    const text =
      req.body?.text == null
        ? null
        : String(
            req.body.text
          ).trim();

    const mediaUrl =
      req.body?.mediaUrl == null
        ? null
        : String(
            req.body.mediaUrl
          ).trim();

    if (
      !['text', 'image', 'video']
        .includes(type)
    ) {
      return res.status(400).json({
        error:
          'نوع الحالة غير صالح'
      });
    }

    if (
      type === 'text' &&
      !text
    ) {
      return res.status(400).json({
        error:
          'نص الحالة مطلوب'
      });
    }

    if (
      ['image', 'video']
        .includes(type) &&
      !mediaUrl
    ) {
      return res.status(400).json({
        error:
          'رابط الوسائط مطلوب'
      });
    }

    const createdAt =
      new Date();

    const expiresAt =
      new Date(
        createdAt.getTime() +
        24 * 60 * 60 * 1000
      );

    const result =
      db.prepare(
        `
        INSERT INTO statuses
        (
          user_code,
          type,
          text,
          media_url,
          created_at,
          expires_at
        )
        VALUES (?, ?, ?, ?, ?, ?)
        `
      ).run(
        req.user.code,
        type,
        text,
        mediaUrl,
        createdAt.toISOString(),
        expiresAt.toISOString()
      );

    const status =
      db.prepare(
        `
        SELECT
          id,
          user_code AS userCode,
          type,
          text,
          media_url AS mediaUrl,
          created_at AS createdAt,
          expires_at AS expiresAt
        FROM statuses
        WHERE id = ?
        `
      ).get(
        result.lastInsertRowid
      );

    io.emit(
      'status_created',
      status
    );

    res.json({
      ok: true,
      status
    });
  }
);

// الحالات الخاصة بمستخدم
app.get(
  '/api/statuses/:code',
  auth,
  (req, res) => {
    removeExpiredStatuses();

    const code =
      String(
        req.params.code
      );

    if (!userExists(code)) {
      return res.status(404).json({
        error:
          'المستخدم غير موجود'
      });
    }

    const statuses =
      db.prepare(
        `
        SELECT
          id,
          user_code AS userCode,
          type,
          text,
          media_url AS mediaUrl,
          created_at AS createdAt,
          expires_at AS expiresAt
        FROM statuses
        WHERE
          user_code = ?
          AND expires_at > ?
        ORDER BY id ASC
        `
      ).all(
        code,
        new Date().toISOString()
      );

    res.json({
      ok: true,
      statuses
    });
  }
);

// جميع الحالات النشطة
app.get(
  '/api/statuses',
  auth,
  (req, res) => {
    removeExpiredStatuses();

    const statuses =
      db.prepare(
        `
        SELECT
          s.id,
          s.user_code AS userCode,
          u.name AS userName,
          s.type,
          s.text,
          s.media_url AS mediaUrl,
          s.created_at AS createdAt,
          s.expires_at AS expiresAt
        FROM statuses s
        JOIN users u
          ON u.code = s.user_code
        WHERE
          s.expires_at > ?
        ORDER BY s.id DESC
        `
      ).all(
        new Date().toISOString()
      );

    res.json({
      ok: true,
      statuses
    });
  }
);

// تسجيل مشاهدة حالة
app.post(
  '/api/statuses/:id/view',
  auth,
  (req, res) => {
    removeExpiredStatuses();

    const statusId =
      Number(
        req.params.id
      );

    const status =
      db.prepare(
        `
        SELECT
          id,
          user_code AS userCode
        FROM statuses
        WHERE id = ?
        `
      ).get(statusId);

    if (!status) {
      return res.status(404).json({
        error:
          'الحالة غير موجودة'
      });
    }

    db.prepare(
      `
      INSERT OR IGNORE INTO status_views
      (
        status_id,
        viewer_code,
        viewed_at
      )
      VALUES (?, ?, ?)
      `
    ).run(
      statusId,
      req.user.code,
      new Date().toISOString()
    );

    res.json({
      ok: true
    });
  }
);

// حذف حالة
app.delete(
  '/api/statuses/:id',
  auth,
  (req, res) => {
    const statusId =
      Number(
        req.params.id
      );

    const result =
      db.prepare(
        `
        DELETE FROM statuses
        WHERE
          id = ?
          AND user_code = ?
        `
      ).run(
        statusId,
        req.user.code
      );

    if (
      result.changes === 0
    ) {
      return res.status(404).json({
        error:
          'الحالة غير موجودة'
      });
    }

    res.json({
      ok: true
    });
  }
);

// ==================================================
// SOCKET.IO
// ==================================================

io.use(
  (socket, next) => {
    try {
      const token =
        socket.handshake.auth?.token;

      if (!token) {
        return next(
          new Error(
            'Authentication required'
          )
        );
      }

      socket.user =
        jwt.verify(
          token,
          JWT_SECRET
        );

      next();
    } catch {
      next(
        new Error(
          'Invalid authentication'
        )
      );
    }
  }
);

io.on(
  'connection',
  (socket) => {
    const code =
      socket.user.code;

    socket.join(
      `user:${code}`
    );

    // ----------------------------------------------
    // Text / media / link messaging
    // ----------------------------------------------

    socket.on(
      'send_message',
      (data, callback) => {
        try {
          const receiverCode =
            String(
              data?.receiverCode || ''
            ).trim();

          const type =
            String(
              data?.type || 'text'
            ).trim();

          const text =
            data?.text == null
              ? null
              : String(
                  data.text
                ).trim();

          const mediaUrl =
            data?.mediaUrl == null
              ? null
              : String(
                  data.mediaUrl
                ).trim();

          if (
            !/^\d{5}$/.test(
              receiverCode
            )
          ) {
            throw new Error(
              'رمز المستخدم يجب أن يتكون من 5 أرقام'
            );
          }

          if (
            receiverCode === code
          ) {
            throw new Error(
              'لا يمكن إرسال رسالة إلى نفسك'
            );
          }

          if (
            !userExists(
              receiverCode
            )
          ) {
            throw new Error(
              'المستخدم غير موجود'
            );
          }

          if (
            ![
              'text',
              'image',
              'video',
              'link'
            ].includes(type)
          ) {
            throw new Error(
              'نوع الرسالة غير صالح'
            );
          }

          if (
            type === 'text' &&
            !text
          ) {
            throw new Error(
              'نص الرسالة مطلوب'
            );
          }

          if (
            ['image', 'video']
              .includes(type) &&
            !mediaUrl
          ) {
            throw new Error(
              'رابط الوسائط مطلوب'
            );
          }

          if (
            type === 'link' &&
            !text &&
            !mediaUrl
          ) {
            throw new Error(
              'الرابط مطلوب'
            );
          }

          const message =
            saveMessage({
              senderCode: code,
              receiverCode,
              type,
              text,
              mediaUrl
            });

          io.to(
            `user:${receiverCode}`
          ).emit(
            'message',
            message
          );

          socket.emit(
            'message_sent',
            message
          );

          if (
            typeof callback ===
            'function'
          ) {
            callback({
              ok: true,
              message
            });
          }
        } catch (error) {
          if (
            typeof callback ===
            'function'
          ) {
            callback({
              ok: false,
              error:
                error.message
            });
          }
        }
      }
    );

    // ==================================================
    // WEBRTC CALL SIGNALING
    // ==================================================

    // بدء مكالمة
    socket.on(
      'call_start',
      (data, callback) => {
        try {
          const receiverCode =
            String(
              data?.receiverCode || ''
            ).trim();

          const callId =
            String(
              data?.callId || ''
            ).trim();

          const callType =
            String(
              data?.callType || 'audio'
            ).trim();

          if (
            !/^\d{5}$/.test(
              receiverCode
            )
          ) {
            throw new Error(
              'رمز المستخدم غير صالح'
            );
          }

          if (
            receiverCode === code
          ) {
            throw new Error(
              'لا يمكن الاتصال بنفسك'
            );
          }

          if (
            !userExists(
              receiverCode
            )
          ) {
            throw new Error(
              'المستخدم غير موجود'
            );
          }

          if (
            !['audio', 'video']
              .includes(callType)
          ) {
            throw new Error(
              'نوع المكالمة غير صالح'
            );
          }

          const payload = {
            callId,
            callerCode: code,
            callerName:
              socket.user.name,
            receiverCode,
            callType,
            createdAt:
              new Date().toISOString()
          };

          io.to(
            `user:${receiverCode}`
          ).emit(
            'incoming_call',
            payload
          );

          if (
            typeof callback ===
            'function'
          ) {
            callback({
              ok: true,
              call: payload
            });
          }
        } catch (error) {
          if (
            typeof callback ===
            'function'
          ) {
            callback({
              ok: false,
              error:
                error.message
            });
          }
        }
      }
    );

    // قبول المكالمة
    socket.on(
      'call_accept',
      (data) => {
        const callerCode =
          String(
            data?.callerCode || ''
          ).trim();

        if (
          !/^\d{5}$/.test(
            callerCode
          )
        ) {
          return;
        }

        io.to(
          `user:${callerCode}`
        ).emit(
          'call_accepted',
          {
            callId:
              data?.callId || '',
            receiverCode:
              code,
            receiverName:
              socket.user.name
          }
        );
      }
    );

    // رفض المكالمة
    socket.on(
      'call_reject',
      (data) => {
        const callerCode =
          String(
            data?.callerCode || ''
          ).trim();

        if (
          !/^\d{5}$/.test(
            callerCode
          )
        ) {
          return;
        }

        io.to(
          `user:${callerCode}`
        ).emit(
          'call_rejected',
          {
            callId:
              data?.callId || '',
            receiverCode:
              code
          }
        );
      }
    );

    // إنهاء المكالمة
    socket.on(
      'call_end',
      (data) => {
        const otherCode =
          String(
            data?.otherCode || ''
          ).trim();

        if (
          !/^\d{5}$/.test(
            otherCode
          )
        ) {
          return;
        }

        io.to(
          `user:${otherCode}`
        ).emit(
          'call_ended',
          {
            callId:
              data?.callId || '',
            fromCode:
              code
          }
        );
      }
    );

    // --------------------------------------------------
    // WebRTC Offer
    // --------------------------------------------------

    socket.on(
      'webrtc_offer',
      (data) => {
        const receiverCode =
          String(
            data?.receiverCode || ''
          ).trim();

        if (
          !/^\d{5}$/.test(
            receiverCode
          )
        ) {
          return;
        }

        io.to(
          `user:${receiverCode}`
        ).emit(
          'webrtc_offer',
          {
            callId:
              data?.callId || '',
            senderCode:
              code,
            offer:
              data?.offer || null
          }
        );
      }
    );

    // --------------------------------------------------
    // WebRTC Answer
    // --------------------------------------------------

    socket.on(
      'webrtc_answer',
      (data) => {
        const receiverCode =
          String(
            data?.receiverCode || ''
          ).trim();

        if (
          !/^\d{5}$/.test(
            receiverCode
          )
        ) {
          return;
        }

        io.to(
          `user:${receiverCode}`
        ).emit(
          'webrtc_answer',
          {
            callId:
              data?.callId || '',
            senderCode:
              code,
            answer:
              data?.answer || null
          }
        );
      }
    );

    // --------------------------------------------------
    // WebRTC ICE Candidate
    // --------------------------------------------------

    socket.on(
      'webrtc_ice_candidate',
      (data) => {
        const receiverCode =
          String(
            data?.receiverCode || ''
          ).trim();

        if (
          !/^\d{5}$/.test(
            receiverCode
          )
        ) {
          return;
        }

        io.to(
          `user:${receiverCode}`
        ).emit(
          'webrtc_ice_candidate',
          {
            callId:
              data?.callId || '',
            senderCode:
              code,
            candidate:
              data?.candidate || null
          }
        );
      }
    );

    // --------------------------------------------------
    // Call busy
    // --------------------------------------------------

    socket.on(
      'call_busy',
      (data) => {
        const callerCode =
          String(
            data?.callerCode || ''
          ).trim();

        if (
          !/^\d{5}$/.test(
            callerCode
          )
        ) {
          return;
        }

        io.to(
          `user:${callerCode}`
        ).emit(
          'call_busy',
          {
            callId:
              data?.callId || '',
            receiverCode:
              code
          }
        );
      }
    );

    // --------------------------------------------------
    // Call ringing
    // --------------------------------------------------

    socket.on(
      'call_ringing',
      (data) => {
        const callerCode =
          String(
            data?.callerCode || ''
          ).trim();

        if (
          !/^\d{5}$/.test(
            callerCode
          )
        ) {
          return;
        }

        io.to(
          `user:${callerCode}`
        ).emit(
          'call_ringing',
          {
            callId:
              data?.callId || '',
            receiverCode:
              code
          }
        );
      }
    );

    // --------------------------------------------------
    // Status realtime notification
    // --------------------------------------------------

    socket.on(
      'status_refresh',
      () => {
        io.emit(
          'status_refresh'
        );
      }
    );
  }
);

// ==================================================
// Cleanup expired statuses
// ==================================================

setInterval(
  () => {
    try {
      removeExpiredStatuses();
    } catch (error) {
      console.error(
        'Status cleanup error:',
        error.message
      );
    }
  },
  60 * 60 * 1000
);

// ==================================================
// Error handling
// ==================================================

app.use(
  (err, _, res, __) => {
    if (
      err instanceof
      multer.MulterError
    ) {
      if (
        err.code ===
        'LIMIT_FILE_SIZE'
      ) {
        return res.status(413).json({
          error:
            'حجم الملف أكبر من الحد المسموح'
        });
      }
    }

    res.status(400).json({
      error:
        err.message ||
        'حدث خطأ في الخادم'
    });
  }
);

// ==================================================
// Start
// ==================================================

httpServer.listen(
  PORT,
  '0.0.0.0',
  () => {
    console.log(
      `Wasal server running on port ${PORT}`
    );
  }
);
