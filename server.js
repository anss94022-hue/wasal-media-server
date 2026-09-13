import 'dotenv/config';
import express from 'express';
import cors from 'cors';
import jwt from 'jsonwebtoken';
import multer from 'multer';
import fs from 'fs';
import path from 'path';

const PORT = process.env.PORT || 3000;

const JWT_SECRET =
  process.env.JWT_SECRET || 'CHANGE_ME_IN_PRODUCTION';

const app = express();

app.use(cors());
app.use(express.json({ limit: '2mb' }));

// Media storage directory
const MEDIA_DIR = './media';

fs.mkdirSync(MEDIA_DIR, { recursive: true });

// Serve uploaded media
app.use('/media', express.static(MEDIA_DIR));

// File storage
const storage = multer.diskStorage({
  destination: (_, __, cb) => {
    cb(null, MEDIA_DIR);
  },

  filename: (_, file, cb) => {
    const ext = path.extname(file.originalname).toLowerCase();

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

// Authentication
function auth(req, res, next) {
  try {
    const token = (req.headers.authorization || '')
      .replace(/^Bearer\s+/i, '');

    req.user = jwt.verify(token, JWT_SECRET);

    next();
  } catch {
    res.status(401).json({
      error: 'رمز الدخول غير صالح أو منتهي'
    });
  }
}

// Health check
app.get('/health', (_, res) => {
  res.json({
    ok: true,
    service: 'wasal-media-server',
    time: new Date().toISOString()
  });
});

// Upload image
app.post(
  '/api/media/upload/image',
  auth,
  upload.single('file'),
  (req, res) => {
    if (!req.file) {
      return res.status(400).json({
        error: 'لم يتم إرسال صورة'
      });
    }

    const url =
      `${req.protocol}://${req.get('host')}/media/${req.file.filename}`;

    res.json({
      ok: true,
      type: 'image',
      filename: req.file.filename,
      url
    });
  }
);

// Upload video
app.post(
  '/api/media/upload/video',
  auth,
  upload.single('file'),
  (req, res) => {
    if (!req.file) {
      return res.status(400).json({
        error: 'لم يتم إرسال فيديو'
      });
    }

    const url =
      `${req.protocol}://${req.get('host')}/media/${req.file.filename}`;

    res.json({
      ok: true,
      type: 'video',
      filename: req.file.filename,
      url
    });
  }
);

// General media upload
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

    const isVideo =
      req.file.mimetype.startsWith('video/');

    const url =
      `${req.protocol}://${req.get('host')}/media/${req.file.filename}`;

    res.json({
      ok: true,
      type: isVideo ? 'video' : 'image',
      filename: req.file.filename,
      url
    });
  }
);

// Error handling
app.use((err, _, res, __) => {
  if (err instanceof multer.MulterError) {
    if (err.code === 'LIMIT_FILE_SIZE') {
      return res.status(413).json({
        error: 'حجم الملف أكبر من الحد المسموح'
      });
    }
  }

  res.status(400).json({
    error: err.message || 'حدث خطأ أثناء رفع الملف'
  });
});

app.get('/', (_, res) => {
  res.json({
    ok: true,
    service: 'wasal-media-server'
  });
});

app.listen(PORT, '0.0.0.0', () => {
  console.log(
    `Wasal media server running on port ${PORT}`
  );
});
