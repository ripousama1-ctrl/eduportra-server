import express from 'express';
import cors from 'cors';
import morgan from 'morgan';
import fs from 'fs';
import path from 'path';
import mongoose from 'mongoose';

const app = express();
const PORT = process.env.PORT || 3000;
const MONGODB_URI = process.env.MONGODB_URI || '';

app.set('trust proxy', 1);
app.disable('x-powered-by');
const allowedOrigins = (process.env.ALLOWED_ORIGINS || '').split(',').map(s => s.trim()).filter(Boolean);
app.use(cors({
  origin: (origin, cb) => {
    if (!origin) return cb(null, true);
    if (allowedOrigins.length === 0 || allowedOrigins.includes(origin)) return cb(null, true);
    return cb(new Error('Not allowed by CORS'));
  },
  credentials: true,
}));
app.use(express.json({ limit: process.env.JSON_LIMIT || '200kb' }));
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('Strict-Transport-Security', 'max-age=15552000; includeSubDomains');
  next();
});
app.use(morgan(process.env.NODE_ENV === 'production' ? 'combined' : 'tiny'));

const dataDir = path.join(process.cwd(), 'data');
const examsFile = path.join(dataDir, 'exams.json');
const attendanceFile = path.join(dataDir, 'attendance.json');
const studentsFile = path.join(dataDir, 'students.json');
const examResultsFile = path.join(dataDir, 'exam_results.json');

function safeStr(v, maxLen = 200) {
  return String(v || '').replace(/[\r\n\t]/g, ' ').trim().slice(0, maxLen);
}

const RATE_LIMIT_WINDOW_MS = Number(process.env.RATE_LIMIT_WINDOW_MS || 60_000);
const RATE_LIMIT_MAX = Number(process.env.RATE_LIMIT_MAX || 180);
const rateStore = new Map();
function rateLimiter(req, res, next) {
  const now = Date.now();
  const ip = req.ip || req.connection.remoteAddress || 'unknown';
  let entry = rateStore.get(ip);
  if (!entry || now > entry.resetAt) {
    entry = { count: 0, resetAt: now + RATE_LIMIT_WINDOW_MS };
    rateStore.set(ip, entry);
  }
  entry.count += 1;
  if (entry.count > RATE_LIMIT_MAX) return res.status(429).json({ error: 'too_many_requests' });
  next();
}
app.use(rateLimiter);

const writeQueues = new Map();
function queueWrite(filePath, mutator) {
  const prev = writeQueues.get(filePath) || Promise.resolve();
  const next = prev.then(async () => {
    const buf = await fs.promises.readFile(filePath, 'utf-8');
    const json = JSON.parse(buf);
    const updated = await mutator(json);
    await fs.promises.writeFile(filePath, JSON.stringify(updated, null, 2));
  }).catch(() => {});
  writeQueues.set(filePath, next);
  return next;
}
function ensureDataFile() {
  if (!fs.existsSync(dataDir)) {
    fs.mkdirSync(dataDir, { recursive: true });
  }
  if (!fs.existsSync(examsFile)) {
    fs.writeFileSync(examsFile, JSON.stringify([]));
  }
  if (!fs.existsSync(attendanceFile)) {
    fs.writeFileSync(attendanceFile, JSON.stringify([]));
  }
  if (!fs.existsSync(studentsFile)) {
    fs.writeFileSync(studentsFile, JSON.stringify([]));
  }
  if (!fs.existsSync(examResultsFile)) {
    fs.writeFileSync(examResultsFile, JSON.stringify([]));
  }
}

ensureDataFile();

let dbConnected = false;
let ExamModel = null;

async function connectMongo() {
  if (!MONGODB_URI) return;
  try {
    await mongoose.connect(MONGODB_URI, { dbName: process.env.DB_NAME || 'collageapp' });
    const examSchema = new mongoose.Schema({
      subject: { type: String, required: true },
      department: { type: String, required: true },
      level: { type: String, required: true },
      tfCount: { type: Number, default: 0 },
      mcqCount: { type: Number, default: 0 },
      questions: { type: Array, default: [] },
      createdAt: { type: Date, default: Date.now },
    }, { timestamps: true });
    ExamModel = mongoose.model('Exam', examSchema);
    dbConnected = true;
    // connected
  } catch (e) {
    // connection failed
    dbConnected = false;
  }
}

await connectMongo();

app.get('/', (_, res) => {
  res.status(200).send('CollageApp Server');
});

app.get('/health/db', async (_, res) => {
  res.json({ state: dbConnected ? 1 : 0 });
});

app.get('/api/exams', async (_, res) => {
  try {
    if (dbConnected && ExamModel) {
      const items = await ExamModel.find().sort({ createdAt: -1 }).lean();
      res.json({ items: items.map(i => ({ ...i, id: i._id })) });
      return;
    }
    const buf = fs.readFileSync(examsFile, 'utf-8');
    const items = JSON.parse(buf);
    res.json({ items });
  } catch (e) {
    res.status(500).json({ error: 'fetch_failed', message: e.message });
  }
});

app.post('/api/exams', async (req, res) => {
  try {
    const { subject = '', department = '', level = '', tfCount = 0, mcqCount = 0, questions = [] } = req.body || {};
    const subjectS = safeStr(subject, 100);
    const departmentS = safeStr(department, 100);
    const levelS = safeStr(level, 100);
    if (!subjectS || !departmentS || !levelS) {
      res.status(400).json({ error: 'invalid_payload' });
      return;
    }
    if (dbConnected && ExamModel) {
      const doc = await ExamModel.create({ subject: subjectS, department: departmentS, level: levelS, tfCount, mcqCount, questions });
      res.json({ id: doc._id.toString() });
      return;
    }
    const id = Math.random().toString(36).slice(2);
    const createdAt = new Date().toISOString();
    await queueWrite(examsFile, (items) => {
      items.unshift({ id, subject: subjectS, department: departmentS, level: levelS, tfCount, mcqCount, questions, createdAt });
      return items;
    });
    res.json({ id });
  } catch (e) {
    res.status(500).json({ error: 'create_failed', message: e.message });
  }
});

app.get('/api/exams/:id', async (req, res) => {
  const { id } = req.params;
  try {
    if (dbConnected && ExamModel) {
      const doc = await ExamModel.findById(id).lean();
      if (!doc) return res.status(404).json({ error: 'not_found' });
      res.json({ exam: { ...doc, id: doc._id } });
      return;
    }
    const buf = fs.readFileSync(examsFile, 'utf-8');
    const items = JSON.parse(buf);
    const exam = items.find(i => (i.id || i._id) === id);
    if (!exam) return res.status(404).json({ error: 'not_found' });
    res.json({ exam });
  } catch (e) {
    res.status(500).json({ error: 'fetch_failed' });
  }
});
app.delete('/api/exams/:id', async (req, res) => {
  try {
    const { id } = req.params;
    if (dbConnected && ExamModel) {
      await ExamModel.findByIdAndDelete(id);
      res.json({ ok: true });
      return;
    }
    await queueWrite(examsFile, (items) => items.filter(i => (i.id || i._id) !== id));
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: 'delete_failed', message: e.message });
  }
});

app.get('/api/attendance/students-by-lecture', (req, res) => {
  const lectureId = String(req.query.lectureId || '').trim();
  if (!lectureId) return res.status(400).json({ error: 'invalid_input' });
  try {
    const buf = fs.readFileSync(attendanceFile, 'utf-8');
    const items = JSON.parse(buf);
    const students = items.filter(i => String(i.lectureId || '') === lectureId).map(i => ({
      studentName: String(i.studentName || ''),
      studentCode: String(i.studentCode || ''),
      department: String(i.department || ''),
      level: String(i.level || ''),
      status: String(i.status || ''),
      time: i.time || Date.now(),
    }));
    res.json({ students });
  } catch (e) {
    res.status(500).json({ error: 'db_error' });
  }
});

app.delete('/api/attendance/clear', (req, res) => {
  const lectureId = String(req.query.lectureId || '').trim();
  if (!lectureId) return res.status(400).json({ error: 'invalid_input' });
  try {
    queueWrite(attendanceFile, (items) => items.filter(i => String(i.lectureId || '') !== lectureId))
      .then(() => res.json({ ok: true }))
      .catch(() => res.status(500).json({ error: 'db_error' }));
    return;
  } catch (e) {
    res.status(500).json({ error: 'db_error' });
  }
});

app.delete('/api/attendance/student', (req, res) => {
  const lectureId = String(req.query.lectureId || '').trim();
  const studentCode = String(req.query.studentCode || '').trim();
  if (!lectureId || !studentCode) return res.status(400).json({ error: 'invalid_input' });
  try {
    queueWrite(attendanceFile, (items) => items.filter(i => !(String(i.lectureId || '') === lectureId && String(i.studentCode || '') === studentCode)))
      .then(() => res.json({ ok: true }))
      .catch(() => res.status(500).json({ error: 'db_error' }));
    return;
  } catch (e) {
    res.status(500).json({ error: 'db_error' });
  }
});

app.delete('/api/attendance/all', (req, res) => {
  try {
    queueWrite(attendanceFile, () => [])
      .then(() => res.json({ ok: true }))
      .catch(() => res.status(500).json({ error: 'db_error' }));
    return;
  } catch (e) {
    res.status(500).json({ error: 'db_error' });
  }
});

app.get('/api/students', (req, res) => {
  try {
    const department = String(req.query.department || '').trim();
    const level = String(req.query.level || '').trim();
    const buf = fs.readFileSync(studentsFile, 'utf-8');
    const items = JSON.parse(buf);
    const normalized = items.map(s => ({
      studentCode: String(s.studentCode || s.code || '').trim(),
      fullName: String(s.fullName || s.name || '').trim(),
      department: String(s.department || '').trim(),
      level: String(s.level || '').trim(),
      status: String(s.status || '').trim(),
    })).filter(s => s.studentCode && s.fullName);
    const filtered = normalized.filter(s => {
      const okDept = department ? s.department === department : true;
      const okLevel = level ? s.level === level : true;
      return okDept && okLevel;
    });
    res.json({ students: filtered });
  } catch (e) {
    res.status(500).json({ error: 'db_error' });
  }
});

app.post('/api/students', (req, res) => {
  try {
    const b = req.body || {};
    const studentCode = safeStr(b.studentCode || b.code, 64);
    const fullName = safeStr(b.fullName || b.name, 128);
    const department = safeStr(b.department, 64);
    const level = safeStr(b.level, 64);
    const status = safeStr(b.status, 64);
    if (!studentCode || !fullName) return res.status(400).json({ error: 'invalid_input' });
    queueWrite(studentsFile, (items) => {
      if (items.find(s => String(s.studentCode || s.code || '') === studentCode)) {
        return items;
      }
      items.push({ studentCode, fullName, department, level, status });
      return items;
    }).then(() => res.json({ ok: true })).catch(() => res.status(500).json({ error: 'db_error' }));
  } catch (e) {
    res.status(500).json({ error: 'db_error' });
  }
});

app.delete('/api/students/:code', (req, res) => {
  try {
    const code = safeStr(req.params.code, 64);
    if (!code) return res.status(400).json({ error: 'invalid_input' });
    queueWrite(studentsFile, (items) => items.filter(s => String(s.studentCode || s.code || '') !== code))
      .then(() => res.json({ ok: true }))
      .catch(() => res.status(500).json({ error: 'db_error' }));
    return;
  } catch (e) {
    res.status(500).json({ error: 'db_error' });
  }
});

app.post('/api/students/import-bulk', (req, res) => {
  try {
    const list = Array.isArray(req.body) ? req.body : [];
    queueWrite(studentsFile, (items) => {
      const byCode = new Map(items.map(s => [String(s.studentCode || s.code || ''), s]));
      for (const raw of list) {
        const studentCode = safeStr(raw.studentCode || raw.code, 64);
        const fullName = safeStr(raw.fullName || raw.name, 128);
        const department = safeStr(raw.department, 64);
        const level = safeStr(raw.level, 64);
        const status = safeStr(raw.status, 64);
        if (!studentCode || !fullName) continue;
        if (byCode.has(studentCode)) continue;
        items.push({ studentCode, fullName, department, level, status });
        byCode.set(studentCode, true);
      }
      return items;
    }).then(() => res.json({ ok: true, count: list.length })).catch(() => res.status(500).json({ error: 'db_error' }));
  } catch (e) {
    res.status(500).json({ error: 'db_error' });
  }
});

app.post('/api/exam-results', (req, res) => {
  try {
    const b = req.body || {};
    const studentCode = safeStr(b.studentCode, 64);
    const examId = safeStr(b.examId, 64);
    const department = safeStr(b.department, 64);
    const level = safeStr(b.level, 64);
    const correct = Number(b.correct || 0);
    const wrong = Number(b.wrong || 0);
    const total = Number(b.total || 0);
    const score = Number(b.score || 0);
    const submittedAt = String(b.submittedAt || new Date().toISOString());
    if (!studentCode || !examId) return res.status(400).json({ error: 'invalid_input' });
    queueWrite(examResultsFile, (items) => {
      items.push({ studentCode, examId, department, level, correct, wrong, total, score, submittedAt });
      return items;
    }).then(() => res.json({ ok: true })).catch(() => res.status(500).json({ error: 'db_error' }));
  } catch (e) {
    res.status(500).json({ error: 'db_error' });
  }
});

app.get('/api/exam-results/latest', (req, res) => {
  try {
    const studentCode = String(req.query.studentCode || '').trim();
    if (!studentCode) return res.status(400).json({ error: 'invalid_input' });
    const buf = fs.readFileSync(examResultsFile, 'utf-8');
    const items = JSON.parse(buf);
    const list = items.filter(i => String(i.studentCode || '') === studentCode);
    if (list.length === 0) return res.json({ result: null });
    const latest = list.sort((a, b) => new Date(String(b.submittedAt || '')).getTime() - new Date(String(a.submittedAt || '')).getTime())[0];
    res.json({ result: latest });
  } catch (e) {
    res.status(500).json({ error: 'db_error' });
  }
});

app.post('/api/auth/login', (req, res) => {
  try {
    const b = req.body || {};
    const studentCode = String(b.studentCode || '').trim().toLowerCase();
    const username = String(b.username || '').trim();
    const password = String(b.password || '').trim();
    if (studentCode) {
      const buf = fs.readFileSync(studentsFile, 'utf-8');
      const items = JSON.parse(buf);
      const s = items.find(it => String(it.studentCode || it.code || '').trim().toLowerCase() === studentCode);
    if (!s) {
      if (Array.isArray(items) && items.length === 0) {
        return res.json({
          user: {
            role: 'student',
            studentCode: studentCode,
            fullName: 'طالب',
            department: '',
            level: '',
          }
        });
      }
      return res.status(401).json({ error: 'invalid_credentials' });
    }
      return res.json({
        user: {
          role: 'student',
          studentCode: String(s.studentCode || s.code || ''),
          fullName: String(s.fullName || s.name || ''),
          department: String(s.department || ''),
          level: String(s.level || ''),
        }
      });
    }
    if (username && password) {
      if (username === 'admin' && password === 'admin') {
        return res.json({ user: { role: 'admin', id: 'admin' } });
      }
      return res.status(401).json({ error: 'invalid_credentials' });
    }
    res.status(400).json({ error: 'invalid_payload' });
  } catch (e) {
    res.status(500).json({ error: 'auth_error' });
  }
});

app.post('/mark-attendance', (req, res) => {
  try {
    const b = req.body || {};
    const lectureId = safeStr(b.lectureId, 64);
    const timestamp = Number(b.timestamp || Date.now());
    const studentCode = safeStr(b.studentId || b.studentCode, 64);
    const studentName = safeStr(b.name || b.studentName, 128);
    const department = safeStr(b.department, 64);
    const level = safeStr(b.level, 64);
    const status = safeStr(b.status, 64);
    if (!lectureId || !studentCode || !studentName) {
      return res.status(400).json({ error: 'invalid_input' });
    }
    queueWrite(attendanceFile, (items) => {
      items.push({
        lectureId,
        time: timestamp,
        studentCode,
        studentName,
        department,
        level,
        status,
      });
      return items;
    }).then(() => res.json({ ok: true })).catch(() => res.status(500).json({ error: 'db_error' }));
  } catch (e) {
    res.status(500).json({ error: 'db_error' });
  }
});

const server = app.listen(PORT, () => {});
server.setTimeout(Number(process.env.REQUEST_TIMEOUT_MS || 30000));
