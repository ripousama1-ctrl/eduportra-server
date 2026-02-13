import express from 'express';
import cors from 'cors';
import morgan from 'morgan';
import fs from 'fs';
import path from 'path';
import mongoose from 'mongoose';

const app = express();
const PORT = process.env.PORT || 3000;
const MONGODB_URI = process.env.MONGODB_URI || '';

app.use(cors());
app.use(express.json());
app.use(morgan(process.env.NODE_ENV === 'production' ? 'combined' : 'tiny'));

const dataDir = path.join(process.cwd(), 'data');
const examsFile = path.join(dataDir, 'exams.json');
const attendanceFile = path.join(dataDir, 'attendance.json');
const studentsFile = path.join(dataDir, 'students.json');
const examResultsFile = path.join(dataDir, 'exam_results.json');

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
    if (!subject || !department || !level) {
      res.status(400).json({ error: 'invalid_payload' });
      return;
    }
    if (dbConnected && ExamModel) {
      const doc = await ExamModel.create({ subject, department, level, tfCount, mcqCount, questions });
      res.json({ id: doc._id.toString() });
      return;
    }
    const buf = fs.readFileSync(examsFile, 'utf-8');
    const items = JSON.parse(buf);
    const id = Math.random().toString(36).slice(2);
    const createdAt = new Date().toISOString();
    items.unshift({ id, subject, department, level, tfCount, mcqCount, questions, createdAt });
    fs.writeFileSync(examsFile, JSON.stringify(items, null, 2));
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
    const buf = fs.readFileSync(examsFile, 'utf-8');
    const items = JSON.parse(buf);
    const next = items.filter(i => (i.id || i._id) !== id);
    fs.writeFileSync(examsFile, JSON.stringify(next, null, 2));
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
    const buf = fs.readFileSync(attendanceFile, 'utf-8');
    const items = JSON.parse(buf);
    const next = items.filter(i => String(i.lectureId || '') !== lectureId);
    fs.writeFileSync(attendanceFile, JSON.stringify(next, null, 2));
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: 'db_error' });
  }
});

app.delete('/api/attendance/student', (req, res) => {
  const lectureId = String(req.query.lectureId || '').trim();
  const studentCode = String(req.query.studentCode || '').trim();
  if (!lectureId || !studentCode) return res.status(400).json({ error: 'invalid_input' });
  try {
    const buf = fs.readFileSync(attendanceFile, 'utf-8');
    const items = JSON.parse(buf);
    const next = items.filter(i => !(String(i.lectureId || '') === lectureId && String(i.studentCode || '') === studentCode));
    fs.writeFileSync(attendanceFile, JSON.stringify(next, null, 2));
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: 'db_error' });
  }
});

app.delete('/api/attendance/all', (req, res) => {
  try {
    fs.writeFileSync(attendanceFile, JSON.stringify([]));
    res.json({ ok: true });
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
    const studentCode = String(b.studentCode || b.code || '').trim();
    const fullName = String(b.fullName || b.name || '').trim();
    const department = String(b.department || '').trim();
    const level = String(b.level || '').trim();
    const status = String(b.status || '').trim();
    if (!studentCode || !fullName) return res.status(400).json({ error: 'invalid_input' });
    const buf = fs.readFileSync(studentsFile, 'utf-8');
    const items = JSON.parse(buf);
    if (items.find(s => String(s.studentCode || s.code || '') === studentCode)) {
      return res.json({ ok: true, duplicated: true });
    }
    items.push({ studentCode, fullName, department, level, status });
    fs.writeFileSync(studentsFile, JSON.stringify(items, null, 2));
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: 'db_error' });
  }
});

app.delete('/api/students/:code', (req, res) => {
  try {
    const code = String(req.params.code || '').trim();
    if (!code) return res.status(400).json({ error: 'invalid_input' });
    const buf = fs.readFileSync(studentsFile, 'utf-8');
    const items = JSON.parse(buf);
    const next = items.filter(s => String(s.studentCode || s.code || '') !== code);
    fs.writeFileSync(studentsFile, JSON.stringify(next, null, 2));
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: 'db_error' });
  }
});

app.post('/api/students/import-bulk', (req, res) => {
  try {
    const list = Array.isArray(req.body) ? req.body : [];
    const buf = fs.readFileSync(studentsFile, 'utf-8');
    const items = JSON.parse(buf);
    const byCode = new Map(items.map(s => [String(s.studentCode || s.code || ''), s]));
    for (const raw of list) {
      const studentCode = String(raw.studentCode || raw.code || '').trim();
      const fullName = String(raw.fullName || raw.name || '').trim();
      const department = String(raw.department || '').trim();
      const level = String(raw.level || '').trim();
      const status = String(raw.status || '').trim();
      if (!studentCode || !fullName) continue;
      if (byCode.has(studentCode)) continue;
      items.push({ studentCode, fullName, department, level, status });
      byCode.set(studentCode, true);
    }
    fs.writeFileSync(studentsFile, JSON.stringify(items, null, 2));
    res.json({ ok: true, count: list.length });
  } catch (e) {
    res.status(500).json({ error: 'db_error' });
  }
});

app.post('/api/exam-results', (req, res) => {
  try {
    const b = req.body || {};
    const studentCode = String(b.studentCode || '').trim();
    const examId = String(b.examId || '').trim();
    const department = String(b.department || '').trim();
    const level = String(b.level || '').trim();
    const correct = Number(b.correct || 0);
    const wrong = Number(b.wrong || 0);
    const total = Number(b.total || 0);
    const score = Number(b.score || 0);
    const submittedAt = String(b.submittedAt || new Date().toISOString());
    if (!studentCode || !examId) return res.status(400).json({ error: 'invalid_input' });
    const buf = fs.readFileSync(examResultsFile, 'utf-8');
    const items = JSON.parse(buf);
    items.push({ studentCode, examId, department, level, correct, wrong, total, score, submittedAt });
    fs.writeFileSync(examResultsFile, JSON.stringify(items, null, 2));
    res.json({ ok: true });
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
    const lectureId = String(b.lectureId || '').trim();
    const timestamp = Number(b.timestamp || Date.now());
    const studentCode = String(b.studentId || b.studentCode || '').trim();
    const studentName = String(b.name || b.studentName || '').trim();
    const department = String(b.department || '').trim();
    const level = String(b.level || '').trim();
    const status = String(b.status || '').trim();
    if (!lectureId || !studentCode || !studentName) {
      return res.status(400).json({ error: 'invalid_input' });
    }
    const buf = fs.readFileSync(attendanceFile, 'utf-8');
    const items = JSON.parse(buf);
    items.push({
      lectureId,
      time: timestamp,
      studentCode,
      studentName,
      department,
      level,
      status,
    });
    fs.writeFileSync(attendanceFile, JSON.stringify(items, null, 2));
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: 'db_error' });
  }
});

app.listen(PORT, () => {});
