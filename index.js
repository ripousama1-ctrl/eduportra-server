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

app.listen(PORT, () => {});
