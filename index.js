const express = require('express');
require('dotenv').config();
const cors = require('cors');
const path = require('path');
const mongoose = require('mongoose');

const app = express();
app.use(cors());
app.use(express.json({ limit: '10mb' }));

const uri =(process.env.MONGO_URI)

mongoose.connect(uri)
  .then(() => {
    console.log("MongoDB connected");

    const port = process.env.PORT || 8080;
    app.get('/', (req, res) => {
  res.send('Server is working 🚀');
});

    app.listen(port, () => {
      console.log(`Server listening on http://localhost:${port}`);
    });
  })
  .catch(err => {
    console.error("MongoDB connection error:", err);
  });

const SessionSchema = new mongoose.Schema({
  code: { type: String, unique: true, index: true },
  expiresAt: { type: Number, index: true },
  active: { type: Boolean, default: true, index: true },
});

const AttendanceSchema = new mongoose.Schema({
  sessionCode: { type: String, index: true },
  studentName: String,
  studentCode: { type: String, index: true },
  department: String,
  level: String,
  status: String,
  time: Number,
});
AttendanceSchema.index({ sessionCode: 1, studentCode: 1 }, { unique: true });

const ScheduleSchema = new mongoose.Schema({
  subject: String,
  day: String,
  date: String,
  time: String,
  location: String,
  department: String,
  level: String,
  imageUrl: String,
  isExam: { type: Boolean, default: false, index: true },
}, { timestamps: true });
ScheduleSchema.index({ department: 1, level: 1, isExam: 1 });

const Session = mongoose.model('Session', SessionSchema);
const Attendance = mongoose.model('Attendance', AttendanceSchema);
const Schedule = mongoose.model('Schedule', ScheduleSchema);

function randomCode() {
  const n = Math.floor(100000 + Math.random() * 900000);
  return String(n);
}

function nowMs() {
  return Date.now();
}

app.get('/attendance', (req, res) => {
  const code = String(req.query.code || '').trim();
  res.setHeader('Content-Type', 'text/html; charset=utf-8');
  res.send(`<html><head><meta charset="utf-8"><title>Attendance</title></head><body><h1>Attendance Code</h1><p>${code}</p></body></html>`);
});

app.get('/health/db', (req, res) => {
  res.json({ state: mongoose.connection.readyState });
});

app.post('/api/session/start', (req, res) => {
  const durationMinutes = Number(req.body.durationMinutes || 15);
  const code = randomCode();
  const expires = nowMs() + durationMinutes * 60 * 1000;
  Session.updateMany({}, { active: false }).then(() =>
    Session.create({ code, expiresAt: expires, active: true })
  ).then(() => res.json({ code, expiresAt: expires }))
   .catch(() => res.status(500).json({ error: 'db_error' }));
});

app.get('/api/session/active', (req, res) => {
  const t = nowMs();
  Session.findOne({ active: true, expiresAt: { $gt: t } }).lean()
    .then(row => {
      if (!row) return res.json({ code: null, expiresAt: null });
      res.json({ code: row.code, expiresAt: row.expiresAt });
    })
    .catch(() => res.status(500).json({ error: 'db_error' }));
});

app.post('/api/attendance/register', (req, res) => {
  const code = String(req.body.code || '').trim();
  const name = String(req.body.name || '').trim();
  const studentCode = String(req.body.studentCode || '').trim();
  const department = String(req.body.department || '').trim();
  const level = String(req.body.level || '').trim();
  const status = String(req.body.status || '').trim();
  if (!code || !name || !studentCode) return res.status(400).json({ error: 'invalid_input' });
  const t = nowMs();
  Session.findOne({ code, active: true, expiresAt: { $gt: t } })
    .then(row => {
      if (!row) return res.status(400).json({ error: 'inactive_session' });
      return Attendance.create({
        sessionCode: code,
        studentName: name,
        studentCode,
        department,
        level,
        status,
        time: t,
      }).then(() => res.json({ ok: true }))
        .catch(err => {
          if (err && err.code === 11000) return res.json({ ok: true, duplicated: true });
          return res.status(500).json({ error: 'db_error' });
        });
    })
    .catch(() => res.status(500).json({ error: 'db_error' }));
});

app.get('/api/attendance/students', (req, res) => {
  const code = String(req.query.code || '').trim();
  if (!code) return res.status(400).json({ error: 'invalid_input' });
  Attendance.find({ sessionCode: code }).sort({ time: -1 }).lean()
    .then(rows => res.json({ students: rows || [] }))
    .catch(() => res.status(500).json({ error: 'db_error' }));
});

app.post('/api/schedules', (req, res) => {
  const b = req.body || {};
  const subject = String(b.subject || '').trim();
  const day = String(b.day || '').trim();
  const date = String(b.date || '').trim();
  const time = String(b.time || '').trim();
  const location = String(b.location || '').trim();
  const department = String(b.department || '').trim();
  const level = String(b.level || '').trim();
  const imageUrl = String(b.imageUrl || '').trim();
  const isExam = Boolean(b.isExam);
  if (!subject || (!day && !date) || !time) return res.status(400).json({ error: 'invalid_input' });
  Schedule.create({ subject, day, date, time, location, department, level, imageUrl, isExam })
    .then(doc => res.json({ id: doc._id }))
    .catch(() => res.status(500).json({ error: 'db_error' }));
});

app.post('/api/schedules/image', (req, res) => {
  const department = String(req.body.department || '').trim();
  const level = String(req.body.level || '').trim();
  const imageUrl = String(req.body.imageUrl || '').trim();
  const isExam = Boolean(req.body.isExam);
  if (!department || !level || !imageUrl) return res.status(400).json({ error: 'invalid_input' });
  Schedule.create({ subject: 'صورة الجدول', day: '', date: '', time: '', location: '', department, level, imageUrl, isExam })
    .then(doc => res.json({ id: doc._id }))
    .catch(() => res.status(500).json({ error: 'db_error' }));
});

app.get('/api/schedules', (req, res) => {
  const department = String(req.query.department || '').trim();
  const level = String(req.query.level || '').trim();
  const isExamParam = req.query.isExam;
  const hasExam = typeof isExamParam !== 'undefined';
  const isExam = hasExam ? Boolean(isExamParam === '1' || isExamParam === 'true') : undefined;
  const query = {};
  if (department) query.department = department;
  if (level) query.level = level;
  if (typeof isExam !== 'undefined') query.isExam = isExam;
  Schedule.find(query).sort({ createdAt: -1 }).lean()
    .then(rows => res.json({ items: rows || [] }))
    .catch(() => res.status(500).json({ error: 'db_error' }));
});

app.delete('/api/schedules/:id', (req, res) => {
  const id = String(req.params.id || '').trim();
  if (!id) return res.status(400).json({ error: 'invalid_id' });
  Schedule.deleteOne({ _id: id })
    .then(() => res.json({ ok: true }))
    .catch(() => res.status(500).json({ error: 'db_error' }));
});
