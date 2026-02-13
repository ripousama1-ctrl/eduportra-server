const express = require('express');
require('dotenv').config();
const cors = require('cors');
const path = require('path');
const mongoose = require('mongoose');
const crypto = require('crypto');

const app = express();
app.use(cors());
app.use(express.json({ limit: '10mb' }));

const uri =(process.env.MONGO_URI)

mongoose.connect(uri)
  .then(() => {
    console.log("MongoDB connected");

    const port = process.env.PORT || 8080;
    // Seed default users if none exist
    (async () => {
      try {
        // Ensure admin/admin exists regardless of current users
        try {
          const { hash, salt } = hashPassword('admin');
          await User.updateOne(
            { username: 'admin' },
            {
              $set: {
                username: 'admin',
                passwordHash: hash,
                passwordSalt: salt,
                role: 'admin',
                fullName: 'المدير العام',
              },
            },
            { upsert: true }
          );
          console.log('Admin account ensured');
        } catch (e) {
          console.error('Ensure admin error', e);
        }
        const count = await User.countDocuments({});
        if (count === 0) {
          const defaults = [];
          // Admin
          {
            const { hash, salt } = hashPassword('admin');
            defaults.push({
              username: 'admin',
              passwordHash: hash,
              passwordSalt: salt,
              role: 'admin',
              fullName: 'المدير العام',
            });
          }
          // لا نقوم بإنشاء حساب عضو تدريس افتراضي؛ سيتم استخدام admin لكلا المدخلين
          // Students by codes (dept + level)
          const depts = [
            { code: 't', name: 'تكنولوجيا التعليم' },
            { code: 'c', name: 'الحاسب الآلي' },
            { code: 'e', name: 'إعلام تربوي' },
            { code: 'a', name: 'تربية فنية' },
            { code: 'm', name: 'تربية موسيقية' },
            { code: 'h', name: 'اقتصاد منزلي' },
          ];
          const levels = [
            { suffix: '1', name: 'الفرقة الأولى' },
            { suffix: '2', name: 'الفرقة الثانية' },
            { suffix: '3', name: 'الفرقة الثالثة' },
            { suffix: '4', name: 'الفرقة الرابعة' },
          ];
          for (const d of depts) {
            for (const l of levels) {
              const code = `${d.code}${l.suffix}`;
              defaults.push({
                role: 'student',
                fullName: `طالب ${d.name} ${l.suffix}`,
                studentCode: code,
                department: d.name,
                level: l.name,
              });
            }
          }
          await User.insertMany(defaults);
          console.log('Seeded default users');
        }
      } catch (e) {
        console.error('User seed error', e);
      }
    })();
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
  ownerUserId: { type: String, index: true },
  lectureId: { type: String, default: '' },
});

const AttendanceSchema = new mongoose.Schema({
  sessionCode: { type: String, index: true },
  lectureId: { type: String, index: true },
  studentName: String,
  studentCode: { type: String, index: true },
  department: String,
  level: String,
  status: String,
  time: Number,
});
AttendanceSchema.index({ sessionCode: 1, studentCode: 1 }, { unique: true });
AttendanceSchema.index({ lectureId: 1, studentCode: 1 }, { unique: true });

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
const AnnouncementSchema = new mongoose.Schema({
  title: String,
  content: String,
  date: String,
  priority: String,
  readByStudentIds: { type: [String], default: [] },
}, { timestamps: true });
const Announcement = mongoose.model('Announcement', AnnouncementSchema);

const UserSchema = new mongoose.Schema({
  username: { type: String, unique: true, sparse: true },
  passwordHash: String,
  passwordSalt: String,
  role: { type: String, enum: ['admin', 'teacher', 'student'], index: true },
  fullName: String,
  // Student fields
  studentCode: { type: String, unique: true, sparse: true },
  department: String,
  level: String,
  status: String,
}, { timestamps: true });
UserSchema.index({ role: 1 });
const User = mongoose.model('User', UserSchema);

function hashPassword(password, salt = '') {
  const usedSalt = salt || crypto.randomBytes(16).toString('hex');
  const hash = crypto.pbkdf2Sync(password, usedSalt, 100000, 64, 'sha512').toString('hex');
  return { hash, salt: usedSalt };
}

function verifyPassword(password, salt, hash) {
  const computed = crypto.pbkdf2Sync(password, salt, 100000, 64, 'sha512').toString('hex');
  return crypto.timingSafeEqual(Buffer.from(computed, 'hex'), Buffer.from(hash, 'hex'));
}

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

// Announcements
app.get('/api/announcements', (req, res) => {
  Announcement.find({}).sort({ createdAt: -1 }).lean()
    .then(rows => res.json({ items: rows || [] }))
    .catch(() => res.status(500).json({ error: 'db_error' }));
});

app.post('/api/announcements', (req, res) => {
  const b = req.body || {};
  const title = String(b.title || '').trim();
  const content = String(b.content || '').trim();
  const date = String(b.date || '').trim();
  const priority = String(b.priority || 'عادي').trim();
  if (!title || !content) return res.status(400).json({ error: 'invalid_input' });
  Announcement.create({ title, content, date, priority })
    .then(doc => res.json({ id: doc._id }))
    .catch(() => res.status(500).json({ error: 'db_error' }));
});

app.delete('/api/announcements/:id', (req, res) => {
  const id = String(req.params.id || '').trim();
  if (!id) return res.status(400).json({ error: 'invalid_id' });
  Announcement.deleteOne({ _id: id })
    .then(() => res.json({ ok: true }))
    .catch(() => res.status(500).json({ error: 'db_error' }));
});

app.post('/api/announcements/:id/read', (req, res) => {
  const id = String(req.params.id || '').trim();
  const studentId = String(req.body.studentId || '').trim();
  if (!id || !studentId) return res.status(400).json({ error: 'invalid_input' });
  Announcement.updateOne({ _id: id }, { $addToSet: { readByStudentIds: studentId } })
    .then(() => res.json({ ok: true }))
    .catch(() => res.status(500).json({ error: 'db_error' }));
});
// Mark attendance using lectureId + timestamp (QR payload)
app.post('/mark-attendance', async (req, res) => {
  try {
    const lectureId = String(req.body.lectureId || '').trim();
    const timestamp = Number(req.body.timestamp || 0);
    const studentId = String(req.body.studentId || '').trim();
    const name = String(req.body.name || '').trim();
    const department = String(req.body.department || '').trim();
    const level = String(req.body.level || '').trim();
    const status = String(req.body.status || '').trim();
    if (!lectureId || !studentId || !name) return res.status(400).json({ error: 'invalid_input' });
    // Allow arbitrary lectureId strings; do not enforce schedule existence
    const t = timestamp > 0 ? timestamp : Date.now();
    try {
      await Attendance.create({
        lectureId,
        studentName: name,
        studentCode: studentId,
        department,
        level,
        status,
        time: t,
      });
      res.json({ ok: true });
    } catch (e) {
      if (e && e.code === 11000) return res.json({ ok: true, duplicated: true });
      return res.status(500).json({ error: 'db_error' });
    }
  } catch (err) {
    if (err && err.code === 11000) return res.json({ ok: true, duplicated: true });
    return res.status(500).json({ error: 'db_error' });
  }
});

// List attendees by lectureId
app.get('/api/attendance/students-by-lecture', (req, res) => {
  const lectureId = String(req.query.lectureId || '').trim();
  if (!lectureId) return res.status(400).json({ error: 'invalid_input' });
  Attendance.find({ lectureId }).sort({ time: -1 }).lean()
    .then(rows => res.json({ students: rows || [] }))
    .catch(() => res.status(500).json({ error: 'db_error' }));
});

app.post('/api/session/start', async (req, res) => {
  try {
    const durationMinutes = Number(req.body.durationMinutes || 15);
    const userId = String(req.body.userId || '').trim();
    const lectureId = String(req.body.lectureId || '').trim();
    if (!userId) return res.status(400).json({ error: 'invalid_input' });
    const code = randomCode();
    const expires = nowMs() + durationMinutes * 60 * 1000;
    await Session.updateMany({ ownerUserId: userId }, { active: false });
    await Session.create({ code, expiresAt: expires, active: true, ownerUserId: userId, lectureId });
    return res.json({ code, expiresAt: expires, lectureId });
  } catch (e) {
    return res.status(500).json({ error: 'db_error' });
  }
});

app.get('/api/session/active', (req, res) => {
  const t = nowMs();
  const userId = String(req.query.userId || '').trim();
  const query = { active: true, expiresAt: { $gt: t } };
  if (userId) query.ownerUserId = userId;
  Session.findOne(query).lean()
    .then(row => {
      if (!row) return res.json({ code: null, expiresAt: null, lectureId: null });
      res.json({ code: row.code, expiresAt: row.expiresAt, lectureId: row.lectureId || '' });
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

app.post('/api/auth/login', async (req, res) => {
  try {
    const b = req.body || {};
    const username = String(b.username || '').trim();
    const password = String(b.password || '').trim();
    const studentCode = String(b.studentCode || '').trim();
    let user;
    if (studentCode) {
      user = await User.findOne({ studentCode, role: 'student' }).lean();
      if (!user) return res.status(401).json({ error: 'invalid_credentials' });
    } else {
      if (!username || !password) return res.status(400).json({ error: 'invalid_input' });
      const doc = await User.findOne({ username }).lean();
      if (!doc) return res.status(401).json({ error: 'invalid_credentials' });
      const ok = verifyPassword(password, doc.passwordSalt || '', doc.passwordHash || '');
      if (!ok) return res.status(401).json({ error: 'invalid_credentials' });
      user = doc;
    }
    const safe = {
      id: user._id,
      username: user.username || '',
      role: user.role,
      fullName: user.fullName || '',
      studentCode: user.studentCode || '',
      department: user.department || '',
      level: user.level || '',
    };
    res.json({ user: safe });
  } catch (e) {
    res.status(500).json({ error: 'db_error' });
  }
});

app.get('/api/users/:id', async (req, res) => {
  try {
    const id = String(req.params.id || '').trim();
    if (!id) return res.status(400).json({ error: 'invalid_id' });
    const user = await User.findById(id).lean();
    if (!user) return res.status(404).json({ error: 'not_found' });
    const safe = {
      id: user._id,
      username: user.username || '',
      role: user.role,
      fullName: user.fullName || '',
      studentCode: user.studentCode || '',
      department: user.department || '',
      level: user.level || '',
    };
    res.json({ user: safe });
  } catch (e) {
    res.status(500).json({ error: 'db_error' });
  }
});

app.patch('/api/users/:id', async (req, res) => {
  try {
    const id = String(req.params.id || '').trim();
    if (!id) return res.status(400).json({ error: 'invalid_id' });
    const b = req.body || {};
    const update = {};
    if (typeof b.fullName !== 'undefined') update.fullName = String(b.fullName || '').trim();
    if (typeof b.department !== 'undefined') update.department = String(b.department || '').trim();
    if (typeof b.level !== 'undefined') update.level = String(b.level || '').trim();
    const doc = await User.findByIdAndUpdate(id, update, { new: true }).lean();
    if (!doc) return res.status(404).json({ error: 'not_found' });
    const safe = {
      id: doc._id,
      username: doc.username || '',
      role: doc.role,
      fullName: doc.fullName || '',
      studentCode: doc.studentCode || '',
      department: doc.department || '',
      level: doc.level || '',
    };
    res.json({ user: safe });
  } catch (e) {
    res.status(500).json({ error: 'db_error' });
  }
});

app.post('/api/students/import-bulk', async (req, res) => {
  try {
    const list = Array.isArray(req.body) ? req.body : [];
    if (!list.length) return res.json({ ok: true, inserted: 0, upserted: 0 });
    const ops = [];
    for (const s of list) {
      const studentCode = String(s.code || s.studentCode || '').trim();
      if (!studentCode) continue;
      const fullName = String(s.name || s.fullName || '').trim();
      const department = String(s.department || '').trim();
      const level = String(s.level || '').trim();
      const status = String(s.status || '').trim();
      ops.push({
        updateOne: {
          filter: { studentCode },
          update: {
            $set: {
              role: 'student',
              fullName,
              department,
              level,
              status,
              studentCode,
            },
          },
          upsert: true,
        },
      });
    }
    if (!ops.length) return res.json({ ok: true, inserted: 0, upserted: 0 });
    const result = await User.bulkWrite(ops, { ordered: false });
    res.json({ ok: true, result });
  } catch (e) {
    res.status(500).json({ error: 'db_error' });
  }
});

// List students globally (optional filters: department, level)
app.get('/api/students', async (req, res) => {
  try {
    const department = String(req.query.department || '').trim();
    const level = String(req.query.level || '').trim();
    const query = { role: 'student' };
    if (department) query.department = department;
    if (level) query.level = level;
    const rows = await User.find(query).sort({ fullName: 1 }).lean();
    const students = rows.map(r => ({
      fullName: r.fullName || '',
      studentCode: r.studentCode || '',
      department: r.department || '',
      level: r.level || '',
      status: r.status || '',
    }));
    res.json({ students });
  } catch (e) {
    res.status(500).json({ error: 'db_error' });
  }
});

// Delete student globally by studentCode
app.delete('/api/students/:studentCode', async (req, res) => {
  try {
    const studentCode = String(req.params.studentCode || '').trim();
    if (!studentCode) return res.status(400).json({ error: 'invalid_id' });
    await User.deleteOne({ studentCode, role: 'student' });
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: 'db_error' });
  }
});

// Add/Upsert single student
app.post('/api/students', async (req, res) => {
  try {
    const b = req.body || {};
    const studentCode = String(b.studentCode || b.code || '').trim();
    const fullName = String(b.fullName || b.name || '').trim();
    const department = String(b.department || '').trim();
    const level = String(b.level || '').trim();
    const status = String(b.status || '').trim();
    if (!studentCode || !fullName) return res.status(400).json({ error: 'invalid_input' });
    const result = await User.updateOne(
      { studentCode },
      {
        $set: {
          role: 'student',
          fullName,
          department,
          level,
          status,
          studentCode,
        },
      },
      { upsert: true }
    );
    res.json({ ok: true, upserted: result.upsertedCount || 0, modified: result.modifiedCount || 0 });
  } catch (e) {
    res.status(500).json({ error: 'db_error' });
  }
});
