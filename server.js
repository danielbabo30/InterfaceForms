require('dotenv').config();
const express    = require('express');
const multer     = require('multer');
const fs         = require('fs');
const path       = require('path');
const crypto     = require('crypto');
const nodemailer = require('nodemailer');
const mongoose   = require('mongoose');
const helmet     = require('helmet');
const rateLimit  = require('express-rate-limit');
const bcrypt     = require('bcryptjs');
const jwt        = require('jsonwebtoken');

const app        = express();
const PORT       = process.env.PORT || 3002;

/* ── Logger ── */
const IS_VERCEL = !!process.env.VERCEL;
const LOG_FILE = path.join(__dirname, 'logs', 'app.log');
if (!IS_VERCEL && !fs.existsSync(path.join(__dirname, 'logs'))) fs.mkdirSync(path.join(__dirname, 'logs'));
function log(level, msg, data) {
  const line = `[${new Date().toISOString()}] [${level}] ${msg}${data ? ' ' + JSON.stringify(data) : ''}\n`;
  process.stdout.write(line);
  if (!IS_VERCEL) fs.appendFileSync(LOG_FILE, line);
}
const logger = { info: (m,d) => log('INFO', m,d), warn: (m,d) => log('WARN', m,d), error: (m,d) => log('ERROR', m,d) };
const UPLOADS_DIR    = path.join(__dirname, 'uploads');
const EMAIL_CFG_FILE = path.join(__dirname, 'email-config.json');
const JWT_SECRET     = process.env.JWT_SECRET || 'change-this-secret-in-production';

/* ── MongoDB ── */
const MONGO_URI = process.env.MONGO_URI || 'mongodb://127.0.0.1:27017/forms-saas';
let _mongoReady = false;
function connectMongo() {
  if (_mongoReady || mongoose.connection.readyState !== 0) return;
  mongoose.connect(MONGO_URI)
    .then(() => { _mongoReady = true; console.log('✓  MongoDB connected'); })
    .catch(e  => console.error('✗  MongoDB connection failed:', e.message));
}
connectMongo();

/* ── Seed superadmin ── */
async function seedSuperAdmin() {
  try {
    const SA_EMAIL    = process.env.SA_EMAIL    || 'admin@system.local';
    const SA_PASSWORD = process.env.SA_PASSWORD || 'Admin1234!';
    const existing = await User.findOne({ role: 'superadmin' });
    if (!existing) {
      const passwordHash = await bcrypt.hash(SA_PASSWORD, 12);
      await User.create({
        id: 'superadmin', tenantId: '__system__', email: SA_EMAIL,
        passwordHash, role: 'superadmin', name: 'Super Admin',
        createdAt: new Date().toISOString(),
      });
      console.log(`✓  Superadmin seeded: ${SA_EMAIL} / ${SA_PASSWORD}`);
    }
  } catch (e) { console.error('seed error:', e.message); }
}
mongoose.connection.once('open', seedSuperAdmin);

/* ── Auth middleware ── */
function requireAuth(req, res, next) {
  const auth = req.headers['authorization'] || '';
  const token = auth.startsWith('Bearer ') ? auth.slice(7) : '';
  if (!token) return res.status(401).json({ ok: false, error: 'Unauthorized' });
  try { req.user = jwt.verify(token, JWT_SECRET); next(); }
  catch { res.status(401).json({ ok: false, error: 'Token invalid or expired' }); }
}

function requireSuperAdmin(req, res, next) {
  requireAuth(req, res, () => {
    if (req.user.role !== 'superadmin') return res.status(403).json({ ok: false, error: 'Forbidden' });
    next();
  });
}

function requireContact(req, res, next) {
  if (!req.user || !req.user.isContact) return res.status(403).json({ ok: false, error: 'Forbidden' });
  next();
}

function requireAdmin(req, res, next) {
  const auth = req.headers['authorization'] || '';
  const jwtToken = auth.startsWith('Bearer ') ? auth.slice(7) : '';
  if (jwtToken) {
    try {
      req.user = jwt.verify(jwtToken, JWT_SECRET);
      if (req.user.role === 'admin' || req.user.role === 'superadmin') return next();
    } catch {}
  }
  res.status(401).json({ ok: false, error: 'Unauthorized' });
}

/* ── Schemas ── */
const TenantSchema = new mongoose.Schema({
  id:        { type: String, required: true, unique: true },
  name:      { type: String, required: true },
  companyId:    { type: String, default: '' },
  contactName:   { type: String, default: '' },
  contactPhone:  { type: String, default: '' },
  contactEmail:  { type: String, default: '' },
  paymentStatus: { type: String, default: '' },
  active:        { type: Boolean, default: true },
  tenantStatus:  { type: String, enum: ['pending', 'active', 'inactive'], default: 'active' },
  linkMode:      { type: String, enum: ['shared', 'perUser'], default: 'shared' },
  leadVisibility:{ type: String, enum: ['all', 'own'], default: 'all' },
  formEditMode:  { type: String, enum: ['contact', 'all'], default: 'contact' },
  formMode:      { type: String, enum: ['shared', 'perUser'], default: 'shared' },
  createdAt: { type: String },
});

const UserSchema = new mongoose.Schema({
  id:            { type: String, required: true, unique: true },
  tenantId:      { type: String, required: true, index: true },
  email:         { type: String, required: true, unique: true },
  passwordHash:  { type: String, required: true },
  role:          { type: String, enum: ['superadmin', 'admin'], default: 'admin' },
  name:          { type: String, default: '' },
  idNumber:      { type: String, default: '' },
  userStatus:    { type: String, enum: ['active', 'frozen', 'removed', 'pending'], default: 'active' },
  onboardToken:  { type: String, default: '' },
  paymentStatus: { type: String, default: '' },
  isContact:     { type: Boolean, default: false },
  createdAt:     { type: String },
});

const FormSchema = new mongoose.Schema({
  id:          { type: String, required: true, unique: true },
  tenantId:    { type: String, default: 'default', index: true },
  title:       { type: String, default: 'טופס חדש' },
  description: { type: String, default: '' },
  questions:   { type: Array,  default: [] },
  createdAt:   { type: String },
  updatedAt:   { type: String },
}, { strict: true });

const SubmissionSchema = new mongoose.Schema({
  id:                 { type: String, required: true, unique: true },
  tenantId:           { type: String, default: 'default', index: true },
  formId:             { type: String, required: true, index: true },
  submittedAt:        { type: String },
  answers:            { type: mongoose.Schema.Types.Mixed, default: {} },
  linkedLeadId:       { type: String, index: true },
  linkSentAt:         { type: String },
  linkSentFormId:     { type: String },
  responseReceivedAt: { type: String },
  subStatus:          { type: String, default: 'נשלח' },
  assignedUserId:     { type: String, default: '' },
});

const SubSessionSchema = new mongoose.Schema({
  token:       { type: String, required: true, unique: true, index: true },
  mainToken:   { type: String, required: true, index: true },
  borrowerNum: { type: Number, required: true },
  formId:      { type: String, required: true },
  status:      { type: String, default: 'pending' },
  answers:     { type: mongoose.Schema.Types.Mixed, default: {} },
  createdAt:   { type: String },
}, { strict: true });

const PrefillSchema = new mongoose.Schema({
  token:     { type: String, required: true, unique: true, index: true },
  answers:   { type: mongoose.Schema.Types.Mixed, default: {} },
  leadId:    { type: String },
  createdAt: { type: Date, default: Date.now, expires: 7 * 24 * 3600 },
});

// Inline file storage (for form uploads in serverless)
const FileStoreSchema = new mongoose.Schema({ _id: String, data: mongoose.Schema.Types.Mixed });
const ContentSchema   = new mongoose.Schema({ _id: String, data: mongoose.Schema.Types.Mixed });

const Tenant     = mongoose.model('Tenant',     TenantSchema);
const User       = mongoose.model('User',       UserSchema);
const Form       = mongoose.model('Form',       FormSchema);
const Submission = mongoose.model('Submission', SubmissionSchema);
const SubSession = mongoose.model('SubSession', SubSessionSchema);
const Prefill    = mongoose.model('Prefill',    PrefillSchema);
const FileStore  = mongoose.model('FileStore',  FileStoreSchema);
const Content    = mongoose.model('Content',    ContentSchema);

/* ── helpers ── */
function genId() { return crypto.randomBytes(4).toString('hex'); }
function esc(s)  { return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;'); }

try { if (!fs.existsSync(UPLOADS_DIR)) fs.mkdirSync(UPLOADS_DIR); } catch(e) {}

const ALLOWED_FORM_MIMES = ['application/pdf','image/png','image/jpeg','application/msword',
  'application/vnd.openxmlformats-officedocument.wordprocessingml.document'];
const formFileUpload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 4 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    if (ALLOWED_FORM_MIMES.includes(file.mimetype)) cb(null, true);
    else cb(new Error('סוג קובץ לא מורשה'));
  }
});

/* ── Security ── */
app.use(helmet({ contentSecurityPolicy: false, crossOriginEmbedderPolicy: false }));
app.use(express.json({ limit: '2mb' }));

const publicSubmitLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, max: 20, standardHeaders: true, legacyHeaders: false,
  skip: (req) => ['127.0.0.1','::1','::ffff:127.0.0.1'].includes(req.ip),
  message: { ok: false, error: 'Too many requests' }
});
const adminLimiter  = rateLimit({ windowMs: 60 * 1000, max: 200, standardHeaders: true, legacyHeaders: false });
const authLimiter   = rateLimit({ windowMs: 15 * 60 * 1000, max: 20, standardHeaders: true, legacyHeaders: false });

/* ── Static ── */
app.get('/admin.html',   (req, res) => res.sendFile(path.join(__dirname, 'admin.html')));
app.get('/super-admin',  (req, res) => res.sendFile(path.join(__dirname, 'super-admin.html')));
app.get('/register',     (req, res) => res.sendFile(path.join(__dirname, 'register.html')));
app.get('/onboard/:token', (req, res) => res.sendFile(path.join(__dirname, 'onboard.html')));
app.use('/uploads', express.static(UPLOADS_DIR, { dotfiles: 'deny' }));
const SENSITIVE = /\.(env|json|js|log|md|gitignore|lock)$/i;
app.get(SENSITIVE, (req, res) => res.status(403).end());

/* ── Registration & Onboarding ── */
const registerLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, max: 10, standardHeaders: true, legacyHeaders: false,
  skip: (req) => ['127.0.0.1','::1','::ffff:127.0.0.1'].includes(req.ip),
  message: { ok: false, error: 'Too many requests' }
});

app.post('/api/register', registerLimiter, async (req, res) => {
  try {
    connectMongo();
    const { tenantName, companyId, contactName, contactPhone, contactEmail, users } = req.body;
    if (!tenantName || tenantName.trim().length < 2)
      return res.status(400).json({ ok: false, error: 'שם חברה חסר' });
    if (!Array.isArray(users) || users.length < 1 || users.length > 10)
      return res.status(400).json({ ok: false, error: 'יש לספק בין 1 ל-10 משתמשים' });
    for (const u of users) {
      if (!u.name || !u.idNumber || !u.email)
        return res.status(400).json({ ok: false, error: 'כל משתמש חייב שם, תעודת זהות ואימייל' });
    }
    const emails = users.map(u => u.email.toLowerCase().trim());
    if (new Set(emails).size !== emails.length)
      return res.status(400).json({ ok: false, error: 'כתובות אימייל כפולות' });
    // Check for existing emails
    const existingUser = await User.findOne({ email: { $in: emails } }).lean();
    if (existingUser)
      return res.status(409).json({ ok: false, error: 'אחד מהאימיילים כבר קיים במערכת' });
    const tenantId = genId() + genId();
    await Tenant.create({
      id: tenantId, name: tenantName.trim(), companyId: companyId || '',
      contactName: contactName || '', contactPhone: contactPhone || '',
      contactEmail: contactEmail || '', paymentStatus: '',
      active: false, tenantStatus: 'pending', createdAt: new Date().toISOString(),
    });
    const randomPwd = crypto.randomBytes(32).toString('hex');
    const passwordHash = await bcrypt.hash(randomPwd, 12);
    for (let i = 0; i < users.length; i++) {
      const u = users[i];
      await User.create({
        id: genId() + genId(), tenantId,
        email: u.email.toLowerCase().trim(),
        passwordHash,
        role: 'admin',
        name: u.name.trim(),
        idNumber: u.idNumber.trim(),
        userStatus: 'pending',
        onboardToken: '',
        isContact: i === 0,
        createdAt: new Date().toISOString(),
      });
    }
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ ok: false, error: 'שגיאה פנימית' }); }
});

app.post('/api/onboard', registerLimiter, async (req, res) => {
  try {
    connectMongo();
    const { token, idNumber, password } = req.body;
    if (!token) return res.status(400).json({ ok: false, error: 'טוקן חסר' });
    const user = await User.findOne({ onboardToken: token });
    if (!user) return res.status(404).json({ ok: false, error: 'הקישור לא תקין או פג תוקף' });
    if (!idNumber || user.idNumber.trim() !== idNumber.trim())
      return res.status(400).json({ ok: false, error: 'תעודת הזהות אינה תואמת' });
    if (!password || password.length < 8)
      return res.status(400).json({ ok: false, error: 'הסיסמה חייבת להכיל לפחות 8 תווים' });
    user.passwordHash = await bcrypt.hash(password, 12);
    user.onboardToken = '';
    await user.save();
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ ok: false, error: 'שגיאה פנימית' }); }
});

/* ═══ AUTH API ═══ */

app.post('/api/auth/login', authLimiter, async (req, res) => {
  try {
    connectMongo();
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ ok: false, error: 'חסרים פרטים' });
    const user = await User.findOne({ email: email.toLowerCase().trim() }).lean();
    if (!user) {
      logger.warn('LOGIN_FAIL: user not found', { email });
      return res.status(401).json({ ok: false, error: 'אימייל או סיסמה שגויים' });
    }
    const match = await bcrypt.compare(password, user.passwordHash);
    if (!match) {
      logger.warn('LOGIN_FAIL: wrong password', { email, userStatus: user.userStatus, hasHash: !!user.passwordHash });
      return res.status(401).json({ ok: false, error: 'אימייל או סיסמה שגויים' });
    }
    if (user.role !== 'superadmin') {
      const tenant = await Tenant.findOne({ id: user.tenantId }).lean();
      if (!tenant || !tenant.active) {
        logger.warn('LOGIN_FAIL: tenant inactive', { email, tenantId: user.tenantId, tenantActive: tenant?.active });
        return res.status(403).json({ ok: false, error: 'החשבון אינו פעיל' });
      }
    }
    logger.info('LOGIN_OK', { email, role: user.role });
    const token = jwt.sign(
      { userId: user.id, tenantId: user.tenantId, role: user.role, name: user.name, isContact: !!user.isContact },
      JWT_SECRET, { expiresIn: '7d' }
    );
    res.json({ ok: true, token, role: user.role, name: user.name, tenantId: user.tenantId, isContact: !!user.isContact });
  } catch (e) {
    logger.error('LOGIN_ERROR', { error: e.message });
    res.status(500).json({ ok: false, error: 'שגיאה פנימית' });
  }
});

app.get('/api/auth/me', requireAuth, (req, res) => res.json({ ok: true, user: req.user }));

/* ═══ SUPER-ADMIN API ═══ */

app.get('/api/sa/tenants', adminLimiter, requireSuperAdmin, async (req, res) => {
  try {
    const tenants = await Tenant.find({}, { _id: 0, __v: 0 }).lean();
    const counts  = await User.aggregate([{ $group: { _id: '$tenantId', count: { $sum: 1 } } }]);
    const countMap = {};
    counts.forEach(c => { countMap[c._id] = c.count; });
    res.json({ ok: true, tenants: tenants.map(t => ({ ...t, userCount: countMap[t.id] || 0 })) });
  } catch (e) { res.status(500).json({ ok: false, error: e.message }); }
});

app.post('/api/sa/tenants', adminLimiter, requireSuperAdmin, async (req, res) => {
  try {
    const { name, companyId, contactName, contactPhone, contactEmail, paymentStatus } = req.body;
    if (!name || name.trim().length < 2) return res.status(400).json({ ok: false, error: 'שם חסר' });
    const tenant = { id: genId(), name: name.trim(), companyId: companyId || '', contactName: contactName || '', contactPhone: contactPhone || '', contactEmail: contactEmail || '', paymentStatus: paymentStatus || '', active: true, createdAt: new Date().toISOString() };
    await Tenant.create(tenant);
    res.json({ ok: true, tenant });
  } catch (e) { res.status(500).json({ ok: false, error: e.message }); }
});

app.patch('/api/sa/tenants/:id', adminLimiter, requireSuperAdmin, async (req, res) => {
  try {
    const { name, active, companyId, contactName, contactPhone, contactEmail, paymentStatus } = req.body;
    const update = {};
    if (typeof name === 'string') update.name = name.trim();
    if (typeof active === 'boolean') update.active = active;
    if (typeof companyId    === 'string') update.companyId    = companyId.trim();
    if (typeof contactName  === 'string') update.contactName  = contactName.trim();
    if (typeof contactPhone === 'string') update.contactPhone = contactPhone.trim();
    if (typeof contactEmail === 'string') update.contactEmail = contactEmail.trim();
    if (typeof paymentStatus === 'string') update.paymentStatus = paymentStatus.trim();
    const t = await Tenant.findOneAndUpdate({ id: req.params.id }, { $set: update }, { new: true, lean: true });
    if (!t) return res.status(404).json({ ok: false, error: 'לא נמצא' });
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ ok: false, error: e.message }); }
});

app.delete('/api/sa/tenants/:id', adminLimiter, requireSuperAdmin, async (req, res) => {
  try {
    await Tenant.deleteOne({ id: req.params.id });
    await User.deleteMany({ tenantId: req.params.id });
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ ok: false, error: e.message }); }
});

app.post('/api/sa/tenants/:id/approve', adminLimiter, requireSuperAdmin, async (req, res) => {
  try {
    const tenant = await Tenant.findOne({ id: req.params.id });
    if (!tenant) return res.status(404).json({ ok: false, error: 'לא נמצא' });
    tenant.active = true;
    tenant.tenantStatus = 'active';
    await tenant.save();
    const pendingUsers = await User.find({ tenantId: req.params.id, userStatus: 'pending' });
    const cfg = getEmailCfg();
    let transporter = null;
    if (cfg?.user && cfg?.pass) {
      transporter = nodemailer.createTransport({
        host: cfg.host, port: cfg.port || 587, secure: cfg.port == 465,
        auth: { user: cfg.user, pass: cfg.pass }
      });
    }
    const BASE_URL = process.env.BASE_URL || 'http://localhost:3002';
    for (const user of pendingUsers) {
      user.onboardToken = crypto.randomBytes(32).toString('hex');
      user.userStatus = 'active';
      await user.save();
      if (transporter) {
        const link = `${BASE_URL}/onboard/${user.onboardToken}`;
        const html = `
<div dir="rtl" style="font-family:Arial,sans-serif;max-width:580px;margin:0 auto;direction:rtl;text-align:right;">
  <div style="background:#1C3A4A;padding:28px 32px;border-radius:12px 12px 0 0;">
    <h2 style="margin:0;color:#C8A96E;font-size:22px;">הזמנה להתחבר למערכת</h2>
    <div style="color:rgba(245,241,235,.7);font-size:14px;margin-top:6px;">${tenant.name}</div>
  </div>
  <div style="background:#fff;padding:28px 32px;border:1px solid #e8ddd0;border-top:none;border-radius:0 0 12px 12px;">
    <p style="font-size:16px;color:#1C3A4A;margin:0 0 16px;">שלום ${user.name},</p>
    <p style="font-size:15px;color:#4a5e6a;line-height:1.6;margin:0 0 24px;">
      חשבונך במערכת אושר! לחץ על הכפתור למטה כדי להגדיר את הסיסמה שלך ולהתחיל להשתמש במערכת.
    </p>
    <a href="${link}" style="display:inline-block;background:#C8A96E;color:#1C3A4A;text-decoration:none;padding:14px 32px;border-radius:8px;font-weight:700;font-size:15px;">הגדר סיסמה והתחבר</a>
    <p style="margin:24px 0 0;font-size:12px;color:#aaa;">אם הכפתור לא עובד, העתק את הקישור: <a href="${link}" style="color:#C8A96E;">${link}</a></p>
  </div>
</div>`;
        try {
          await transporter.sendMail({
            from: `"${cfg.fromName || 'Forms SaaS'}" <${cfg.user}>`,
            to: user.email,
            subject: `הזמנה להתחבר למערכת — ${tenant.name}`,
            html,
          });
        } catch (mailErr) { console.error('send onboard email error:', mailErr.message); }
      }
    }
    res.json({ ok: true, usersApproved: pendingUsers.length });
  } catch (e) { res.status(500).json({ ok: false, error: e.message }); }
});

app.get('/api/sa/users', adminLimiter, requireSuperAdmin, async (req, res) => {
  try {
    const users = await User.find({}, { _id: 0, __v: 0, passwordHash: 0 }).lean();
    res.json({ ok: true, users });
  } catch (e) { res.status(500).json({ ok: false, error: e.message }); }
});

app.post('/api/sa/users', adminLimiter, requireSuperAdmin, async (req, res) => {
  try {
    const { tenantId, email, password, name, idNumber, role, paymentStatus } = req.body;
    if (!tenantId || !email || !password) return res.status(400).json({ ok: false, error: 'חסרים שדות חובה' });
    if (password.length < 8) return res.status(400).json({ ok: false, error: 'סיסמה קצרה מדי (מינימום 8)' });
    if (await User.findOne({ email: email.toLowerCase().trim() }))
      return res.status(409).json({ ok: false, error: 'אימייל כבר קיים' });
    const passwordHash = await bcrypt.hash(password, 12);
    const user = {
      id: genId() + genId(), tenantId, email: email.toLowerCase().trim(),
      passwordHash, name: name || '', idNumber: idNumber || '',
      role: role === 'superadmin' ? 'superadmin' : 'admin',
      userStatus: 'active', paymentStatus: paymentStatus || '',
      createdAt: new Date().toISOString(),
    };
    await User.create(user);
    const { passwordHash: _, ...safe } = user;
    res.json({ ok: true, user: safe });
  } catch (e) { res.status(500).json({ ok: false, error: e.message }); }
});

app.patch('/api/sa/users/:id', adminLimiter, requireSuperAdmin, async (req, res) => {
  try {
    const { name, password, idNumber, userStatus, paymentStatus } = req.body;
    const update = {};
    if (typeof name === 'string') update.name = name.trim();
    if (typeof idNumber === 'string') update.idNumber = idNumber.trim();
    if (typeof paymentStatus === 'string') update.paymentStatus = paymentStatus.trim();
    if (userStatus && ['active', 'frozen', 'removed', 'pending'].includes(userStatus)) update.userStatus = userStatus;
    if (typeof password === 'string' && password.length >= 8)
      update.passwordHash = await bcrypt.hash(password, 12);
    const u = await User.findOneAndUpdate({ id: req.params.id }, { $set: update }, { new: true, lean: true });
    if (!u) return res.status(404).json({ ok: false, error: 'לא נמצא' });
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ ok: false, error: e.message }); }
});

app.delete('/api/sa/users/:id', adminLimiter, requireSuperAdmin, async (req, res) => {
  try {
    const r = await User.deleteOne({ id: req.params.id });
    if (!r.deletedCount) return res.status(404).json({ ok: false, error: 'לא נמצא' });
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ ok: false, error: e.message }); }
});

/* ═══ TENANT USER MANAGEMENT (contact-only) ═══ */

app.get('/api/tenant/users', adminLimiter, requireAdmin, requireContact, async (req, res) => {
  try {
    const users = await User.find({ tenantId: req.user.tenantId }, { _id: 0, passwordHash: 0, onboardToken: 0, __v: 0 }).lean();
    res.json({ ok: true, users });
  } catch (e) { res.status(500).json({ ok: false, error: e.message }); }
});

app.post('/api/tenant/users', adminLimiter, requireAdmin, requireContact, async (req, res) => {
  try {
    const { name, email, idNumber } = req.body;
    if (!name || !email) return res.status(400).json({ ok: false, error: 'שם ואימייל הם שדות חובה' });
    const existing = await User.findOne({ email: email.toLowerCase().trim() }).lean();
    if (existing) return res.status(409).json({ ok: false, error: 'האימייל כבר קיים' });
    const passwordHash = await bcrypt.hash(crypto.randomBytes(32).toString('hex'), 12);
    const user = await User.create({
      id: genId() + genId(), tenantId: req.user.tenantId,
      email: email.toLowerCase().trim(), passwordHash, role: 'admin',
      name: name.trim(), idNumber: (idNumber || '').trim(),
      userStatus: 'active', isContact: false, onboardToken: '',
      createdAt: new Date().toISOString(),
    });
    const { passwordHash: _, onboardToken: __, ...clean } = user.toObject();
    res.json({ ok: true, user: clean });
  } catch (e) { res.status(500).json({ ok: false, error: e.message }); }
});

app.patch('/api/tenant/users/:id/status', adminLimiter, requireAdmin, requireContact, async (req, res) => {
  try {
    const { userStatus } = req.body;
    if (!['active', 'frozen'].includes(userStatus)) return res.status(400).json({ ok: false, error: 'סטטוס לא תקין' });
    const user = await User.findOne({ id: req.params.id, tenantId: req.user.tenantId }).lean();
    if (!user) return res.status(404).json({ ok: false, error: 'לא נמצא' });
    if (user.isContact) return res.status(403).json({ ok: false, error: 'לא ניתן לשנות סטטוס של איש הקשר הראשי' });
    await User.updateOne({ id: req.params.id }, { $set: { userStatus } });
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ ok: false, error: e.message }); }
});

/* ═══ TENANT SETTINGS API ═══ */

app.get('/api/tenant/settings', adminLimiter, requireAdmin, async (req, res) => {
  try {
    const tenant = await Tenant.findOne({ id: req.user.tenantId }, { linkMode: 1, leadVisibility: 1, formEditMode: 1, formMode: 1, _id: 0 }).lean();
    res.json({
      ok: true,
      linkMode:     tenant?.linkMode     || 'shared',
      leadVisibility: tenant?.leadVisibility || 'all',
      formEditMode: tenant?.formEditMode || 'contact',
      formMode:     tenant?.formMode     || 'shared',
    });
  } catch (e) { res.status(500).json({ ok: false, error: e.message }); }
});

app.post('/api/tenant/settings', adminLimiter, requireAdmin, requireContact, async (req, res) => {
  try {
    const { linkMode, leadVisibility, formEditMode, formMode } = req.body;
    const update = {};
    if (['shared', 'perUser'].includes(linkMode))   update.linkMode = linkMode;
    if (['all', 'own'].includes(leadVisibility))     update.leadVisibility = leadVisibility;
    if (['contact', 'all'].includes(formEditMode))  update.formEditMode = formEditMode;
    if (['shared', 'perUser'].includes(formMode))   update.formMode = formMode;
    await Tenant.updateOne({ id: req.user.tenantId }, { $set: update });
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ ok: false, error: e.message }); }
});

/* ═══ FORMS API ═══ */

app.get('/api/forms', adminLimiter, requireAdmin, async (req, res) => {
  try {
    const tid = req.user.tenantId;
    if (tid === '__system__') {
      const forms = await Form.find({}, { _id: 0 }).lean();
      return res.json({ forms });
    }
    // Fetch only this tenant's own forms
    let forms = await Form.find({ tenantId: tid }, { _id: 0 }).lean();
    if (forms.length === 0) {
      // No forms yet — clone defaults (from DB or forms.json) into this tenant
      const defaults = await Form.find({ tenantId: 'default' }, { _id: 0 }).lean();
      if (defaults.length) {
        const clones = defaults.map(f => ({ ...f, id: genId(), tenantId: tid, createdAt: new Date().toISOString(), updatedAt: new Date().toISOString() }));
        await Form.insertMany(clones);
        return res.json({ forms: clones });
      }
      const file = path.join(__dirname, 'forms.json');
      if (fs.existsSync(file)) {
        const { forms: ff } = JSON.parse(fs.readFileSync(file, 'utf8'));
        if (ff?.length) {
          const clones = ff.map(f => ({ ...f, id: genId(), tenantId: tid, createdAt: new Date().toISOString(), updatedAt: new Date().toISOString() }));
          await Form.insertMany(clones);
          return res.json({ forms: clones });
        }
      }
    }
    res.json({ forms });
  } catch (e) { res.status(500).json({ ok: false, error: e.message }); }
});

app.post('/api/forms', adminLimiter, requireAdmin, async (req, res) => {
  try {
    const form = {
      id: genId(), tenantId: req.user.tenantId,
      title: req.body.title || 'טופס חדש',
      description: req.body.description || '',
      questions: req.body.questions || [],
      createdAt: new Date().toISOString(), updatedAt: new Date().toISOString(),
    };
    await Form.create(form);
    res.json({ ok: true, form });
  } catch (e) { res.status(500).json({ ok: false, error: e.message }); }
});

app.put('/api/forms/:id', adminLimiter, requireAdmin, async (req, res) => {
  try {
    if (req.user.tenantId !== '__system__') {
      const tenant = await Tenant.findOne({ id: req.user.tenantId }).lean();
      if (tenant?.formEditMode === 'contact' && !req.user.isContact)
        return res.status(403).json({ ok: false, error: 'רק איש הקשר הראשי יכול לערוך את הטופס' });
    }
    const { title, description, questions } = req.body;
    const update = {
      title:       typeof title       === 'string' ? title.slice(0, 500)       : undefined,
      description: typeof description === 'string' ? description.slice(0, 2000) : undefined,
      questions:   Array.isArray(questions)         ? questions                 : undefined,
      updatedAt:   new Date().toISOString(),
    };
    Object.keys(update).forEach(k => update[k] === undefined && delete update[k]);
    const form = await Form.findOneAndUpdate({ id: req.params.id }, { $set: update }, { new: true, lean: true });
    if (!form) return res.status(404).json({ ok: false, error: 'not found' });
    const { _id, __v, ...clean } = form;
    res.json({ ok: true, form: clean });
  } catch (e) { res.status(500).json({ ok: false, error: e.message }); }
});

app.delete('/api/forms/:id', adminLimiter, requireAdmin, async (req, res) => {
  try {
    const r = await Form.deleteOne({ id: req.params.id });
    if (!r.deletedCount) return res.status(404).json({ ok: false, error: 'not found' });
    await Submission.deleteMany({ formId: req.params.id });
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ ok: false, error: e.message }); }
});

/* ═══ SUBMISSIONS API ═══ */

app.post('/api/submit/:id', publicSubmitLimiter, async (req, res) => {
  try {
    const form = await Form.findOne({ id: req.params.id }).lean();
    if (!form) return res.status(404).json({ ok: false, error: 'form not found' });
    const subDoc = {
      id: genId(), formId: req.params.id, tenantId: form.tenantId || 'default',
      submittedAt: new Date().toISOString(), answers: req.body.answers || {},
      assignedUserId: req.body.uid || '',
    };
    if (req.body.leadId) subDoc.linkedLeadId = req.body.leadId;
    await Submission.create(subDoc);
    if (req.body.leadId) {
      await Submission.findOneAndUpdate(
        { id: req.body.leadId }, { responseReceivedAt: new Date().toISOString() }
      ).catch(() => {});
    }
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ ok: false, error: e.message }); }
});

app.get('/api/submissions/:id', adminLimiter, requireAdmin, async (req, res) => {
  try {
    if (!/^[a-f0-9]{1,32}$/.test(req.params.id))
      return res.status(400).json({ ok: false, error: 'invalid id' });
    const form = await Form.findOne({ id: req.params.id }, { _id: 0 }).lean();
    if (!form) return res.status(404).json({ ok: false, error: 'not found' });
    const submissions = await Submission.find({ formId: req.params.id }, { _id: 0, __v: 0 })
      .sort({ submittedAt: -1 }).lean();
    res.json({ form, submissions });
  } catch (e) { res.status(500).json({ ok: false, error: e.message }); }
});

const SUB_STATUSES = ['נשלח','ממתין לאישור','הוקפאה','נדחה','בוטל','אושר'];
app.patch('/api/submissions/:id/status', adminLimiter, requireAdmin, async (req, res) => {
  try {
    const { status } = req.body;
    if (!SUB_STATUSES.includes(status)) return res.status(400).json({ ok: false, error: 'invalid status' });
    await Submission.findOneAndUpdate({ id: req.params.id }, { $set: { subStatus: status } });
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ ok: false, error: e.message }); }
});

/* ═══ LEADS API ═══ */

app.get('/api/leads', adminLimiter, requireAdmin, async (req, res) => {
  try {
    const tid   = req.user.tenantId;
    const tQuery = tid === '__system__' ? {} : { tenantId: { $in: [tid, 'default'] } };

    const tenant = tid !== '__system__' ? await Tenant.findOne({ id: tid }).lean() : null;
    const ownOnly = tenant && tenant.leadVisibility === 'own';
    const ownFilter = ownOnly ? { assignedUserId: req.user.userId } : {};

    const [forms, leads, linkedSubs] = await Promise.all([
      Form.find({ ...tQuery }, { _id: 0, id: 1, title: 1, questions: 1 }).lean(),
      Submission.find({ formId: { $in: ['__contact__', '__manual__'] }, ...tQuery, ...ownFilter }, { _id: 0, __v: 0 }).sort({ submittedAt: -1 }).lean(),
      Submission.find({ linkedLeadId: { $exists: true }, ...tQuery, ...ownFilter }, { _id: 0, __v: 0 }).sort({ submittedAt: 1 }).lean(),
    ]);

    const formMap = {};
    forms.forEach(f => { formMap[f.id] = f; });
    const linkedByLead = {};
    linkedSubs.forEach(s => {
      const lid = s.linkedLeadId;
      if (!linkedByLead[lid]) linkedByLead[lid] = [];
      linkedByLead[lid].push({ ...s, formTitle: formMap[s.formId]?.title || s.formId, formQuestions: formMap[s.formId]?.questions || [] });
    });

    const result = leads.map(lead => ({
      ...lead,
      formTitle:         lead.formId === '__contact__' ? 'פנייה מדף הנחיתה' : 'ליד ידני',
      formQuestions:     [],
      linkedSubmissions: linkedByLead[lead.id] || []
    }));
    res.json({ leads: result });
  } catch (e) { res.status(500).json({ ok: false, error: e.message }); }
});

app.post('/api/leads/manual', adminLimiter, requireAdmin, async (req, res) => {
  try {
    await Submission.create({
      id: genId(), formId: '__manual__', tenantId: req.user.tenantId,
      submittedAt: new Date().toISOString(), answers: req.body.answers || {},
    });
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ ok: false, error: e.message }); }
});

app.patch('/api/leads/:id/link-sent', adminLimiter, requireAdmin, async (req, res) => {
  try {
    await Submission.findOneAndUpdate(
      { id: req.params.id },
      { linkSentAt: new Date().toISOString(), linkSentFormId: req.body.formId || '' }
    );
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ ok: false, error: e.message }); }
});

app.delete('/api/leads/:id', adminLimiter, requireAdmin, async (req, res) => {
  try {
    const r = await Submission.deleteOne({ id: req.params.id });
    if (!r.deletedCount) return res.status(404).json({ ok: false, error: 'not found' });
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ ok: false, error: e.message }); }
});

/* ═══ PREFILL API ═══ */

app.get('/api/prefill/:token', async (req, res) => {
  try {
    const doc = await Prefill.findOne({ token: req.params.token }).lean();
    if (!doc) return res.status(404).json({ ok: false });
    res.json({ ok: true, answers: doc.answers });
  } catch (e) { res.status(500).json({ ok: false }); }
});

app.post('/api/leads/:leadId/prefill-link', adminLimiter, requireAdmin, async (req, res) => {
  try {
    const { submissionId } = req.body;
    const sub = await Submission.findOne({ id: submissionId }).lean();
    if (!sub) return res.status(404).json({ ok: false, error: 'submission not found' });
    const token = genId() + genId();
    await Prefill.create({ token, answers: sub.answers || {}, leadId: req.params.leadId });
    res.json({ ok: true, url: `/form/${sub.formId}?leadId=${req.params.leadId}&prefill=${token}` });
  } catch (e) { res.status(500).json({ ok: false, error: 'server error' }); }
});

/* ═══ FILE UPLOAD API ═══ */

app.post('/api/form-upload', publicSubmitLimiter, formFileUpload.single('file'), async (req, res) => {
  if (!req.file) return res.status(400).json({ ok: false, error: 'no file' });
  try {
    const fileId = genId() + genId();
    await FileStore.findByIdAndUpdate(
      'file_' + fileId,
      { data: { buf: req.file.buffer.toString('base64'), mime: req.file.mimetype, name: Buffer.from(req.file.originalname, 'latin1').toString('utf8') } },
      { upsert: true }
    );
    res.json({ ok: true, url: `/api/files/${fileId}`, name: req.file.originalname });
  } catch(e) { res.status(500).json({ ok: false, error: e.message }); }
});

app.get('/api/files/:id', async (req, res) => {
  try {
    const doc = await FileStore.findById('file_' + req.params.id).lean();
    if (!doc?.data?.buf) return res.status(404).send('Not found');
    const buf = Buffer.from(doc.data.buf, 'base64');
    res.set('Content-Type', doc.data.mime || 'application/octet-stream');
    res.set('Content-Disposition', `inline; filename="${encodeURIComponent(doc.data.name || 'file')}"`);
    res.send(buf);
  } catch(e) { res.status(500).send('Error'); }
});

/* ═══ SUB-SESSION API ═══ */

app.post('/api/sub-session', publicSubmitLimiter, async (req, res) => {
  try {
    const { mainToken, borrowerNum, formId } = req.body;
    if (!mainToken || !borrowerNum || !formId) return res.status(400).json({ ok: false, error: 'missing fields' });
    if (!/^[a-f0-9]{1,32}$/.test(formId)) return res.status(400).json({ ok: false, error: 'invalid formId' });
    const token = crypto.randomBytes(20).toString('hex');
    await SubSession.create({ token, mainToken, borrowerNum: Number(borrowerNum), formId, createdAt: new Date().toISOString() });
    res.json({ ok: true, token, url: `/sub/${token}` });
  } catch(e) { res.status(500).json({ ok: false, error: 'Internal server error' }); }
});

app.get('/api/sub-status/:mainToken', publicSubmitLimiter, async (req, res) => {
  try {
    const subs = await SubSession.find({ mainToken: req.params.mainToken }).lean();
    res.json({ ok: true, subs: subs.map(s => ({ borrowerNum: s.borrowerNum, status: s.status, answers: s.status === 'complete' ? s.answers : null })) });
  } catch(e) { res.status(500).json({ ok: false, error: 'Internal server error' }); }
});

app.post('/api/sub-submit/:token', publicSubmitLimiter, async (req, res) => {
  try {
    const { answers } = req.body;
    if (!answers || typeof answers !== 'object') return res.status(400).json({ ok: false, error: 'missing answers' });
    const sub = await SubSession.findOne({ token: req.params.token });
    if (!sub) return res.status(404).json({ ok: false, error: 'not found' });
    if (sub.status === 'complete') return res.json({ ok: true, alreadyDone: true });
    sub.answers = answers; sub.status = 'complete';
    await sub.save();
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ ok: false, error: 'Internal server error' }); }
});

app.get('/sub/:token', async (req, res) => {
  try {
    const sub = await SubSession.findOne({ token: req.params.token }).lean();
    if (!sub) return res.status(404).send('<h2 style="font-family:sans-serif;text-align:center;margin-top:100px">הקישור לא תקין</h2>');
    if (sub.status === 'complete') return res.send('<!DOCTYPE html><html lang="he" dir="rtl"><head><meta charset="UTF-8"/><title>תודה</title></head><body style="font-family:sans-serif;text-align:center;margin-top:100px"><h2>תודה! מילאת את הטופס בהצלחה.</h2></body></html>');
    res.redirect(`/form/${sub.formId}?sub=${req.params.token}&bn=${sub.borrowerNum}`);
  } catch(e) { res.status(500).send('Internal server error'); }
});

/* ═══ EMAIL API ═══ */

function getEmailCfg() {
  try { return JSON.parse(fs.readFileSync(EMAIL_CFG_FILE, 'utf8')); } catch { return null; }
}

app.get('/api/email-config', adminLimiter, requireAdmin, (req, res) => {
  const cfg = getEmailCfg();
  if (!cfg) return res.json({ configured: false });
  res.json({ configured: true, host: cfg.host, port: cfg.port, user: cfg.user, fromName: cfg.fromName });
});

app.post('/api/email-config', adminLimiter, requireAdmin, (req, res) => {
  const { host, port, user, pass, fromName } = req.body;
  fs.writeFileSync(EMAIL_CFG_FILE, JSON.stringify({ host, port: Number(port), user, pass, fromName }, null, 2));
  res.json({ ok: true });
});

app.post('/api/send-lead', adminLimiter, requireAdmin, async (req, res) => {
  try {
    const { to, formTitle, submittedAt, fields, attachments } = req.body;
    if (!to || !to.length) return res.status(400).json({ error: 'חסרות כתובות מייל' });
    const cfg = getEmailCfg();
    if (!cfg?.user || !cfg?.pass) return res.status(400).json({ error: 'הגדרות מייל לא הוגדרו' });
    const transporter = nodemailer.createTransport({
      host: cfg.host, port: cfg.port || 587, secure: cfg.port == 465,
      auth: { user: cfg.user, pass: cfg.pass }
    });
    const date = new Date(submittedAt).toLocaleDateString('he-IL', { day:'2-digit', month:'2-digit', year:'numeric', hour:'2-digit', minute:'2-digit' });
    const rows = (fields||[]).map(f => `<tr><td style="padding:9px 14px;font-weight:600;color:#1C3A4A;background:#f5f1eb;border-bottom:1px solid #e8ddd0;width:40%;">${esc(f.question)}</td><td style="padding:9px 14px;border-bottom:1px solid #e8ddd0;">${esc(f.answer)||'—'}</td></tr>`).join('');
    const html = `<div style="font-family:Arial,sans-serif;max-width:620px;margin:0 auto;direction:rtl;text-align:right;"><div style="background:#1C3A4A;padding:22px 24px;border-radius:10px 10px 0 0;"><h2 style="margin:0;color:#C8A96E;font-size:20px;">ליד חדש</h2><div style="color:rgba(245,241,235,.7);font-size:13px;margin-top:4px;">${esc(formTitle)}</div></div><div style="background:#fff;padding:20px 24px;border:1px solid #e8ddd0;border-top:none;"><div style="font-size:12px;color:#aaa;margin-bottom:16px;">התקבל ב: ${esc(date)}</div><table style="width:100%;border-collapse:collapse;">${rows}</table></div></div>`;
    const mailAttachments = [];
    for (const a of (attachments||[])) {
      if (!a.url || !a.name) continue;
      const fp = path.join(__dirname, a.url.startsWith('/') ? a.url.slice(1) : a.url);
      if (fs.existsSync(fp)) mailAttachments.push({ filename: a.name, path: fp });
    }
    await transporter.sendMail({ from: `"${cfg.fromName||'Forms SaaS'}" <${cfg.user}>`, to: to.join(', '), subject: `ליד חדש — ${formTitle}`, html, attachments: mailAttachments });
    res.json({ ok: true });
  } catch (e) { console.error('send-lead error:', e.message); res.status(500).json({ error: 'Internal server error' }); }
});

/* ═══ PUBLIC FORM PAGE ═══ */

app.get('/form/:id', async (req, res) => {
  const form = await Form.findOne({ id: req.params.id }, { _id: 0 }).lean();
  if (!form || form.tenantId === 'default') return res.status(404).send('<h2 style="font-family:sans-serif;text-align:center;margin-top:100px">הטופס לא נמצא</h2>');

  // read site content for branding
  let logoText = 'ייעוץ', logoAccent = 'משכנתאות';
  try {
    const contentDoc = await Content.findById('main').lean();
    const C = contentDoc?.data || {};
    logoText   = C.nav?.logoText   || logoText;
    logoAccent = C.nav?.logoAccent || logoAccent;
  } catch {}

  // Split questions into pages by page_break items
  const allItems = form.questions || [];
  const pages = [[]];
  const pageTitles = [''];
  const pageShowConds = [null];
  const pageRepeatGroups = [null];
  allItems.forEach(q => {
    if (q.type === 'page_break') {
      pages.push([]);
      pageTitles.push(q.title || '');
      pageShowConds.push(q.showCondition || null);
      pageRepeatGroups.push(q.repeatGroup || null);
    } else {
      pages[pages.length - 1].push(q);
    }
  });
  const cleanPages = pages
    .map((p, i) => ({ title: pageTitles[i], questions: p, showCondition: pageShowConds[i] || null, repeatGroup: pageRepeatGroups[i] || null }))
    .filter(p => p.questions.length > 0);
  const safeJson = obj => JSON.stringify(obj)
    .replace(/</g, '\\u003c')
    .replace(/>/g, '\\u003e')
    .replace(/&/g, '\\u0026');
  const pagesJson     = safeJson(cleanPages);
  const questionsJson = safeJson(allItems.filter(q => q.type !== 'page_break'));

  res.send(`<!DOCTYPE html>
<html lang="he" dir="rtl">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>${esc(form.title)} | ${esc(logoText)} ${esc(logoAccent)}</title>
  <link href="https://fonts.googleapis.com/css2?family=Heebo:wght@300;400;500;600;700&family=Fraunces:ital,opsz,wght@0,9..144,400;1,9..144,400&display=swap" rel="stylesheet" />
  <style>
    *,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
    :root{--ocean:#1C3A4A;--gold:#C8A96E;--dg:#A07840;--cream:#F5F1EB;--sand:#E8DDD0;--green:#2E5D4B;--red:#B8624C}
    body{font-family:'Heebo',sans-serif;background:var(--cream);color:#1a2830;direction:rtl;min-height:100vh}
    .nav{background:var(--cream);border-bottom:1px solid rgba(28,58,74,.1);padding:0 24px;height:60px;display:flex;align-items:center;justify-content:space-between;position:sticky;top:0;z-index:10}
    .nav-logo{font-family:'Fraunces','Frank Ruhl Libre',serif;font-size:18px;font-weight:500;color:var(--ocean);text-decoration:none}
    .nav-logo span{color:var(--gold);font-style:italic}
    .progress-wrap{background:rgba(28,58,74,.06);height:5px;width:100%}
    .progress-bar{height:5px;background:linear-gradient(to left,var(--gold),var(--dg));transition:width .5s cubic-bezier(.4,0,.2,1);width:0%}
    .page-dots{display:flex;align-items:center;justify-content:center;gap:8px;padding:16px 0 4px}
    .page-dot{width:28px;height:6px;border-radius:3px;background:rgba(28,58,74,.1);transition:background .3s,width .3s}
    .page-dot.done{background:rgba(200,169,110,.5)}
    .page-dot.active{background:var(--gold);width:36px}
    .page{max-width:640px;margin:0 auto;padding:20px 24px 80px}
    .form-header{margin-bottom:20px;text-align:center}
    .form-badge{display:inline-block;background:rgba(200,169,110,.15);border:1px solid rgba(200,169,110,.4);border-radius:100px;padding:5px 14px;font-size:12px;font-weight:600;color:var(--dg);margin-bottom:16px}
    .form-title{font-family:'Fraunces','Frank Ruhl Libre',serif;font-size:clamp(24px,5vw,38px);font-weight:400;color:var(--ocean);margin-bottom:10px}
    .form-desc{font-size:15px;color:#5a6e7a;line-height:1.65}
    .wizard-step{display:none}
    .wizard-step.active{display:block;animation:stepIn .3s ease both}
    .wizard-step.active.back{animation:stepInBack .3s ease both}
    @keyframes stepIn{from{opacity:0;transform:translateX(-18px)}to{opacity:1;transform:none}}
    @keyframes stepInBack{from{opacity:0;transform:translateX(18px)}to{opacity:1;transform:none}}
    @keyframes stepOut{from{opacity:1;transform:none}to{opacity:0;transform:translateX(18px)}}
    .question-card{background:#fff;border-radius:14px;padding:32px;border:1px solid rgba(28,58,74,.07);box-shadow:0 2px 16px rgba(28,58,74,.05)}
    .q-num{font-size:11px;font-weight:700;letter-spacing:.12em;text-transform:uppercase;color:var(--gold);margin-bottom:10px}
    .q-label{font-size:19px;font-weight:600;color:var(--ocean);line-height:1.35;margin-bottom:6px}
    .q-desc{font-size:13px;color:#7a8e99;margin-bottom:16px;line-height:1.55}
    .req{color:var(--red)}
    .form-input,.form-textarea{width:100%;margin-top:14px;padding:13px 15px;border:1px solid #d8d3ca;border-radius:9px;font-family:'Heebo',sans-serif;font-size:15px;color:#1a2830;background:#faf9f6;direction:rtl;transition:border-color .2s,box-shadow .2s}
    .form-input:focus,.form-textarea:focus{outline:none;border-color:var(--gold);background:#fff;box-shadow:0 0 0 3px rgba(200,169,110,.15)}
    .form-textarea{min-height:120px;resize:vertical}
    .file-upload-wrap{margin-top:14px}
    .file-upload-label{display:flex;align-items:center;gap:10px;padding:14px 18px;border:2px dashed #d8d3ca;border-radius:10px;cursor:pointer;background:#faf9f6;transition:border-color .2s,background .2s;font-family:'Heebo',sans-serif;color:#5a7080;font-size:14px}
    .file-upload-label:hover{border-color:var(--gold);background:#fff}
    .file-upload-label input[type=file]{display:none}
    .file-upload-icon{font-size:22px}
    .file-upload-status{margin-top:8px;font-size:13px;color:#5a7080;padding:6px 10px;background:rgba(28,58,74,.06);border-radius:6px;display:none}
    .file-upload-status.ok{color:#2a7a4e;background:rgba(46,122,78,.1);display:block}
    .file-upload-status.err{color:#c0392b;background:rgba(192,57,43,.1);display:block}
    .file-upload-progress{height:3px;background:var(--gold);border-radius:2px;width:0;transition:width .3s;margin-top:4px}
    .options-group{display:flex;flex-direction:column;gap:10px;margin-top:16px}
    .option-label{display:flex;align-items:center;gap:13px;cursor:pointer;padding:12px 16px;border-radius:9px;border:1.5px solid #e2ddd6;transition:border-color .2s,background .2s,transform .1s;user-select:none}
    .option-label:hover{border-color:rgba(200,169,110,.6);background:rgba(200,169,110,.04);transform:translateX(-2px)}
    .option-label input{display:none}
    .option-box{width:22px;height:22px;border-radius:50%;border:2px solid #c8c0b4;display:flex;align-items:center;justify-content:center;flex-shrink:0;transition:border-color .2s,background .2s}
    .option-box--check{border-radius:6px}
    .option-check{font-size:12px;color:#fff;opacity:0;transition:opacity .15s;font-weight:700}
    .option-label:has(input[type=radio]:checked){border-color:var(--gold);background:rgba(200,169,110,.09)}
    .option-label:has(input[type=radio]:checked) .option-box{border-color:var(--gold);background:var(--gold)}
    .option-label:has(input[type=checkbox]:checked){border-color:var(--gold);background:rgba(200,169,110,.09)}
    .option-label:has(input[type=checkbox]:checked) .option-box--check{border-color:var(--gold);background:var(--gold)}
    .option-label:has(input[type=checkbox]:checked) .option-check{opacity:1}
    .option-text{font-size:15px;color:#2a3c47;font-weight:500}
    .step-nav{display:flex;align-items:center;justify-content:space-between;margin-top:24px;gap:12px}
    .btn-back{background:rgba(28,58,74,.07);color:var(--ocean);border:none;padding:13px 24px;border-radius:8px;font-family:'Heebo',sans-serif;font-size:15px;font-weight:600;cursor:pointer;transition:background .2s;display:flex;align-items:center;gap:6px}
    .btn-back:hover{background:rgba(28,58,74,.13)}
    .btn-back:disabled{opacity:.3;cursor:default}
    .btn-next{background:var(--ocean);color:var(--cream);border:none;padding:13px 32px;border-radius:8px;font-family:'Heebo',sans-serif;font-size:15px;font-weight:700;cursor:pointer;transition:background .2s,transform .15s,box-shadow .2s;display:flex;align-items:center;gap:6px;margin-right:auto}
    .btn-next:hover{background:#2a5570;transform:translateY(-1px);box-shadow:0 6px 20px rgba(28,58,74,.2)}
    .btn-submit-final{background:var(--gold);color:var(--ocean);border:none;padding:14px 40px;border-radius:8px;font-family:'Heebo',sans-serif;font-size:16px;font-weight:700;cursor:pointer;transition:background .2s,transform .15s,box-shadow .2s;display:flex;align-items:center;gap:8px;margin-right:auto}
    .btn-submit-final:hover{background:var(--dg);color:#fff;transform:translateY(-1px);box-shadow:0 8px 24px rgba(160,120,64,.3)}
    .page-section-title{font-family:'Fraunces','Frank Ruhl Libre',serif;font-size:22px;font-weight:400;color:var(--ocean);margin-bottom:20px;padding-bottom:12px;border-bottom:2px solid rgba(200,169,110,.25)}
    .intro-header{font-family:'Fraunces','Frank Ruhl Libre',serif;font-size:28px;font-weight:600;color:var(--ocean);text-align:center;margin-bottom:24px;}
    .branch-hint{font-size:12px;color:rgba(200,169,110,.8);margin-top:12px;display:flex;align-items:center;gap:5px}
    .success-screen{display:none;text-align:center;padding:60px 0;animation:stepIn .4s ease both}
    .success-icon{font-size:72px;margin-bottom:24px}
    .success-title{font-family:'Fraunces',serif;font-size:34px;font-weight:400;color:var(--ocean);margin-bottom:12px}
    .success-sub{font-size:16px;color:#5a6e7a;line-height:1.6}
    .form-id-note{margin-top:48px;font-size:11px;color:#ccc;text-align:center}
    .review-screen{display:none;animation:stepIn .35s ease both}
    .review-section{margin-bottom:28px}
    .review-section-title{font-size:13px;font-weight:700;letter-spacing:.1em;text-transform:uppercase;color:var(--gold);margin-bottom:12px;padding-bottom:8px;border-bottom:1px solid rgba(200,169,110,.2)}
    .review-row{display:flex;align-items:flex-start;justify-content:space-between;gap:12px;padding:10px 0;border-bottom:1px solid rgba(28,58,74,.06)}
    .review-row:last-child{border-bottom:none}
    .review-label{font-size:13px;color:#7a8e99;flex:0 0 44%;text-align:right}
    .review-value{font-size:14px;font-weight:500;color:var(--ocean);flex:1;text-align:right;word-break:break-word}
    .review-value.empty{color:#c0c8cc;font-style:italic}
    .review-edit-btn{background:none;border:none;cursor:pointer;color:var(--gold);font-size:13px;padding:2px 6px;border-radius:4px;flex-shrink:0;white-space:nowrap}
    .review-edit-btn:hover{background:rgba(200,169,110,.12)}
    .review-edit-wrap{display:none;margin-top:6px;width:100%}
    .review-edit-wrap.open{display:block}
    .review-edit-input{width:100%;padding:9px 12px;border:1.5px solid var(--gold);border-radius:8px;font-family:'Heebo',sans-serif;font-size:14px;direction:rtl;outline:none}
    .review-edit-save{margin-top:6px;background:var(--ocean);color:#fff;border:none;padding:7px 18px;border-radius:7px;font-family:'Heebo',sans-serif;font-size:13px;font-weight:700;cursor:pointer}
    .review-submit-bar{position:sticky;bottom:0;background:var(--cream);padding:16px 0 8px;margin-top:24px;text-align:center;border-top:1px solid rgba(28,58,74,.08)}
    .review-back-btn{background:rgba(28,58,74,.07);color:var(--ocean);border:none;padding:11px 22px;border-radius:8px;font-family:'Heebo',sans-serif;font-size:14px;font-weight:600;cursor:pointer;margin-left:12px}
    @keyframes shake{0%,100%{transform:none}20%,60%{transform:translateX(-5px)}40%,80%{transform:translateX(5px)}}
    .shake{animation:shake .35s ease}
    .process-tree{display:none;max-width:640px;margin:0 auto 18px;direction:rtl;font-family:'Heebo',sans-serif}
    .pt-row{display:flex;align-items:flex-start;gap:0;position:relative}
    .pt-group{flex:1;display:flex;flex-direction:column;align-items:center;position:relative}
    .pt-connector{position:absolute;top:11px;left:50%;right:-50%;height:2px;background:rgba(28,58,74,.12);z-index:0;transition:background .3s}
    .pt-group:first-child .pt-connector{display:none}
    .pt-group--done .pt-connector{background:rgba(200,169,110,.5)}
    .pt-group-top{display:flex;flex-direction:column;align-items:center;gap:5px;z-index:1;width:100%}
    .pt-group-num{width:22px;height:22px;border-radius:50%;background:rgba(28,58,74,.1);display:flex;align-items:center;justify-content:center;font-size:11px;font-weight:700;color:rgba(28,58,74,.35);transition:background .3s,color .3s;position:relative;z-index:1}
    .pt-group--active .pt-group-num{background:var(--ocean);color:#fff}
    .pt-group--done .pt-group-num{background:var(--gold);color:#fff}
    .pt-group-label{font-size:11px;font-weight:700;color:rgba(28,58,74,.35);text-align:center;transition:color .3s;white-space:nowrap}
    .pt-group--active .pt-group-label,.pt-group--done .pt-group-label{color:var(--ocean)}
    .pt-steps{display:flex;flex-direction:column;align-items:center;gap:2px;margin-top:6px;width:100%}
    .pt-step{font-size:11px;color:#b0bec5;padding:3px 8px;border-radius:5px;text-align:center;transition:all .2s;white-space:nowrap}
    .pt-step--active{color:var(--ocean);font-weight:700;background:rgba(200,169,110,.12)}
    .pt-step--done{color:#7a9aaa}
  </style>
</head>
<body>
  <nav class="nav">
    <a href="/" class="nav-logo">${esc(logoText)} <span>${esc(logoAccent)}</span></a>
    <div style="display:none" id="navStepLabel"></div>
  </nav>
  <div class="progress-wrap" style="display:none"><div class="progress-bar" id="progressBar"></div></div>

  <div class="page">
    <div class="form-header">
      <div class="form-badge">טופס מקוון</div>
      <h1 class="form-title">${esc(form.title)}</h1>
      ${form.description ? `<p class="form-desc">${esc(form.description)}</p>` : ''}
    </div>
    <div class="page-dots" id="pageDots"></div>
    <div id="processTree" class="process-tree"></div>
    <div id="wizardWrap"></div>
    <div id="reviewScreen" class="review-screen"></div>

    <div class="success-screen" id="successScreen">
      <div class="success-icon">✅</div>
      <div class="success-title">הטופס נשלח בהצלחה!</div>
      <p class="success-sub">תודה רבה על פנייתך.<br>ניצור איתך קשר בהקדם האפשרי.</p>
      <button onclick="window.location.href=window.location.pathname" style="margin-top:28px;background:transparent;border:2px solid var(--gold);color:var(--ocean);padding:10px 28px;border-radius:8px;font-family:'Heebo',sans-serif;font-size:15px;font-weight:600;cursor:pointer;">← שלח פנייה נוספת</button>
    </div>
    <div class="form-id-note">מזהה טופס: ${form.id}</div>
  </div>

<script>
var RAW_PAGES = ${pagesJson};
var ALL_QS    = ${questionsJson};
var FORM_ID   = '${form.id}';

function clonePageForBorrower(page, n) {
  var clone = JSON.parse(JSON.stringify(page));
  clone.title = clone.title.replace(/לווה\\s*1/g, 'לווה ' + n);
  clone.repeatInstance = n;
  clone.questions = clone.questions.map(function(q) {
    var nq = JSON.parse(JSON.stringify(q));
    nq.id = nq.id.split('_b1_').join('_b' + n + '_');
    if (nq.branches) {
      var nb = {};
      Object.keys(nq.branches).forEach(function(k) {
        var v = nq.branches[k];
        if (typeof v === 'string') v = v.split('_b1_').join('_b' + n + '_');
        nb[k] = v;
      });
      nq.branches = nb;
    }
    return nq;
  });
  return clone;
}

function clonePageForLoan(page, n) {
  var clone = JSON.parse(JSON.stringify(page));
  clone.title = 'הלוואה ' + n;
  clone.repeatInstance = n;
  clone.questions = clone.questions.map(function(q) {
    var nq = JSON.parse(JSON.stringify(q));
    nq.id = nq.id.replace(/^ln1_/, 'ln' + n + '_');
    if (nq.branches) {
      var nb = {};
      Object.keys(nq.branches).forEach(function(k) {
        var v = nq.branches[k];
        if (typeof v === 'string') v = v.replace(/^ln1_/, 'ln' + n + '_');
        nb[k] = v;
      });
      nq.branches = nb;
    }
    return nq;
  });
  return clone;
}

function clonePageForMortgage(page, n) {
  var clone = JSON.parse(JSON.stringify(page));
  clone.title = 'משכנתא ' + n;
  clone.repeatInstance = n;
  clone.questions = clone.questions.map(function(q) {
    var nq = JSON.parse(JSON.stringify(q));
    nq.id = nq.id.replace(/^mt1_/, 'mt' + n + '_');
    if (nq.branches) {
      var nb = {};
      Object.keys(nq.branches).forEach(function(k) {
        var v = nq.branches[k];
        if (typeof v === 'string') v = v.replace(/^mt1_/, 'mt' + n + '_');
        nb[k] = v;
      });
      nq.branches = nb;
    }
    return nq;
  });
  return clone;
}

function buildEffectivePages(rawPages, bCount, lnCount, mtCount) {
  var result = [];
  rawPages.forEach(function(page) {
    if (page.repeatGroup === 'borrower') {
      for (var n = 1; n <= Math.max(1, bCount); n++) {
        result.push(clonePageForBorrower(page, n));
      }
    } else if (page.repeatGroup === 'loan') {
      var cnt = Math.max(0, lnCount || 0);
      for (var n = 1; n <= cnt; n++) {
        result.push(clonePageForLoan(page, n));
      }
    } else if (page.repeatGroup === 'mortgage') {
      var mtCnt = Math.max(0, mtCount || 0);
      for (var n = 1; n <= mtCnt; n++) {
        result.push(clonePageForMortgage(page, n));
      }
    } else {
      result.push(page);
    }
  });
  return result;
}

var PAGES = buildEffectivePages(RAW_PAGES, 1, 0, 0);
var PAGE_CONDITIONS = PAGES.map(function(p) { return p.showCondition || null; });
const LEAD_ID      = new URLSearchParams(window.location.search).get('leadId') || '';
const PREFILL_TOKEN = new URLSearchParams(window.location.search).get('prefill') || '';
const UID_PARAM    = new URLSearchParams(window.location.search).get('uid') || '';
const answers = {};
const qById = {};
ALL_QS.forEach(q => qById[q.id] = q);
let pageHistory = [0];
let currentPage = 0;

function classifyPageStep(pageIdx) {
  var page = PAGES[pageIdx];
  if (!page) return null;
  if (pageIdx === 0) return null;
  var title = page.title || '';
  var qIds  = page.questions.map(function(q) { return q.id; });
  var loanTypeIdx = PAGES.findIndex(function(p) {
    return p.questions && p.questions.some(function(q) { return q.id === 'loan_type'; });
  });
  if (loanTypeIdx >= 0 && pageIdx >= loanTypeIdx) {
    if (qIds.indexOf('loan_type') >= 0)                          return { main: 'property', sub: 'loan_type' };
    var propPat  = ['פרטי הנכס', 'הנכס הקיים', 'הנכס החדש'];
    var dealPat  = ['פרטי העסקה', 'מכירת הנכס', 'סוג המחזור', 'פרטי המשכנתא', 'פרטי ההגדלה', 'פרטי ההשקעה', 'נתוני המשכנתא', 'זכאות'];
    var equityPat= ['הון עצמי', 'גורמים מלווים'];
    if (propPat.some(function(k){ return title.indexOf(k)>=0; })) return { main: 'property', sub: 'loan_type' };
    if (equityPat.some(function(k){ return title.indexOf(k)>=0; })) return { main: 'property', sub: 'equity' };
    if (title.indexOf('מסמכים') >= 0)                            return { main: 'property', sub: 'equity' };
    if (dealPat.some(function(k){ return title.indexOf(k)>=0; })) return { main: 'property', sub: 'deal' };
    return { main: 'property', sub: 'deal' };
  }
  if (title.indexOf('ערב') >= 0) return { main: 'borrowers', sub: 'guarantor' };
  var liabPat = ['הלוואות', 'הלוואה', 'משכנתאות', 'משכנתא', 'עיקולים', 'מסמכים והצהרה'];
  if (liabPat.some(function(k){ return title.indexOf(k)>=0; })) return { main: 'borrowers', sub: 'liabilities' };
  return { main: 'borrowers', sub: 'personal' };
}

function renderProcessTree(pageIdx) {
  var tree = document.getElementById('processTree');
  if (!tree) return;
  if (pageIdx === 0) { tree.style.display = 'none'; return; }
  var cur = classifyPageStep(pageIdx);
  if (!cur) { tree.style.display = 'none'; return; }
  var showGuarantor = answers['q_guar_exists'] === 'כן';
  function getStepState(groupId, stepId) {
    var foundActive = false, foundDone = false;
    for (var i = 0; i < PAGES.length; i++) {
      var c = classifyPageStep(i);
      if (!c || c.main !== groupId || c.sub !== stepId) continue;
      if (i === pageIdx) foundActive = true;
      else if (i < pageIdx) foundDone = true;
    }
    if (foundActive) return 'active';
    if (foundDone)   return 'done';
    return 'upcoming';
  }
  var groups = [
    { id: 'borrowers', label: 'פרטי הלווים', num: '01', steps: [
        { id: 'personal', label: 'פרטים אישיים' },
        { id: 'guarantor', label: 'פרטי ערב', hidden: !showGuarantor },
        { id: 'liabilities', label: 'התחייבויות' }
    ]},
    { id: 'property', label: 'פרטי הנכס', num: '02', steps: [
        { id: 'loan_type', label: 'סוג הנכס' },
        { id: 'deal', label: 'פרטי העסקה' },
        { id: 'equity', label: 'הון עצמי ומימון' }
    ]}
  ];
  var html = '<div class="pt-row">';
  groups.forEach(function(group) {
    var isActive = cur.main === group.id;
    var isDone   = (group.id === 'borrowers' && cur.main === 'property');
    var cls = 'pt-group' + (isActive ? ' pt-group--active' : '') + (isDone ? ' pt-group--done' : '');
    html += '<div class="' + cls + '"><div class="pt-connector"></div><div class="pt-group-top">';
    html += '<div class="pt-group-num">' + (isDone ? '✓' : group.num) + '</div>';
    html += '<div class="pt-group-label">' + group.label + '</div></div><div class="pt-steps">';
    group.steps.forEach(function(step) {
      if (step.hidden) return;
      var st = getStepState(group.id, step.id);
      var sc = 'pt-step' + (st === 'active' ? ' pt-step--active' : st === 'done' ? ' pt-step--done' : '');
      html += '<div class="' + sc + '">' + step.label + '</div>';
    });
    html += '</div></div>';
  });
  html += '</div>';
  tree.innerHTML = html;
  tree.style.display = 'block';
  var dots = document.getElementById('pageDots');
  if (dots) dots.style.display = 'none';
}

function start() {
  if (!PAGES.length) { showSuccess(); return; }
  if (SUB_TOKEN && SUB_BORROWER_NUM >= 2) {
    PAGES = PAGES.filter(function(p) {
      var t = p.title || '';
      return t.indexOf('לווה ' + SUB_BORROWER_NUM) !== -1;
    });
    if (!PAGES.length) { document.getElementById('wizardWrap').innerHTML = '<p style="text-align:center;padding:60px;font-family:Heebo,sans-serif">הטופס כבר מולא. תודה!</p>'; return; }
  }
  if (PREFILL_TOKEN) {
    fetch('/api/prefill/' + PREFILL_TOKEN)
      .then(function(r) { return r.json(); })
      .then(function(d) { if (d.ok && d.answers) Object.assign(answers, d.answers); })
      .catch(function() {})
      .finally(function() {
        var loanPage = PAGES.findIndex(function(p) { return p.questions.some(function(q) { return q.id === 'loan_type'; }); });
        var startPage = loanPage >= 0 ? loanPage : 0;
        pageHistory = [startPage];
        renderDots();
        renderPage(startPage);
      });
  } else {
    renderDots();
    renderPage(0);
  }
}

function renderDots() {
  const wrap = document.getElementById('pageDots');
  if (PAGES.length <= 1) { wrap.style.display='none'; return; }
  wrap.style.display = 'none';
  wrap.innerHTML = PAGES.map((_, i) =>
    \`<div class="page-dot \${i===currentPage?'active':i<currentPage?'done':''}" id="dot-\${i}"></div>\`
  ).join('');
}
function updateDots() {
  PAGES.forEach((_, i) => {
    const d = document.getElementById('dot-'+i);
    if (!d) return;
    d.className = 'page-dot ' + (i===currentPage?'active':i<currentPage?'done':'');
  });
}

function getPageInternalTargets(pageQs) {
  const targetMap = {};
  const pageIds = new Set(pageQs.map(q => q.id));
  pageQs.forEach(q => {
    if (!q.branching || !q.branches) return;
    Object.values(q.branches).forEach(raw => {
      const ids = Array.isArray(raw) ? raw : [raw];
      ids.forEach(tId => {
        if (tId && tId !== 'next' && tId !== 'end' && !tId.startsWith('page:') && pageIds.has(tId)) {
          if (!targetMap[tId]) targetMap[tId] = [];
          targetMap[tId].push(q.id);
        }
      });
    });
  });
  return targetMap;
}

function applyInitialVisibility(pageQs, targetMap) {
  Object.keys(targetMap).forEach(tId => {
    const sources = targetMap[tId];
    const shouldShow = sources.some(srcId => {
      const srcQ = qById[srcId];
      const ans = answers['q_'+srcId];
      if (!srcQ || !ans) return false;
      const selected = Array.isArray(ans) ? ans : [ans];
      return selected.some(s => {
        const t = srcQ.branches[s];
        return Array.isArray(t) ? t.includes(tId) : t === tId;
      });
    });
    const el = document.querySelector(\`[data-branch-target="\${tId}"]\`);
    if (el) el.style.display = shouldShow ? '' : 'none';
  });
}

function updateIntraPageBranches(srcQId, selectedVal, pageQs) {
  const q = qById[srcQId];
  if (!q || !q.branching || !q.branches) return;
  const pageIds = new Set(pageQs.map(pq => pq.id));
  const allTargets = Object.values(q.branches).flatMap(t => Array.isArray(t) ? t : [t])
    .filter(t => t && t !== 'next' && t !== 'end' && !t.startsWith('page:') && pageIds.has(t));
  allTargets.forEach(tId => {
    const el = document.querySelector(\`[data-branch-target="\${tId}"]\`);
    if (el) { el.style.display = 'none'; delete answers['q_'+tId]; }
  });
  const target = q.branches[selectedVal];
  if (target) {
    const targets = Array.isArray(target) ? target : [target];
    targets.forEach(tId => {
      if (tId && tId !== 'next' && tId !== 'end' && !tId.startsWith('page:') && pageIds.has(tId)) {
        const el = document.querySelector(\`[data-branch-target="\${tId}"]\`);
        if (el) el.style.display = '';
      }
    });
  }
}

function resolvePageTitle(title) {
  for (var n = 1; n <= 4; n++) {
    var marker = 'לווה ' + n;
    if (title.indexOf(marker) !== -1) {
      var fname = (answers['q_b' + n + '_fname'] || '').trim();
      var lname = (answers['q_b' + n + '_lname'] || '').trim();
      var name  = [fname, lname].filter(Boolean).join(' ');
      if (name) return title.split(marker).join('לווה — ' + name);
    }
  }
  return title;
}

function renderPage(pageIdx, direction) {
  currentPage = pageIdx;
  const page  = PAGES[pageIdx];
  const qs    = page.questions;
  const isLast = pageIdx === PAGES.length - 1;
  const wrap  = document.getElementById('wizardWrap');
  function visiblePages() {
    return PAGES.reduce(function(acc, _, i) {
      var cond = PAGE_CONDITIONS[i];
      if (!cond) return acc + 1;
      var saved = answers['q_' + cond.qId];
      var val   = Array.isArray(saved) ? saved[0] : saved;
      return cond.vals.includes(val) ? acc + 1 : acc;
    }, 0);
  }
  function visiblePageNum(idx) {
    var n = 0;
    for (var i = 0; i <= idx; i++) {
      var cond = PAGE_CONDITIONS[i];
      if (!cond) { n++; continue; }
      var saved = answers['q_' + cond.qId];
      var val   = Array.isArray(saved) ? saved[0] : saved;
      if (cond.vals.includes(val)) n++;
    }
    return n;
  }
  var vTotal = visiblePages();
  var vNum   = visiblePageNum(pageIdx);
  document.getElementById('progressBar').style.width = Math.round((vNum / vTotal) * 100) + '%';
  document.getElementById('navStepLabel').textContent = vTotal > 1 ? \`עמוד \${vNum} מתוך \${vTotal}\` : '';
  updateDots();
  renderProcessTree(pageIdx);
  const internalTargets = getPageInternalTargets(qs);
  const crossPageCond = {};
  ALL_QS.forEach(sq => {
    if (!sq.branching || !sq.branches) return;
    const srcPage = PAGES.findIndex(p => p.questions.some(pq => pq.id === sq.id));
    Object.entries(sq.branches).forEach(([val, targetId]) => {
      const ids = Array.isArray(targetId) ? targetId : [targetId];
      ids.forEach(tId => {
        if (!tId || tId === 'next' || tId === 'end' || tId.startsWith('page:')) return;
        const tgtPage = PAGES.findIndex(p => p.questions.some(pq => pq.id === tId));
        if (tgtPage >= 0 && tgtPage !== srcPage) {
          (crossPageCond[tId] = crossPageCond[tId] || []).push({sourceQId: sq.id, requiredVal: val});
        }
      });
    });
  });
  let qNum = ALL_QS.findIndex(q => q.id === qs[0]?.id) + 1;
  const questionsHtml = qs.map((q, localIdx) => {
    const savedVal = answers['q_'+q.id];
    let inputHtml = '';
    if (q.type === 'text') {
      inputHtml = \`<input type="text" data-qid="\${q.id}" class="form-input q-input" placeholder="הכנס תשובה..." value="\${esc(savedVal||'')}" \${q.required?'required':''} />\`;
    } else if (q.type === 'textarea') {
      inputHtml = \`<textarea data-qid="\${q.id}" class="form-textarea q-input" placeholder="הכנס תשובה..." \${q.required?'required':''}>\${esc(savedVal||'')}</textarea>\`;
    } else if (q.type === 'radio') {
      inputHtml = \`<div class="options-group" data-qid="\${q.id}" data-type="radio">\${(q.options||[]).map(opt=>\`
        <label class="option-label">
          <input type="radio" name="radio_\${q.id}" value="\${esc(opt)}" \${savedVal===opt?'checked':''}
            onchange="onRadioChange('\${q.id}',this.value,\${pageIdx},\${q.branching?'true':'false'})" />
          <span class="option-box"><span class="option-check">✓</span></span>
          <span class="option-text">\${esc(opt)}</span>
        </label>\`).join('')}</div>\`;
    } else if (q.type === 'checkbox') {
      const savedArr = Array.isArray(savedVal)?savedVal:(savedVal?[savedVal]:[]);
      inputHtml = \`<div class="options-group" data-qid="\${q.id}" data-type="checkbox">\${(q.options||[]).map(opt=>\`
        <label class="option-label">
          <input type="checkbox" name="check_\${q.id}" value="\${esc(opt)}" \${savedArr.includes(opt)?'checked':''}
            onchange="onCheckboxChange('\${q.id}',\${pageIdx})"/>
          <span class="option-box option-box--check"><span class="option-check">✓</span></span>
          <span class="option-text">\${esc(opt)}</span>
        </label>\`).join('')}</div>\`;
    } else if (q.type === 'file') {
      const savedFile = savedVal ? JSON.parse(savedVal) : null;
      inputHtml = \`
        <div class="file-upload-wrap" data-qid="\${q.id}">
          <label class="file-upload-label">
            <input type="file" accept=".pdf,.png,.jpg,.jpeg,.doc,.docx" onchange="onFileChange('\${q.id}',this)" />
            <span class="file-upload-icon">📎</span>
            <span class="file-upload-text">בחר קובץ (PDF, PNG, JPG, DOC עד 4MB)</span>
          </label>
          <div class="file-upload-progress" id="fp-\${q.id}"></div>
          <div class="file-upload-status \${savedFile?'ok':''}" id="fs-\${q.id}">\${savedFile?'✔ '+esc(savedFile.name):''}</div>
        </div>\`;
    } else if (q.type === 'date') {
      inputHtml = \`<input type="date" data-qid="\${q.id}" class="form-input q-input" value="\${esc(savedVal||'')}" \${q.required?'required':''} style="max-width:220px;" />\`;
    }
    const isIntraTarget  = !!internalTargets[q.id];
    const crossConds = crossPageCond[q.id];
    const isCrossTarget = !!crossConds;
    const crossCondMet  = isCrossTarget && crossConds.some(c => {
      const saved = answers['q_'+c.sourceQId];
      return Array.isArray(saved) ? saved.includes(c.requiredVal) : saved === c.requiredVal;
    });
    const hideCross = isCrossTarget && !crossCondMet;
    if (hideCross) delete answers['q_'+q.id];
    const isBranchTarget = isIntraTarget || isCrossTarget;
    const num = qNum + localIdx;
    return \`
      <div class="question-card" style="margin-bottom:14px;\${hideCross?'display:none;':''}" data-qi="\${num}"
           \${isBranchTarget ? \`data-branch-target="\${q.id}"\` : ''}>
        <div class="q-label">\${esc(q.label)}\${(q.required && !hideCross)?' <span class="req">*</span>':''}</div>
        \${q.description?\`<div class="q-desc">\${esc(q.description)}</div>\`:''}
        \${inputHtml}
      </div>\`;
  }).join('');
  const resolvedTitle = resolvePageTitle(page.title || '');
  const pageTitle = resolvedTitle ? \`<div class="page-section-title">\${esc(resolvedTitle)}</div>\` : '';
  const introHeader = pageIdx === 0 ? \`<div class="intro-header">רגע לפני שמתחילים</div>\` : '';
  const canBack   = pageHistory.length > 1;
  wrap.innerHTML = \`
    <div class="wizard-step active\${direction==='back'?' back':''}">
      \${introHeader}
      \${pageTitle}
      \${questionsHtml}
      <div class="step-nav">
        <button class="btn-back" onclick="goBack()" \${canBack?'':'disabled'}>→ חזרה</button>
        \${isLast
          ? \`<button class="btn-submit-final" onclick="showReviewScreen()">שלח טופס ✓</button>\`
          : \`<button class="btn-next" onclick="goNextPage(\${pageIdx})">הבא ←</button>\`}
      </div>
    </div>\`;
  applyInitialVisibility(qs, internalTargets);
  window.scrollTo({ top: 0, behavior: 'smooth' });
}

function isQVisible(qId) {
  const card = document.querySelector(\`[data-branch-target="\${qId}"]\`);
  if (!card) return true;
  return card.style.display !== 'none';
}

function collectPageAnswers(pageIdx) {
  const qs = PAGES[pageIdx].questions;
  let valid = true;
  qs.forEach(q => {
    if (!isQVisible(q.id)) return;
    if (q.type === 'text' || q.type === 'textarea' || q.type === 'date') {
      const el = document.querySelector(\`[data-qid="\${q.id}"].q-input\`);
      if (!el) return;
      if (q.required && !el.value.trim()) {
        el.classList.add('shake'); setTimeout(()=>el.classList.remove('shake'),400);
        valid = false; return;
      }
      answers['q_'+q.id] = el.value.trim();
    } else if (q.type === 'radio') {
      const checked = document.querySelector(\`input[name="radio_\${q.id}"]:checked\`);
      if (q.required && !checked) {
        const grp = document.querySelector(\`[data-qid="\${q.id}"].options-group\`);
        if (grp) { grp.classList.add('shake'); setTimeout(()=>grp.classList.remove('shake'),400); }
        valid = false; return;
      }
      answers['q_'+q.id] = checked ? checked.value : '';
    } else if (q.type === 'checkbox') {
      const checked = [...document.querySelectorAll(\`input[name="check_\${q.id}"]:checked\`)].map(i=>i.value);
      if (q.required && !checked.length) {
        const grp = document.querySelector(\`[data-qid="\${q.id}"].options-group\`);
        if (grp) { grp.classList.add('shake'); setTimeout(()=>grp.classList.remove('shake'),400); }
        valid = false; return;
      }
      answers['q_'+q.id] = checked;
    } else if (q.type === 'file') {
      if (q.required && !answers['q_'+q.id]) {
        const wrap = document.querySelector(\`.file-upload-wrap[data-qid="\${q.id}"]\`);
        if (wrap) { wrap.classList.add('shake'); setTimeout(()=>wrap.classList.remove('shake'),400); }
        valid = false;
      }
    }
  });
  return valid;
}

function getBranchTargetPage(q, answerVal) {
  if (!q.branching || !q.branches) return null;
  const target = q.branches[answerVal];
  if (!target || target === 'next') return null;
  if (target === 'end') return 'END';
  if (Array.isArray(target)) return null;
  if (target.startsWith('page:')) {
    const pg = parseInt(target.split(':')[1], 10) - 1;
    return (pg >= 0 && pg < PAGES.length) ? pg : null;
  }
  const pageIdx = PAGES.findIndex(p => p.questions.some(pq => pq.id === target));
  return pageIdx >= 0 ? pageIdx : null;
}

async function onFileChange(qId, input) {
  const file = input.files[0];
  if (!file) return;
  const statusEl = document.getElementById('fs-'+qId);
  const progressEl = document.getElementById('fp-'+qId);
  if (file.size > 4 * 1024 * 1024) {
    statusEl.className = 'file-upload-status err';
    statusEl.textContent = '✖ הקובץ גדול מ-4MB';
    input.value = ''; return;
  }
  const allowed = ['application/pdf','image/png','image/jpeg','application/msword',
    'application/vnd.openxmlformats-officedocument.wordprocessingml.document'];
  if (!allowed.includes(file.type)) {
    statusEl.className = 'file-upload-status err';
    statusEl.textContent = '✖ סוג קובץ לא נתמך';
    input.value = ''; return;
  }
  statusEl.className = 'file-upload-status';
  statusEl.textContent = '⏳ מעלה...';
  progressEl.style.width = '40%';
  try {
    const fd = new FormData();
    fd.append('file', file);
    const res = await fetch('/api/form-upload', { method: 'POST', body: fd });
    const data = await res.json();
    if (!data.ok) throw new Error(data.error);
    progressEl.style.width = '100%';
    setTimeout(() => { progressEl.style.width = '0'; }, 600);
    statusEl.className = 'file-upload-status ok';
    statusEl.textContent = '✔ ' + data.name;
    answers['q_'+qId] = JSON.stringify({ url: data.url, name: data.name });
  } catch(e) {
    progressEl.style.width = '0';
    statusEl.className = 'file-upload-status err';
    statusEl.textContent = '✖ שגיאה בהעלאה: ' + e.message;
  }
}

function onRadioChange(qId, val, pageIdx, hasBranching) {
  answers['q_'+qId] = val;
  const pageQs = PAGES[pageIdx].questions;
  updateIntraPageBranches(qId, val, pageQs);
  const otherQs = pageQs.filter(q => q.id !== qId);
  if (otherQs.length === 0) {
    setTimeout(() => goNextPage(pageIdx), 350);
  } else {
    const allOthersHidden = otherQs.every(q => {
      const el = document.querySelector(\`[data-branch-target="\${q.id}"]\`);
      return el && el.style.display === 'none';
    });
    if (allOthersHidden) setTimeout(() => goNextPage(pageIdx), 350);
  }
}

function onCheckboxChange(qId, pageIdx) {
  const pageQs = PAGES[pageIdx].questions;
  const checked = [...document.querySelectorAll(\`input[name="check_\${qId}"]:checked\`)].map(i=>i.value);
  answers['q_'+qId] = checked;
  checked.forEach(val => updateIntraPageBranches(qId, val, pageQs));
  const q = qById[qId];
  if (!q || !q.branching || !q.branches) return;
  const pageIds = new Set(pageQs.map(pq => pq.id));
  Object.entries(q.branches).forEach(([optVal, tId]) => {
    const ids = Array.isArray(tId) ? tId : [tId];
    ids.forEach(id => {
      if (!id || id === 'next' || id === 'end' || id.startsWith('page:') || !pageIds.has(id)) return;
      if (!checked.includes(optVal)) {
        const el = document.querySelector(\`[data-branch-target="\${id}"]\`);
        if (el) { el.style.display = 'none'; delete answers['q_'+id]; }
      }
    });
  });
}

function goNextPage(pageIdx) {
  if (!collectPageAnswers(pageIdx)) return;
  const qs = PAGES[pageIdx].questions;
  let branchTarget = null;
  for (const q of qs) {
    const ans = answers['q_'+q.id];
    if (!ans) continue;
    const t = getBranchTargetPage(q, Array.isArray(ans)?ans[0]:ans);
    if (t === 'END') { showReviewScreen(); return; }
    if (t !== null) { branchTarget = t; break; }
  }
  let nextPage = branchTarget !== null ? branchTarget : pageIdx + 1;
  while (nextPage < PAGES.length) {
    const cond = PAGE_CONDITIONS[nextPage];
    if (!cond) break;
    const saved = answers['q_' + cond.qId];
    const val   = Array.isArray(saved) ? saved[0] : saved;
    if (cond.vals.includes(val)) break;
    nextPage++;
  }
  // Rebuild pages after page 0 (borrower count now known)
  if (pageIdx === 0) {
    var bCount0 = parseInt(answers['q_b_count'] || answers['b_count'] || '1', 10);
    var lnCount0 = parseInt(answers['q_ln_count'] || '0', 10);
    var mtCount0 = parseInt(answers['q_mt_count'] || '0', 10);
    PAGES = buildEffectivePages(RAW_PAGES, bCount0, lnCount0, mtCount0);
    PAGE_CONDITIONS = PAGES.map(function(p) { return p.showCondition || null; });
    pageHistory = [0];
    // recalculate nextPage after rebuild
    nextPage = branchTarget !== null ? branchTarget : 1;
    while (nextPage < PAGES.length) {
      var cond0 = PAGE_CONDITIONS[nextPage];
      if (!cond0) break;
      var sv0 = answers['q_' + cond0.qId];
      var vl0 = Array.isArray(sv0) ? sv0[0] : sv0;
      if (cond0.vals.includes(vl0)) break;
      nextPage++;
    }
  }
  if (nextPage >= PAGES.length) { showReviewScreen(); return; }
  pageHistory.push(nextPage);
  if (pageIdx === 0 && !SUB_TOKEN) {
    var bCount = parseInt(answers['q_b_count'] || answers['b_count'] || '1', 10);
    for (var bn = 2; bn <= bCount; bn++) {
      if (!shareChoiceMade[bn]) {
        pageHistory.pop();
        showShareInterstitial(bn, nextPage);
        return;
      }
    }
  }
  renderPage(nextPage);
}

function goBack() {
  if (pageHistory.length <= 1) return;
  const curQs = PAGES[currentPage].questions;
  curQs.forEach(q => {
    if (q.type === 'text' || q.type === 'textarea' || q.type === 'date') {
      const el = document.querySelector(\`[data-qid="\${q.id}"].q-input\`);
      if (el) answers['q_'+q.id] = el.value.trim();
    }
  });
  pageHistory.pop();
  const prev = pageHistory[pageHistory.length - 1];
  renderPage(prev, 'back');
}

function showReviewScreen() {
  const lastIdx = PAGES.length - 1;
  collectPageAnswers(lastIdx);
  const container = document.getElementById('reviewScreen');
  const wizard    = document.getElementById('wizardWrap');
  wizard.style.display    = 'none';
  container.style.display = 'block';
  container.className     = 'review-screen';
  void container.offsetWidth;
  let html = '<h2 style="font-family:Fraunces,serif;font-size:24px;color:var(--ocean);margin-bottom:6px;text-align:right">סיכום הטופס</h2>';
  html += '<p style="font-size:13px;color:#8a9ba5;margin-bottom:28px;text-align:right">בדוק את הפרטים לפני השליחה. ניתן ללחוץ על עריכה לתיקון.</p>';
  PAGES.forEach(function(page, pi) {
    var cond = PAGE_CONDITIONS[pi];
    if (cond) {
      var saved = answers['q_' + cond.qId];
      var val   = Array.isArray(saved) ? saved[0] : saved;
      if (!cond.vals.includes(val)) return;
    }
    var rowsHtml = '';
    page.questions.forEach(function(q) {
      if (q.type === 'file') {
        var fdata = answers['q_' + q.id];
        if (!fdata) return;
        try { var f = JSON.parse(fdata); rowsHtml += reviewRow(q, f.name, false); } catch(e) {}
        return;
      }
      var ans = answers['q_' + q.id];
      var display = Array.isArray(ans) ? ans.join(', ') : (ans || '');
      rowsHtml += reviewRow(q, display, q.type !== 'file');
    });
    if (!rowsHtml) return;
    var sectionTitle = resolvePageTitle(page.title || ('עמוד ' + (pi+1)));
    html += '<div class="review-section"><div class="review-section-title">' + esc(sectionTitle) + '</div>' + rowsHtml + '</div>';
  });
  html += '<div class="review-submit-bar"><button class="review-back-btn" onclick="hideReviewScreen()">← חזרה לעריכה</button><button class="btn-submit-final" onclick="submitAllPages()">שלח טופס ✓</button></div>';
  container.innerHTML = html;
  window.scrollTo({ top: 0, behavior: 'smooth' });
}

function reviewRow(q, value, editable) {
  var empty = !value || !value.toString().trim();
  var valueHtml = '<span class="review-value' + (empty ? ' empty' : '') + '" id="rv_' + q.id + '">' + (empty ? '(לא מולא)' : esc(value.toString())) + '</span>';
  var editHtml = '';
  if (editable) {
    var inputHtml = '';
    if (q.type === 'radio') {
      inputHtml = (q.options || []).map(function(opt) {
        return '<label style="display:flex;align-items:center;gap:8px;margin-bottom:6px;cursor:pointer;direction:rtl"><input type="radio" name="re_' + q.id + '" value="' + esc(opt) + '"' + (value === opt ? ' checked' : '') + ' /><span>' + esc(opt) + '</span></label>';
      }).join('');
    } else if (q.type === 'textarea') {
      inputHtml = '<textarea class="review-edit-input" id="re_' + q.id + '" rows="3">' + esc(value) + '</textarea>';
    } else {
      inputHtml = '<input type="text" class="review-edit-input" id="re_' + q.id + '" value="' + esc(value) + '" />';
    }
    editHtml = '<div class="review-edit-wrap" id="rew_' + q.id + '">' + inputHtml + '<button class="review-edit-save" data-qid="' + q.id + '" data-qtype="' + q.type + '" onclick="saveReviewEdit(this.dataset.qid,this.dataset.qtype)">שמור</button></div>';
  }
  return '<div class="review-row"><span class="review-label">' + esc(q.label || '') + '</span><div style="flex:1;text-align:right">' + valueHtml + (editable ? '<br/><button class="review-edit-btn" id="reb_' + q.id + '" data-qid="' + q.id + '" onclick="toggleReviewEdit(this.dataset.qid)">✏️ ערוך</button>' : '') + editHtml + '</div></div>';
}

function toggleReviewEdit(qId) {
  var wrap = document.getElementById('rew_' + qId);
  var btn  = document.getElementById('reb_' + qId);
  var open = wrap.classList.contains('open');
  wrap.classList.toggle('open', !open);
  btn.textContent = open ? '✏️ ערוך' : '✕ סגור';
}

function saveReviewEdit(qId, type) {
  var newVal;
  if (type === 'radio') {
    var checked = document.querySelector('input[name="re_' + qId + '"]:checked');
    newVal = checked ? checked.value : '';
  } else if (type === 'textarea' || type === 'text' || type === 'date') {
    newVal = document.getElementById('re_' + qId).value.trim();
  } else { newVal = ''; }
  answers['q_' + qId] = newVal;
  var span = document.getElementById('rv_' + qId);
  if (span) { span.textContent = newVal || '(לא מולא)'; span.className = 'review-value' + (newVal ? '' : ' empty'); }
  toggleReviewEdit(qId);
}

function hideReviewScreen() {
  document.getElementById('reviewScreen').style.display = 'none';
  var wizard = document.getElementById('wizardWrap');
  wizard.style.display = '';
  renderPage(PAGES.length - 1, 'back');
}

async function submitAllPages() {
  if (SUB_TOKEN) {
    var btn = document.querySelector('.btn-submit-final');
    if (btn) { btn.disabled = true; btn.textContent = '⏳ שולח...'; }
    try {
      var r = await fetch('/api/sub-submit/' + SUB_TOKEN, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ answers: answers }) });
      var d = await r.json();
      if (!d.ok) throw new Error(d.error);
      var titleEl = document.getElementById('successScreen').querySelector('.success-title');
      if (titleEl) titleEl.textContent = 'תודה! הנתונים נשלחו בהצלחה.';
      showSuccess();
    } catch(e) {
      if (btn) { btn.disabled = false; btn.textContent = 'שלח טופס ✓'; }
      alert('אירעה שגיאה. נסה שוב.');
    }
    return;
  }
  if (!collectPageAnswers(currentPage)) return;
  var btn = document.querySelector('.btn-submit-final');
  if (btn) { btn.disabled = true; btn.textContent = '⏳ שולח...'; }
  document.getElementById('progressBar').style.width = '100%';
  try {
    const payload = { answers };
    if (LEAD_ID) payload.leadId = LEAD_ID;
    if (UID_PARAM) payload.uid = UID_PARAM;
    const res = await fetch('/api/submit/'+FORM_ID, { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify(payload) });
    const data = await res.json();
    if (data.ok) { showSuccess(); }
    else throw new Error(data.error);
  } catch(e) {
    if (btn) { btn.disabled=false; btn.textContent='שלח טופס ✓'; }
    alert('אירעה שגיאה. נסה שוב.');
  }
}

function showSuccess() {
  document.getElementById('wizardWrap').style.display    = 'none';
  document.getElementById('reviewScreen').style.display  = 'none';
  document.getElementById('pageDots').style.display      = 'none';
  document.getElementById('successScreen').style.display = 'block';
  document.getElementById('navStepLabel').textContent    = '';
  document.getElementById('progressBar').style.width     = '100%';
  sessionStorage.setItem('formSubmitted_' + FORM_ID, '1');
  window.scrollTo({ top: 0, behavior: 'smooth' });
}

function esc(s){ return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;'); }

window.addEventListener('pageshow', e => { if (e.persisted) { window.location.reload(); } });

var MAIN_TOKEN = (function() {
  var k = 'mainToken_' + FORM_ID;
  var t = sessionStorage.getItem(k);
  if (!t) { t = Math.random().toString(36).slice(2) + Date.now().toString(36); sessionStorage.setItem(k, t); }
  return t;
})();

var SUB_TOKEN = null, SUB_BORROWER_NUM = 0;
(function() {
  var params = new URLSearchParams(window.location.search);
  SUB_TOKEN = params.get('sub') || null;
  SUB_BORROWER_NUM = parseInt(params.get('bn') || '0', 10);
})();

var delegatedBorrowers = {};
var shareChoiceMade = {};
var pollInterval = null;

function startPolling() {
  if (pollInterval) return;
  pollInterval = setInterval(async function() {
    try {
      var r = await fetch('/api/sub-status/' + MAIN_TOKEN);
      var d = await r.json();
      if (!d.ok) return;
      d.subs.forEach(function(s) {
        if (s.status === 'complete' && delegatedBorrowers[s.borrowerNum] !== 'complete') {
          delegatedBorrowers[s.borrowerNum] = 'complete';
          if (s.answers) { Object.keys(s.answers).forEach(function(k) { answers[k] = s.answers[k]; }); }
          showBorrowerCompletedToast(s.borrowerNum);
          updateShareStatusCards();
        }
      });
    } catch(e) {}
  }, 5000);
}

function showBorrowerCompletedToast(num) {
  var name = (answers['q_b' + num + '_fname'] || '') + ' ' + (answers['q_b' + num + '_lname'] || '');
  name = name.trim() || ('לווה ' + num);
  var toast = document.createElement('div');
  toast.style.cssText = 'position:fixed;bottom:24px;right:24px;background:#2E5D4B;color:#fff;padding:14px 20px;border-radius:10px;font-family:Heebo,sans-serif;font-size:15px;z-index:9999;direction:rtl;box-shadow:0 4px 20px rgba(0,0,0,.2);animation:stepIn .3s ease';
  toast.textContent = '✓ ' + name + ' סיים/ה למלא את הנתונים';
  document.body.appendChild(toast);
  setTimeout(function() { toast.remove(); }, 5000);
}

function updateShareStatusCards() {
  Object.keys(delegatedBorrowers).forEach(function(num) {
    var card = document.getElementById('share-status-' + num);
    if (!card) return;
    if (delegatedBorrowers[num] === 'complete') {
      card.innerHTML = '<div style="color:#2E5D4B;font-size:15px;font-weight:600">✓ לווה ' + num + ' סיים למלא את הנתונים שלו</div>';
    }
  });
}

function showShareInterstitial(borrowerNum, targetPageIdx) {
  var wrap = document.getElementById('wizardWrap');
  var name = 'לווה ' + borrowerNum;
  wrap.innerHTML = \`
    <div class="wizard-step active">
      <div class="page-section-title">\${esc(name)} — איך תרצה להמשיך?</div>
      <div style="display:flex;flex-direction:column;gap:14px;margin:24px 0">
        <button class="btn-next" style="width:100%;justify-content:center" onclick="chooseLocalFill(\${borrowerNum},\${targetPageIdx})">✍️ אני אמלא את הנתונים כאן</button>
        <button class="btn-back" style="width:100%;justify-content:center;background:rgba(200,169,110,.15);border:1px solid rgba(200,169,110,.4);color:var(--ocean)" onclick="chooseShareLink(\${borrowerNum},\${targetPageIdx},this)">🔗 שלח קישור ל\${esc(name)} לימלא בעצמו</button>
      </div>
      <div id="share-link-area-\${borrowerNum}" style="display:none;margin-top:8px"></div>
      <div class="step-nav" style="margin-top:24px">
        <button class="btn-back" onclick="goBack()">→ חזרה</button>
        <button class="btn-next" id="share-continue-\${borrowerNum}" style="display:none" onclick="nextShareOrContinue(\${borrowerNum},\${targetPageIdx})">המשך ←</button>
      </div>
    </div>\`;
}

function nextShareOrContinue(borrowerNum, targetPageIdx) {
  var bCount = parseInt(answers['q_b_count'] || answers['b_count'] || '1', 10);
  for (var bn = borrowerNum + 1; bn <= bCount; bn++) {
    if (!shareChoiceMade[bn]) { showShareInterstitial(bn, targetPageIdx); return; }
  }
  pageHistory.push(targetPageIdx);
  renderPage(targetPageIdx);
}

async function chooseLocalFill(borrowerNum, targetPageIdx) {
  shareChoiceMade[borrowerNum] = 'local';
  nextShareOrContinue(borrowerNum, targetPageIdx);
}

async function chooseShareLink(borrowerNum, targetPageIdx, btn) {
  btn.disabled = true; btn.textContent = '⏳ יוצר קישור...';
  try {
    var r = await fetch('/api/sub-session', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ mainToken: MAIN_TOKEN, borrowerNum: borrowerNum, formId: FORM_ID }) });
    var d = await r.json();
    if (!d.ok) throw new Error(d.error);
    shareChoiceMade[borrowerNum] = 'shared';
    delegatedBorrowers[borrowerNum] = 'pending';
    var fullUrl = window.location.origin + d.url;
    var area = document.getElementById('share-link-area-' + borrowerNum);
    area.style.display = 'block';
    area.innerHTML = \`
      <div style="background:rgba(200,169,110,.1);border:1px solid rgba(200,169,110,.35);border-radius:10px;padding:16px;direction:rtl">
        <div style="font-size:13px;color:#5a6e7a;margin-bottom:8px">שלח את הקישור הבא ללווה \${borrowerNum}:</div>
        <div style="display:flex;gap:8px;align-items:center">
          <input id="sub-link-\${borrowerNum}" type="text" value="\${esc(fullUrl)}" readonly style="flex:1;padding:9px 12px;border:1px solid #d8d3ca;border-radius:7px;font-size:13px;direction:ltr;background:#fff;outline:none"/>
          <button onclick="copySubLink(\${borrowerNum})" style="background:var(--ocean);color:#fff;border:none;padding:9px 16px;border-radius:7px;font-family:Heebo,sans-serif;font-size:13px;cursor:pointer">העתק</button>
        </div>
        <div id="share-status-\${borrowerNum}" style="margin-top:10px;font-size:13px;color:#8a9ba5">⏳ ממתין ללווה \${borrowerNum} למלא את הנתונים...</div>
      </div>\`;
    document.getElementById('share-continue-' + borrowerNum).style.display = 'flex';
    startPolling();
  } catch(e) {
    btn.disabled = false;
    btn.textContent = '🔗 שלח קישור ללווה ' + borrowerNum + ' לימלא בעצמו';
    alert('שגיאה ביצירת הקישור. נסה שוב.');
  }
}

function copySubLink(borrowerNum) {
  var inp = document.getElementById('sub-link-' + borrowerNum);
  inp.select();
  navigator.clipboard.writeText(inp.value).then(function() {
    var btn = inp.nextElementSibling;
    btn.textContent = '✓ הועתק';
    setTimeout(function() { btn.textContent = 'העתק'; }, 2000);
  });
}

start();
</script>
</body>
</html>`);
});

if (require.main === module) {
  app.listen(PORT, () => console.log(`✓  http://localhost:${PORT}  |  admin: http://localhost:${PORT}/admin.html  |  super-admin: http://localhost:${PORT}/super-admin`));
}

module.exports = app;
