const express  = require('express');
const cors     = require('cors');
const bcrypt   = require('bcryptjs');
const jwt      = require('jsonwebtoken');
const { Pool } = require('pg');

const app = express();
app.set('trust proxy', 1);

app.use(cors({ origin: true, credentials: true }));
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));

// ── DATABASE ──────────────────────────────────────
let _pool = null;
function getPool() {
  if (!_pool) {
    _pool = new Pool({
      connectionString: process.env.DATABASE_URL,
      ssl: { rejectUnauthorized: false },
      max: 1,
      idleTimeoutMillis: 10000,
      connectionTimeoutMillis: 10000
    });
  }
  return _pool;
}
async function db(sql, params) {
  return getPool().query(sql, params);
}

// ── JWT ───────────────────────────────────────────
const JWT  = process.env.JWT_SECRET          || 'paype2026secret';
const JREF = process.env.JWT_REFRESH_SECRET  || 'paype2026refresh';

function makeTokens(userId, role) {
  return {
    access:  jwt.sign({ userId, role }, JWT,  { expiresIn: '7d' }),
    refresh: jwt.sign({ userId },       JREF, { expiresIn: '30d' })
  };
}

async function auth(req, res, next) {
  try {
    const h = req.headers.authorization;
    if (!h || !h.startsWith('Bearer ')) {
      return res.status(401).json({ success: false, message: 'No token' });
    }
    const d = jwt.verify(h.split(' ')[1], JWT);
    const r = await db(
      `SELECT u.id, u.username, u.role, u.is_active, u.employee_id,
              e.first_name, e.last_name, e.work_email
       FROM users u
       LEFT JOIN employees e ON e.id = u.employee_id
       WHERE u.id = $1`, [d.userId]
    );
    if (!r.rows.length || !r.rows[0].is_active) {
      return res.status(401).json({ success: false, message: 'Unauthorized' });
    }
    req.user = r.rows[0];
    next();
  } catch (e) {
    if (e.name === 'TokenExpiredError') {
      return res.status(401).json({ success: false, message: 'Token expired', code: 'TOKEN_EXPIRED' });
    }
    return res.status(401).json({ success: false, message: 'Invalid token' });
  }
}

function canHR(req, res, next) {
  if (!['admin', 'hr', 'manager'].includes(req.user.role)) {
    return res.status(403).json({ success: false, message: 'HR access required' });
  }
  next();
}

// ═══════════════════════════════
//  ROUTES
// ═══════════════════════════════

// Root
app.get('/', (req, res) => {
  res.json({
    success: true,
    message: '🚀 PayPe HRMS API',
    version: '1.0.0',
    company: 'PayPe Technologies Pvt. Ltd.',
    domain:  'hr.paype.co.in',
    links: {
      health: '/api/health',
      docs:   '/api/docs',
      login:  'POST /api/auth/login'
    }
  });
});

// Health
app.get('/api/health', async (req, res) => {
  let dbStatus = 'not configured';
  if (process.env.DATABASE_URL) {
    try {
      await db('SELECT 1');
      dbStatus = 'connected ✅';
      // Auto-migrate missing columns
      const migrations = [
        // Attendance location
        'ALTER TABLE attendance ADD COLUMN IF NOT EXISTS latitude_in NUMERIC(10,7)',
        'ALTER TABLE attendance ADD COLUMN IF NOT EXISTS longitude_in NUMERIC(10,7)',
        'ALTER TABLE attendance ADD COLUMN IF NOT EXISTS accuracy_in NUMERIC',
        'ALTER TABLE attendance ADD COLUMN IF NOT EXISTS distance_in INTEGER',
        'ALTER TABLE attendance ADD COLUMN IF NOT EXISTS location_in TEXT',
        'ALTER TABLE attendance ADD COLUMN IF NOT EXISTS latitude_out NUMERIC(10,7)',
        'ALTER TABLE attendance ADD COLUMN IF NOT EXISTS longitude_out NUMERIC(10,7)',
        'ALTER TABLE attendance ADD COLUMN IF NOT EXISTS distance_out INTEGER',
        'ALTER TABLE attendance ADD COLUMN IF NOT EXISTS location_out TEXT',
        // Employee columns
        'ALTER TABLE employees ADD COLUMN IF NOT EXISTS designation VARCHAR(200)',
        'ALTER TABLE employees ADD COLUMN IF NOT EXISTS work_location VARCHAR(200)',
        'ALTER TABLE employees ADD COLUMN IF NOT EXISTS blood_group VARCHAR(10)',
        'ALTER TABLE employees ADD COLUMN IF NOT EXISTS gender VARCHAR(20)',
        'ALTER TABLE employees ADD COLUMN IF NOT EXISTS marital_status VARCHAR(20)',
        'ALTER TABLE employees ADD COLUMN IF NOT EXISTS address TEXT',
        'ALTER TABLE employees ADD COLUMN IF NOT EXISTS emergency_contact VARCHAR(200)',
        'ALTER TABLE employees ADD COLUMN IF NOT EXISTS aadhaar_number VARCHAR(20)',
        'ALTER TABLE employees ADD COLUMN IF NOT EXISTS pan_number VARCHAR(20)',
        'ALTER TABLE employees ADD COLUMN IF NOT EXISTS bank_name VARCHAR(100)',
        'ALTER TABLE employees ADD COLUMN IF NOT EXISTS account_number VARCHAR(50)',
        'ALTER TABLE employees ADD COLUMN IF NOT EXISTS ifsc_code VARCHAR(20)',
        'ALTER TABLE employees ADD COLUMN IF NOT EXISTS bank_branch VARCHAR(100)',
        'ALTER TABLE employees ADD COLUMN IF NOT EXISTS date_of_birth DATE',
        'ALTER TABLE employees ADD COLUMN IF NOT EXISTS personal_email VARCHAR(200)',
        'ALTER TABLE employees ADD COLUMN IF NOT EXISTS alternate_mobile VARCHAR(20)',
        "ALTER TABLE employees ADD COLUMN IF NOT EXISTS employment_status VARCHAR(30) DEFAULT 'Active'",
        'ALTER TABLE employees ADD COLUMN IF NOT EXISTS date_of_joining DATE',
        'ALTER TABLE employees ADD COLUMN IF NOT EXISTS annual_ctc NUMERIC DEFAULT 0',
        'ALTER TABLE employees ADD COLUMN IF NOT EXISTS photo_url TEXT'
      ];
      for (const sql of migrations) {
        try { await db(sql); } catch(e2) {}
      }
    } catch (e) {
      dbStatus = 'error: ' + e.message;
    }
  }
  res.json({
    success: true,
    status:  'healthy',
    service: 'PayPe HRMS API',
    version: '1.0.0',
    domain:  'hr.paype.co.in',
    db:      dbStatus,
    time:    new Date().toISOString()
  });
});

// Docs
app.get('/api/docs', (req, res) => {
  res.json({
    name:    'PayPe HRMS API',
    version: '1.0.0',
    base:    'https://hr.paype.co.in/api',
    auth:    'Authorization: Bearer <token>',
    routes: {
      'POST /api/auth/login':                    'Login',
      'POST /api/auth/refresh':                  'Refresh token',
      'POST /api/auth/logout':                   'Logout',
      'GET  /api/auth/me':                       'My profile (auth)',
      'GET  /api/dashboard/stats':               'KPIs (auth)',
      'GET  /api/employees':                     'List employees (HR)',
      'POST /api/employees':                     'Add employee (HR)',
      'GET  /api/employees/:id':                 'Get employee (auth)',
      'PUT  /api/employees/:id':                 'Update employee (HR)',
      'GET  /api/departments':                   'Departments (auth)',
      'POST /api/attendance/punch':              'Punch in/out (auth)',
      'GET  /api/attendance/today':              'Today log (HR)',
      'GET  /api/attendance/my':                 'My attendance (auth)',
      'GET  /api/leave/policies':                'Leave policies (auth)',
      'GET  /api/leave/balances/my':             'My balance (auth)',
      'POST /api/leave/apply':                   'Apply leave (auth)',
      'GET  /api/leave/requests':                'All requests (HR)',
      'POST /api/leave/requests/:id/approve':    'Approve/Reject (HR)',
      'POST /api/payroll/calculate':             'Salary preview (auth)',
      'POST /api/payroll/run':                   'Run payroll (HR)',
      'GET  /api/payroll/payslip/my/:m/:y':      'My payslip (auth)'
    }
  });
});

// ── AUTH ──────────────────────────────────────────

app.post('/api/auth/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) {
      return res.status(400).json({ success: false, message: 'Username and password required' });
    }
    const r = await db(
      `SELECT u.id, u.password_hash, u.role, u.is_active, u.employee_id,
              e.first_name, e.last_name, e.work_email, e.photo_url,
              e.employee_id AS emp_code, e.work_location,
              d.name AS department_name, des.title AS designation
       FROM users u
       LEFT JOIN employees e   ON e.id  = u.employee_id
       LEFT JOIN departments d ON d.id  = e.department_id
       LEFT JOIN designations des ON des.id = e.designation_id
       WHERE LOWER(u.username) = LOWER($1)`,
      [username.trim()]
    );
    if (!r.rows.length) {
      return res.status(401).json({ success: false, message: 'Invalid credentials' });
    }
    const u = r.rows[0];
    if (!u.is_active) {
      return res.status(401).json({ success: false, message: 'Account deactivated. Contact HR.' });
    }
    const ok = await bcrypt.compare(password, u.password_hash);
    if (!ok) {
      return res.status(401).json({ success: false, message: 'Invalid credentials' });
    }
    const { access, refresh } = makeTokens(u.id, u.role);
    const exp = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000);
    await db(`DELETE FROM refresh_tokens WHERE user_id = $1 AND expires_at < NOW()`, [u.id]);
    await db(
      `INSERT INTO refresh_tokens (id, user_id, token, expires_at)
       VALUES (gen_random_uuid(), $1, $2, $3)`,
      [u.id, refresh, exp]
    );
    await db(`UPDATE users SET last_login = NOW() WHERE id = $1`, [u.id]);
    return res.json({
      success: true,
      message: 'Login successful',
      data: {
        accessToken:  access,
        refreshToken: refresh,
        user: {
          id:           u.id,
          employeeId:   u.employee_id,
          empCode:      u.emp_code,
          firstName:    u.first_name,
          lastName:     u.last_name,
          fullName:     `${u.first_name} ${u.last_name}`,
          email:        u.work_email,
          role:         u.role,
          department:   u.department_name,
          designation:  u.designation,
          location:     u.work_location,
          photoUrl:     u.photo_url
        }
      }
    });
  } catch (e) {
    console.error('Login error:', e.message);
    return res.status(500).json({ success: false, message: e.message });
  }
});

app.post('/api/auth/refresh', async (req, res) => {
  try {
    const { refreshToken } = req.body;
    if (!refreshToken) return res.status(400).json({ success: false, message: 'Refresh token required' });
    const d = jwt.verify(refreshToken, JREF);
    const s = await db(
      `SELECT * FROM refresh_tokens WHERE token = $1 AND user_id = $2 AND expires_at > NOW()`,
      [refreshToken, d.userId]
    );
    if (!s.rows.length) return res.status(401).json({ success: false, message: 'Invalid or expired token' });
    const u = await db(`SELECT id, role FROM users WHERE id = $1`, [d.userId]);
    if (!u.rows.length) return res.status(401).json({ success: false, message: 'User not found' });
    const { access, refresh: newR } = makeTokens(d.userId, u.rows[0].role);
    await db(`DELETE FROM refresh_tokens WHERE token = $1`, [refreshToken]);
    const exp = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000);
    await db(`INSERT INTO refresh_tokens (id,user_id,token,expires_at) VALUES (gen_random_uuid(),$1,$2,$3)`,
      [d.userId, newR, exp]);
    return res.json({ success: true, data: { accessToken: access, refreshToken: newR } });
  } catch (e) {
    return res.status(401).json({ success: false, message: 'Invalid token' });
  }
});

app.post('/api/auth/logout', async (req, res) => {
  try {
    if (req.body.refreshToken) {
      await db(`DELETE FROM refresh_tokens WHERE token = $1`, [req.body.refreshToken]);
    }
    return res.json({ success: true, message: 'Logged out' });
  } catch (e) {
    return res.status(500).json({ success: false, message: e.message });
  }
});

app.get('/api/auth/me', auth, (req, res) => {
  res.json({ success: true, data: req.user });
});

app.post('/api/auth/change-password', auth, async (req, res) => {
  try {
    const { currentPassword, newPassword } = req.body;
    if (!currentPassword || !newPassword || newPassword.length < 8) {
      return res.status(400).json({ success: false, message: 'Valid passwords required (min 8 chars)' });
    }
    const r = await db(`SELECT password_hash FROM users WHERE id = $1`, [req.user.id]);
    const ok = await bcrypt.compare(currentPassword, r.rows[0].password_hash);
    if (!ok) return res.status(400).json({ success: false, message: 'Current password incorrect' });
    const hash = await bcrypt.hash(newPassword, 12);
    await db(`UPDATE users SET password_hash = $1 WHERE id = $2`, [hash, req.user.id]);
    await db(`DELETE FROM refresh_tokens WHERE user_id = $1`, [req.user.id]);
    return res.json({ success: true, message: 'Password changed. Please login again.' });
  } catch (e) {
    return res.status(500).json({ success: false, message: e.message });
  }
});

// ── DASHBOARD ─────────────────────────────────────

app.get('/api/dashboard/stats', auth, async (req, res) => {
  try {
    const today = new Date().toISOString().slice(0, 10);
    const [emp, att, lv, pend, pay, depts] = await Promise.all([
      db(`SELECT status, COUNT(*) c FROM employees GROUP BY status`),
      db(`SELECT COUNT(*) c FROM attendance WHERE date=$1 AND status='Present'`, [today]),
      db(`SELECT COUNT(*) c FROM leave_requests WHERE status='Approved' AND $1::date BETWEEN from_date AND to_date`, [today]),
      db(`SELECT COUNT(*) c FROM leave_requests WHERE status='Pending'`),
      db(`SELECT * FROM payroll_runs WHERE status='Processed' ORDER BY year DESC, month DESC LIMIT 1`),
      db(`SELECT d.name, COUNT(e.id) c FROM departments d LEFT JOIN employees e ON e.department_id=d.id AND e.status='Active' GROUP BY d.id,d.name ORDER BY c DESC`)
    ]);
    const byS = {};
    emp.rows.forEach(r => { byS[r.status] = parseInt(r.c); });
    const total = Object.values(byS).reduce((a, b) => a + b, 0);
    res.json({
      success: true,
      data: {
        employees: { total, active: byS.Active||0, probation: byS.Probation||0, notice: byS['Notice Period']||0 },
        attendance: { present: parseInt(att.rows[0]?.c||0), onLeave: parseInt(lv.rows[0]?.c||0) },
        leave: { pendingApprovals: parseInt(pend.rows[0]?.c||0) },
        payroll: pay.rows[0] || null,
        departmentStats: depts.rows
      }
    });
  } catch (e) {
    res.status(500).json({ success: false, message: e.message });
  }
});

// ── EMPLOYEES ─────────────────────────────────────

app.get('/api/employees', auth, canHR, async (req, res) => {
  try {
    const { department, status, search, page = 1, limit = 20 } = req.query;
    const conds = [], params = [];
    if (department) { params.push(department); conds.push(`e.department_id=$${params.length}`); }
    if (status)     { params.push(status);     conds.push(`e.status=$${params.length}`); }
    if (search) {
      params.push(`%${search}%`);
      conds.push(`(e.first_name ILIKE $${params.length} OR e.last_name ILIKE $${params.length} OR e.work_email ILIKE $${params.length} OR e.employee_id ILIKE $${params.length})`);
    }
    const where = conds.length ? 'WHERE ' + conds.join(' AND ') : '';
    const off = (parseInt(page) - 1) * parseInt(limit);
    params.push(parseInt(limit), off);
    const [data, cnt] = await Promise.all([
      db(`SELECT e.id, e.employee_id, e.first_name, e.last_name,
                 e.first_name||' '||e.last_name AS full_name,
                 e.work_email, e.mobile, e.work_location,
                 e.employment_type, e.date_of_joining, e.status, e.photo_url,
                 d.name AS department_name, des.title AS designation
          FROM employees e
          LEFT JOIN departments d   ON d.id  = e.department_id
          LEFT JOIN designations des ON des.id = e.designation_id
          ${where} ORDER BY e.date_of_joining DESC
          LIMIT $${params.length-1} OFFSET $${params.length}`, params),
      db(`SELECT COUNT(*) c FROM employees e ${where}`, params.slice(0, -2))
    ]);
    res.json({
      success: true,
      data: {
        employees: data.rows,
        pagination: { total: parseInt(cnt.rows[0].c), page: parseInt(page), limit: parseInt(limit) }
      }
    });
  } catch (e) {
    res.status(500).json({ success: false, message: e.message });
  }
});

app.get('/api/employees/stats', auth, canHR, async (req, res) => {
  try {
    const [byStatus, byDept, recent] = await Promise.all([
      db(`SELECT status, COUNT(*) c FROM employees GROUP BY status ORDER BY c DESC`),
      db(`SELECT d.name, COUNT(e.id) c FROM departments d LEFT JOIN employees e ON e.department_id=d.id GROUP BY d.id,d.name ORDER BY c DESC`),
      db(`SELECT first_name, last_name, employee_id, date_of_joining FROM employees ORDER BY date_of_joining DESC LIMIT 5`)
    ]);
    const total = byStatus.rows.reduce((a, r) => a + parseInt(r.c), 0);
    res.json({ success: true, data: { total, byStatus: byStatus.rows, byDepartment: byDept.rows, recentJoiners: recent.rows } });
  } catch (e) {
    res.status(500).json({ success: false, message: e.message });
  }
});

app.get('/api/employees/:id', auth, async (req, res) => {
  try {
    const r = await db(
      `SELECT e.*, d.name AS department_name
       FROM employees e
       LEFT JOIN departments d ON d.id=e.department_id
       WHERE e.id=$1`, [req.params.id]
    );
    if (!r.rows.length) return res.status(404).json({ success: false, message: 'Employee not found' });
    res.json({ success: true, data: r.rows[0] });
  } catch(e) { res.status(500).json({ success: false, message: e.message }); }
});


app.post('/api/employees', auth, canHR, async (req, res) => {
  try {
    const { firstName, lastName, workEmail, mobile, departmentId, designationId, workLocation, dateOfJoining, employmentType, annualCtc } = req.body;
    if (!firstName || !lastName || !workEmail || !mobile) {
      return res.status(400).json({ success: false, message: 'firstName, lastName, workEmail, mobile required' });
    }
    const cnt = await db(`SELECT COUNT(*) c FROM employees`);
    const empCode = 'PPC' + String(parseInt(cnt.rows[0].c) + 1).padStart(3, '0');
    const r = await db(
      `INSERT INTO employees (id,employee_id,first_name,last_name,work_email,mobile,department_id,designation_id,work_location,employment_type,date_of_joining,created_by)
       VALUES (gen_random_uuid(),$1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
       RETURNING id, employee_id, first_name, last_name, work_email`,
      [empCode, firstName, lastName, workEmail.toLowerCase(), mobile, departmentId||null, designationId||null, workLocation||null, employmentType||'Full-Time', dateOfJoining||null, req.user.id]
    );
    const empId = r.rows[0].id;
    const tempPass = firstName.toLowerCase() + new Date().getFullYear();
    const hash = await bcrypt.hash(tempPass, 12);
    await db(`INSERT INTO users (id,employee_id,username,password_hash,role) VALUES (gen_random_uuid(),$1,$2,$3,'employee')`,
      [empId, workEmail.toLowerCase(), hash]);
    if (annualCtc) {
      const gm = annualCtc / 12, basic = gm * 0.5, hra = basic * 0.5, rem = gm - basic - hra;
      const spl = rem * 0.5, conv = rem * 0.5, pfe = basic * 0.12, pfer = basic * 0.0425;
      const esic = gm <= 21000 ? gm * 0.0075 : 0, net = gm - pfe - esic;
      await db(`INSERT INTO salary_structures (id,employee_id,effective_from,annual_ctc,basic,hra,special_allowance,conveyance,pf_employee,pf_employer,esic_employee,net_salary,is_active)
                VALUES (gen_random_uuid(),$1,NOW(),$2,$3,$4,$5,$6,$7,$8,$9,$10,true)`,
        [empId, annualCtc, basic.toFixed(2), hra.toFixed(2), spl.toFixed(2), conv.toFixed(2), pfe.toFixed(2), pfer.toFixed(2), esic.toFixed(2), net.toFixed(2)]);
    }
    res.status(201).json({ success: true, message: `Employee ${empCode} created. Temp password: ${tempPass}`, data: r.rows[0] });
  } catch (e) {
    if (e.code === '23505') return res.status(409).json({ success: false, message: 'Email already exists' });
    res.status(500).json({ success: false, message: e.message });
  }
});

app.put('/api/employees/:id', auth, async (req, res) => {
  try {
    // Allow employee to update own profile only; HR/Admin can update anyone
    if (req.user.role === 'employee') {
      const empCheck = await db('SELECT id FROM employees WHERE id=(SELECT employee_id FROM users WHERE id=$1)', [req.user.userId]);
      if (!empCheck.rows.length || empCheck.rows[0].id !== req.params.id) {
        return res.status(403).json({ success: false, message: 'Access denied' });
      }
    }
    const map = {
      firstName:'first_name', lastName:'last_name', mobile:'mobile',
      workLocation:'work_location', bloodGroup:'blood_group',
      departmentId:'department_id', designation:'designation',
      dateOfJoining:'date_of_joining', workEmail:'work_email',
      employmentStatus:'employment_status', gender:'gender',
      maritalStatus:'marital_status', address:'address',
      emergencyContact:'emergency_contact',
      aadhaarNumber:'aadhaar_number', panNumber:'pan_number',
      bankName:'bank_name', accountNumber:'account_number',
      ifscCode:'ifsc_code', bankBranch:'bank_branch',
      dateOfBirth:'date_of_birth', personalEmail:'personal_email',
      alternateMobile:'alternate_mobile', annualCtc:'annual_ctc',
      photoUrl:'photo_url'
    };
    const sets = [], params = [];
    for (const [k, v] of Object.entries(req.body)) {
      const col = map[k];
      if (col && v !== undefined && v !== '') {
        params.push(v);
        sets.push(col + '=$' + params.length);
      }
    }
    if (!sets.length) return res.status(400).json({ success: false, message: 'No valid fields to update' });
    params.push(req.params.id);
    const sql = 'UPDATE employees SET ' + sets.join(', ') + ' WHERE id=$' + params.length;
    console.log('Update SQL:', sql, params);
    await db(sql, params);
    // Return updated employee
    const updated = await db('SELECT * FROM employees WHERE id=$1', [req.params.id]);
    res.json({ success: true, message: 'Employee updated successfully!', data: updated.rows[0] });
  } catch (e) {
    console.error('PUT employee error:', e.message);
    res.status(500).json({ success: false, message: e.message });
  }
});

// ── DEPARTMENTS & DESIGNATIONS ────────────────────

app.get('/api/departments', auth, async (req, res) => {
  try {
    const r = await db(`SELECT * FROM departments ORDER BY name`);
    res.json({ success: true, data: r.rows });
  } catch (e) { res.status(500).json({ success: false, message: e.message }); }
});

app.get('/api/designations', auth, async (req, res) => {
  try {
    const { departmentId } = req.query;
    const r = departmentId
      ? await db(`SELECT * FROM designations WHERE department_id=$1 ORDER BY title`, [departmentId])
      : await db(`SELECT * FROM designations ORDER BY title`);
    res.json({ success: true, data: r.rows });
  } catch (e) { res.status(500).json({ success: false, message: e.message }); }
});

// ── ATTENDANCE ────────────────────────────────────

app.post('/api/attendance/punch', auth, async (req, res) => {
  try {
    const today = new Date().toISOString().slice(0, 10);
    const { latitude, longitude, accuracy, distance, address } = req.body;
    const locationJson = latitude ? JSON.stringify({lat:latitude,lng:longitude,acc:accuracy,dist:distance,addr:address}) : null;
    
    // Get employee id from user
    const userEmp = await db('SELECT employee_id FROM users WHERE id=$1', [req.user.userId]);
    const empId = userEmp.rows[0]?.employee_id;
    if (!empId) return res.status(400).json({ success: false, message: 'Employee profile not linked' });

    const ex = await db(`SELECT * FROM attendance WHERE employee_id=$1 AND DATE(punch_in)=$2`, [empId, today]);
    
    if (!ex.rows.length) {
      // Punch In
      await db(`INSERT INTO attendance (employee_id, punch_in, latitude_in, longitude_in, accuracy_in, distance_in, location_in)
        VALUES ($1, NOW(), $2, $3, $4, $5, $6)`,
        [empId, latitude||null, longitude||null, accuracy||null, distance||null, locationJson]);
      res.json({ success: true, message: 'Punched In successfully!' });
    } else {
      var rec = ex.rows[0];
      if (rec.punch_out) return res.status(400).json({ success: false, message: 'Already punched out today' });
      // Punch Out
      await db(`UPDATE attendance SET punch_out=NOW(), latitude_out=$1, longitude_out=$2, accuracy_out=$3, distance_out=$4, location_out=$5, updated_at=NOW()
        WHERE id=$6`,
        [latitude||null, longitude||null, accuracy||null, distance||null, locationJson, rec.id]);
      res.json({ success: true, message: 'Punched Out successfully!' });
    }
  } catch(e) { res.status(500).json({ success: false, message: e.message }); }
});


app.get('/api/attendance/today', auth, async (req, res) => {
  try {
    const today = new Date().toISOString().slice(0, 10);
    const r = await db(`SELECT a.*, e.first_name, e.last_name, e.employee_id AS emp_code,
      a.latitude_in AS latitude, a.longitude_in AS longitude, a.distance_in AS distance
      FROM attendance a JOIN employees e ON e.id=a.employee_id
      WHERE DATE(a.punch_in)=$1 ORDER BY e.first_name`, [today]);
    res.json({ success: true, data: r.rows });
  } catch(e) { res.status(500).json({ success: false, message: e.message }); }
});


app.get('/api/attendance/my', auth, async (req, res) => {
  try {
    const m = parseInt(req.query.month) || new Date().getMonth() + 1;
    const y = parseInt(req.query.year)  || new Date().getFullYear();
    const today = new Date().toISOString().slice(0, 10);
    const [recs, td] = await Promise.all([
      db(`SELECT * FROM attendance WHERE employee_id=$1 AND EXTRACT(MONTH FROM date)=$2 AND EXTRACT(YEAR FROM date)=$3 ORDER BY date DESC`, [req.user.employee_id, m, y]),
      db(`SELECT * FROM attendance WHERE employee_id=$1 AND date=$2`, [req.user.employee_id, today])
    ]);
    res.json({
      success: true,
      data: {
        month: m, year: y,
        today: td.rows[0] || null,
        records: recs.rows,
        summary: {
          present:    recs.rows.filter(r => r.status === 'Present').length,
          absent:     recs.rows.filter(r => r.status === 'Absent').length,
          totalHours: recs.rows.reduce((s, r) => s + (parseFloat(r.hours_worked) || 0), 0).toFixed(1)
        }
      }
    });
  } catch (e) { res.status(500).json({ success: false, message: e.message }); }
});

app.get('/api/attendance/employee/:id', auth, canHR, async (req, res) => {
  try {
    const m = parseInt(req.query.month) || new Date().getMonth() + 1;
    const y = parseInt(req.query.year)  || new Date().getFullYear();
    const r = await db(`SELECT * FROM attendance WHERE employee_id=$1 AND EXTRACT(MONTH FROM date)=$2 AND EXTRACT(YEAR FROM date)=$3 ORDER BY date DESC`,
      [req.params.id, m, y]);
    res.json({ success: true, data: { month: m, year: y, records: r.rows } });
  } catch (e) { res.status(500).json({ success: false, message: e.message }); }
});

// ── LEAVE ─────────────────────────────────────────

app.get('/api/leave/policies', auth, async (req, res) => {
  try {
    const r = await db(`SELECT * FROM leave_policies ORDER BY name`);
    res.json({ success: true, data: r.rows });
  } catch (e) { res.status(500).json({ success: false, message: e.message }); }
});

app.get('/api/leave/balances/my', auth, async (req, res) => {
  try {
    const y = new Date().getFullYear();
    const r = await db(
      `SELECT lb.*, lp.name, lp.code, lp.days_per_year, lp.is_paid
       FROM leave_balances lb
       JOIN leave_policies lp ON lp.id = lb.leave_policy_id
       WHERE lb.employee_id=$1 AND lb.year=$2 ORDER BY lp.name`,
      [req.user.employee_id, y]
    );
    res.json({ success: true, data: r.rows });
  } catch (e) { res.status(500).json({ success: false, message: e.message }); }
});

app.get('/api/leave/requests/my', auth, async (req, res) => {
  try {
    const r = await db(
      `SELECT lr.*, lp.name AS leave_type, lp.code
       FROM leave_requests lr
       JOIN leave_policies lp ON lp.id = lr.leave_policy_id
       WHERE lr.employee_id=$1 ORDER BY lr.created_at DESC LIMIT 20`,
      [req.user.employee_id]
    );
    res.json({ success: true, data: r.rows });
  } catch (e) { res.status(500).json({ success: false, message: e.message }); }
});

app.get('/api/leave/requests', auth, canHR, async (req, res) => {
  try {
    const status = req.query.status || 'Pending';
    const r = await db(
      `SELECT lr.*, lp.name AS leave_type,
              e.first_name||' '||e.last_name AS employee_name, e.employee_id AS emp_code,
              d.name AS department_name
       FROM leave_requests lr
       JOIN leave_policies lp ON lp.id=lr.leave_policy_id
       JOIN employees e ON e.id=lr.employee_id
       LEFT JOIN departments d ON d.id=e.department_id
       WHERE ($1='All' OR lr.status=$1)
       ORDER BY lr.created_at DESC LIMIT 50`, [status]
    );
    res.json({ success: true, data: r.rows });
  } catch (e) { res.status(500).json({ success: false, message: e.message }); }
});

app.post('/api/leave/apply', auth, async (req, res) => {
  try {
    const { leavePolicyId, fromDate, toDate, reason } = req.body;
    if (!leavePolicyId || !fromDate || !toDate || !reason) {
      return res.status(400).json({ success: false, message: 'All fields required' });
    }
    let d = new Date(fromDate), days = 0;
    while (d <= new Date(toDate)) { if (d.getDay() !== 0 && d.getDay() !== 6) days++; d.setDate(d.getDate() + 1); }
    if (days <= 0) return res.status(400).json({ success: false, message: 'Invalid date range' });
    const bal = await db(`SELECT balance FROM leave_balances WHERE employee_id=$1 AND leave_policy_id=$2 AND year=EXTRACT(YEAR FROM NOW())`,
      [req.user.employee_id, leavePolicyId]);
    if (bal.rows.length && parseFloat(bal.rows[0].balance) < days) {
      return res.status(400).json({ success: false, message: `Insufficient balance. Available: ${bal.rows[0].balance}, Requested: ${days}` });
    }
    await db(`INSERT INTO leave_requests (id,employee_id,leave_policy_id,from_date,to_date,days,reason,status) VALUES (gen_random_uuid(),$1,$2,$3,$4,$5,$6,'Pending')`,
      [req.user.employee_id, leavePolicyId, fromDate, toDate, days, reason]);
    res.status(201).json({ success: true, message: `Leave applied for ${days} day(s). Pending HR approval.` });
  } catch (e) { res.status(500).json({ success: false, message: e.message }); }
});

app.post('/api/leave/requests/:id/approve', auth, canHR, async (req, res) => {
  try {
    const { action, rejectionNote } = req.body;
    if (!['Approved', 'Rejected'].includes(action)) {
      return res.status(400).json({ success: false, message: 'action must be Approved or Rejected' });
    }
    const lr = await db(`SELECT * FROM leave_requests WHERE id=$1`, [req.params.id]);
    if (!lr.rows.length) return res.status(404).json({ success: false, message: 'Request not found' });
    if (lr.rows[0].status !== 'Pending') return res.status(400).json({ success: false, message: 'Already processed' });
    await db(`UPDATE leave_requests SET status=$1, approved_by=$2, approved_at=NOW(), rejection_note=$3 WHERE id=$4`,
      [action, req.user.employee_id, rejectionNote||null, req.params.id]);
    if (action === 'Approved') {
      await db(`UPDATE leave_balances SET used=used+$1, balance=GREATEST(balance-$1,0) WHERE employee_id=$2 AND leave_policy_id=$3 AND year=EXTRACT(YEAR FROM NOW())`,
        [lr.rows[0].days, lr.rows[0].employee_id, lr.rows[0].leave_policy_id]);
    }
    res.json({ success: true, message: `Leave ${action.toLowerCase()} successfully` });
  } catch (e) { res.status(500).json({ success: false, message: e.message }); }
});

app.get('/api/leave/calendar/:year/:month', auth, async (req, res) => {
  try {
    const { year, month } = req.params;
    const [holidays, leaves] = await Promise.all([
      db(`SELECT * FROM holidays WHERE EXTRACT(YEAR FROM date)=$1 AND EXTRACT(MONTH FROM date)=$2`, [year, month]),
      db(`SELECT lr.from_date, lr.to_date, lr.days, lp.name AS leave_type, e.first_name||' '||e.last_name AS employee_name
          FROM leave_requests lr
          JOIN employees e ON e.id=lr.employee_id
          JOIN leave_policies lp ON lp.id=lr.leave_policy_id
          WHERE lr.status='Approved'
            AND (EXTRACT(MONTH FROM lr.from_date)=$2 AND EXTRACT(YEAR FROM lr.from_date)=$1
              OR EXTRACT(MONTH FROM lr.to_date)=$2 AND EXTRACT(YEAR FROM lr.to_date)=$1)`, [year, month])
    ]);
    res.json({ success: true, data: { holidays: holidays.rows, leaves: leaves.rows } });
  } catch (e) { res.status(500).json({ success: false, message: e.message }); }
});

// ── PAYROLL ───────────────────────────────────────

app.post('/api/payroll/calculate', auth, async (req, res) => {
  try {
    const ctc = parseFloat(req.body.annualCtc) || 0;
    if (!ctc) return res.status(400).json({ success: false, message: 'annualCtc required' });
    const bp = parseFloat(req.body.basicPct) || 0.5;
    const gm = ctc / 12, basic = gm * bp, hra = basic * 0.5, rem = gm - basic - hra;
    const spl = rem * 0.5, conv = rem * 0.5;
    const pfe = basic * 0.12, pfer = basic * 0.0425;
    const esic = gm <= 21000 ? gm * 0.0075 : 0, pt = gm > 15000 ? 200 : 0;
    const ded = pfe + esic + pt, net = gm - ded;
    res.json({
      success: true,
      data: {
        annualCtc: ctc,
        monthly: +gm.toFixed(2), basic: +basic.toFixed(2), hra: +hra.toFixed(2),
        specialAllowance: +spl.toFixed(2), conveyance: +conv.toFixed(2),
        pfEmployee: +pfe.toFixed(2), pfEmployer: +pfer.toFixed(2),
        esicEmployee: +esic.toFixed(2), professionalTax: pt,
        totalDeductions: +ded.toFixed(2), netSalary: +net.toFixed(2)
      }
    });
  } catch (e) { res.status(500).json({ success: false, message: e.message }); }
});

app.post('/api/payroll/salary-structure', auth, canHR, async (req, res) => {
  try {
    const { employeeId, annualCtc, effectiveFrom } = req.body;
    if (!employeeId || !annualCtc) return res.status(400).json({ success: false, message: 'employeeId and annualCtc required' });
    const gm = annualCtc / 12, basic = gm * 0.5, hra = basic * 0.5, rem = gm - basic - hra;
    const spl = rem * 0.5, conv = rem * 0.5, pfe = basic * 0.12, pfer = basic * 0.0425;
    const esic = gm <= 21000 ? gm * 0.0075 : 0, net = gm - pfe - esic;
    await db(`UPDATE salary_structures SET is_active=false WHERE employee_id=$1`, [employeeId]);
    await db(`INSERT INTO salary_structures (id,employee_id,effective_from,annual_ctc,basic,hra,special_allowance,conveyance,pf_employee,pf_employer,esic_employee,net_salary,is_active,created_by)
              VALUES (gen_random_uuid(),$1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,true,$12)`,
      [employeeId, effectiveFrom||new Date().toISOString().slice(0,10), annualCtc, basic.toFixed(2), hra.toFixed(2), spl.toFixed(2), conv.toFixed(2), pfe.toFixed(2), pfer.toFixed(2), esic.toFixed(2), net.toFixed(2), req.user.id]);
    res.status(201).json({ success: true, message: 'Salary structure saved', data: { netSalary: +net.toFixed(2) } });
  } catch (e) { res.status(500).json({ success: false, message: e.message }); }
});

app.post('/api/payroll/run', auth, canHR, async (req, res) => {
  try {
    const m = parseInt(req.body.month) || new Date().getMonth() + 1;
    const y = parseInt(req.body.year)  || new Date().getFullYear();
    const ex = await db(`SELECT id,status FROM payroll_runs WHERE month=$1 AND year=$2`, [m, y]);
    if (ex.rows.length && ex.rows[0].status === 'Processed') {
      return res.status(409).json({ success: false, message: `Payroll for ${m}/${y} already processed` });
    }
    const emps = await db(`SELECT e.id, ss.basic, ss.hra, ss.special_allowance, ss.conveyance, ss.pf_employee, ss.esic_employee, ss.professional_tax
                           FROM employees e JOIN salary_structures ss ON ss.employee_id=e.id AND ss.is_active=true WHERE e.status='Active'`);
    let tg = 0, td = 0, tn = 0;
    let runId;
    if (ex.rows.length) {
      runId = ex.rows[0].id;
      await db(`UPDATE payroll_runs SET status='Processing' WHERE id=$1`, [runId]);
    } else {
      const rr = await db(`INSERT INTO payroll_runs (id,month,year,status) VALUES (gen_random_uuid(),$1,$2,'Processing') RETURNING id`, [m, y]);
      runId = rr.rows[0].id;
    }
    for (const e of emps.rows) {
      const g = +e.basic + +e.hra + +e.special_allowance + +e.conveyance;
      const d = +e.pf_employee + +e.esic_employee + (+e.professional_tax||0);
      const n = g - d; tg += g; td += d; tn += n;
      await db(`DELETE FROM payslips WHERE employee_id=$1 AND month=$2 AND year=$3`, [e.id, m, y]);
      await db(`INSERT INTO payslips (id,payroll_run_id,employee_id,month,year,basic,hra,special_allowance,conveyance,gross_salary,pf_employee,esic_employee,professional_tax,total_deductions,net_salary,status)
                VALUES (gen_random_uuid(),$1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,'Generated')`,
        [runId, e.id, m, y, e.basic, e.hra, e.special_allowance, e.conveyance, g.toFixed(2), e.pf_employee, e.esic_employee, e.professional_tax||0, d.toFixed(2), n.toFixed(2)]);
    }
    await db(`UPDATE payroll_runs SET status='Processed',total_gross=$1,total_deduct=$2,total_net=$3,processed_at=NOW(),processed_by=$4 WHERE id=$5`,
      [tg.toFixed(2), td.toFixed(2), tn.toFixed(2), req.user.id, runId]);
    res.json({ success: true, message: `Payroll processed for ${emps.rows.length} employees`, data: { month: m, year: y, totalEmployees: emps.rows.length, totalGross: +tg.toFixed(2), totalNet: +tn.toFixed(2) } });
  } catch (e) { res.status(500).json({ success: false, message: e.message }); }
});

app.get('/api/payroll/runs', auth, canHR, async (req, res) => {
  try {
    const r = await db(`SELECT * FROM payroll_runs ORDER BY year DESC, month DESC LIMIT 12`);
    res.json({ success: true, data: r.rows });
  } catch (e) { res.status(500).json({ success: false, message: e.message }); }
});

app.get('/api/payroll/summary/:month/:year', auth, canHR, async (req, res) => {
  try {
    const run = await db(`SELECT * FROM payroll_runs WHERE month=$1 AND year=$2`, [req.params.month, req.params.year]);
    if (!run.rows.length) return res.status(404).json({ success: false, message: 'Payroll not run for this period' });
    const ps = await db(`SELECT ps.*, e.first_name, e.last_name, e.employee_id AS emp_code FROM payslips ps JOIN employees e ON e.id=ps.employee_id WHERE ps.payroll_run_id=$1 ORDER BY e.first_name`, [run.rows[0].id]);
    res.json({ success: true, data: { run: run.rows[0], payslips: ps.rows } });
  } catch (e) { res.status(500).json({ success: false, message: e.message }); }
});

app.get('/api/payroll/payslip/my/:month/:year', auth, async (req, res) => {
  try {
    const r = await db(
      `SELECT ps.*, e.first_name, e.last_name, e.employee_id AS emp_code, e.work_email,
              d.name AS department_name, des.title AS designation
       FROM payslips ps
       JOIN employees e ON e.id=ps.employee_id
       LEFT JOIN departments d ON d.id=e.department_id
       LEFT JOIN designations des ON des.id=e.designation_id
       WHERE ps.employee_id=$1 AND ps.month=$2 AND ps.year=$3`,
      [req.user.employee_id, req.params.month, req.params.year]
    );
    if (!r.rows.length) return res.status(404).json({ success: false, message: 'Payslip not found for this period' });
    res.json({ success: true, data: r.rows[0] });
  } catch (e) { res.status(500).json({ success: false, message: e.message }); }
});

// ── NOTIFICATIONS ─────────────────────────────────

app.get('/api/notifications', auth, async (req, res) => {
  try {
    const r = await db(`SELECT * FROM notifications WHERE user_id=$1 ORDER BY created_at DESC LIMIT 20`, [req.user.id]);
    res.json({ success: true, data: r.rows });
  } catch (e) { res.status(500).json({ success: false, message: e.message }); }
});

app.patch('/api/notifications/:id/read', auth, async (req, res) => {
  try {
    await db(`UPDATE notifications SET is_read=true WHERE id=$1 AND user_id=$2`, [req.params.id, req.user.id]);
    res.json({ success: true, message: 'Marked as read' });
  } catch (e) { res.status(500).json({ success: false, message: e.message }); }
});



// ═══════════════════════════════════════════════════
// PHASE 2 — RECRUITMENT + ONBOARDING + EMPLOYEE MGT
// ═══════════════════════════════════════════════════

// ── JOBS ─────────────────────────────────────────

app.get('/api/jobs', async (req, res) => {
  try {
    const { status, department } = req.query;
    let sql = `SELECT j.*, d.name AS department_name,
               (SELECT COUNT(*) FROM applications a WHERE a.job_id=j.id) AS applicants
               FROM jobs j LEFT JOIN departments d ON d.id=j.department_id WHERE 1=1`;
    const params = [];
    if (status) { params.push(status); sql += ` AND j.status=$${params.length}`; }
    if (department) { params.push(department); sql += ` AND j.department_id=$${params.length}`; }
    sql += ' ORDER BY j.created_at DESC';
    const r = await db(sql, params);
    res.json({ success: true, data: r.rows });
  } catch(e) { res.status(500).json({ success: false, message: e.message }); }
});

app.get('/api/jobs/:id', async (req, res) => {
  try {
    const r = await db(`SELECT j.*, d.name AS department_name FROM jobs j LEFT JOIN departments d ON d.id=j.department_id WHERE j.id=$1`, [req.params.id]);
    if (!r.rows.length) return res.status(404).json({ success: false, message: 'Job not found' });
    const apps = await db(`SELECT a.*, c.first_name, c.last_name, c.email, c.current_position, c.experience_yrs, c.ai_score FROM applications a JOIN candidates c ON c.id=a.candidate_id WHERE a.job_id=$1 ORDER BY a.ai_score DESC NULLS LAST`, [req.params.id]);
    res.json({ success: true, data: { ...r.rows[0], applications: apps.rows } });
  } catch(e) { res.status(500).json({ success: false, message: e.message }); }
});

app.post('/api/jobs', auth, async (req, res) => {
  try {
    const { title, departmentId, location, jobType, experienceMin, experienceMax, salaryMin, salaryMax, description, requirements, responsibilities, openings, closesAt } = req.body;
    if (!title) return res.status(400).json({ success: false, message: 'Title required' });
    const r = await db(`INSERT INTO jobs (title, department_id, location, job_type, experience_min, experience_max, salary_min, salary_max, description, requirements, responsibilities, openings, closes_at, posted_by, status)
      VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,'Draft') RETURNING *`,
      [title, departmentId||null, location||null, jobType||'Full-Time', experienceMin||0, experienceMax||5, salaryMin||null, salaryMax||null, description||null, requirements||null, responsibilities||null, openings||1, closesAt||null, req.user.id]);
    res.status(201).json({ success: true, message: 'Job created', data: r.rows[0] });
  } catch(e) { res.status(500).json({ success: false, message: e.message }); }
});

app.put('/api/jobs/:id', auth, async (req, res) => {
  try {
    const { status, title, description, requirements, openings, closesAt } = req.body;
    const sets = [], params = [];
    if (title) { params.push(title); sets.push(`title=$${params.length}`); }
    if (status) { params.push(status); sets.push(`status=$${params.length}`);
      if (status === 'Active') { sets.push(`posted_at=NOW()`); sets.push(`posted_by='${req.user.id}'`); }
    }
    if (description) { params.push(description); sets.push(`description=$${params.length}`); }
    if (requirements) { params.push(requirements); sets.push(`requirements=$${params.length}`); }
    if (openings) { params.push(openings); sets.push(`openings=$${params.length}`); }
    if (closesAt) { params.push(closesAt); sets.push(`closes_at=$${params.length}`); }
    if (!sets.length) return res.status(400).json({ success: false, message: 'No fields to update' });
    params.push(req.params.id);
    await db(`UPDATE jobs SET ${sets.join(',')}, updated_at=NOW() WHERE id=$${params.length}`, params);
    res.json({ success: true, message: 'Job updated' });
  } catch(e) { res.status(500).json({ success: false, message: e.message }); }
});

// ── CANDIDATES ────────────────────────────────────

app.get('/api/candidates', auth, async (req, res) => {
  try {
    const { search } = req.query;
    let sql = `SELECT c.*, (SELECT COUNT(*) FROM applications a WHERE a.candidate_id=c.id) AS total_applications FROM candidates c WHERE 1=1`;
    const params = [];
    if (search) {
      params.push(`%${search}%`);
      sql += ` AND (c.first_name ILIKE $1 OR c.last_name ILIKE $1 OR c.email ILIKE $1 OR c.current_company ILIKE $1)`;
    }
    sql += ' ORDER BY c.created_at DESC';
    const r = await db(sql, params);
    res.json({ success: true, data: r.rows });
  } catch(e) { res.status(500).json({ success: false, message: e.message }); }
});

app.post('/api/candidates', auth, async (req, res) => {
  try {
    const { firstName, lastName, email, mobile, currentCompany, currentPosition, experienceYrs, currentCtc, expectedCtc, noticePeriod, location, source } = req.body;
    if (!firstName || !lastName || !email) return res.status(400).json({ success: false, message: 'Name and email required' });
    const r = await db(`INSERT INTO candidates (first_name, last_name, email, mobile, current_company, current_position, experience_yrs, current_ctc, expected_ctc, notice_period, location, source)
      VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12) RETURNING *`,
      [firstName, lastName, email.toLowerCase(), mobile||null, currentCompany||null, currentPosition||null, experienceYrs||null, currentCtc||null, expectedCtc||null, noticePeriod||null, location||null, source||'Direct']);
    res.status(201).json({ success: true, message: 'Candidate added', data: r.rows[0] });
  } catch(e) {
    if (e.code === '23505') return res.status(409).json({ success: false, message: 'Candidate email already exists' });
    res.status(500).json({ success: false, message: e.message });
  }
});

// ── APPLICATIONS ──────────────────────────────────

app.get('/api/applications', auth, async (req, res) => {
  try {
    const { jobId, status, stage } = req.query;
    let sql = `SELECT a.*, c.first_name, c.last_name, c.email, c.mobile, c.current_company, c.current_position, c.experience_yrs, c.current_ctc, c.expected_ctc, c.notice_period, c.location AS candidate_location,
               j.title AS job_title, d.name AS department_name
               FROM applications a
               JOIN candidates c ON c.id=a.candidate_id
               JOIN jobs j ON j.id=a.job_id
               LEFT JOIN departments d ON d.id=j.department_id
               WHERE 1=1`;
    const params = [];
    if (jobId) { params.push(jobId); sql += ` AND a.job_id=$${params.length}`; }
    if (status) { params.push(status); sql += ` AND a.status=$${params.length}`; }
    if (stage) { params.push(stage); sql += ` AND a.stage=$${params.length}`; }
    sql += ' ORDER BY a.ai_score DESC NULLS LAST, a.applied_at DESC';
    const r = await db(sql, params);
    res.json({ success: true, data: r.rows });
  } catch(e) { res.status(500).json({ success: false, message: e.message }); }
});

app.post('/api/applications', auth, async (req, res) => {
  try {
    const { jobId, candidateId } = req.body;
    if (!jobId || !candidateId) return res.status(400).json({ success: false, message: 'jobId and candidateId required' });
    const r = await db(`INSERT INTO applications (job_id, candidate_id) VALUES ($1,$2) RETURNING *`, [jobId, candidateId]);
    res.status(201).json({ success: true, message: 'Application created', data: r.rows[0] });
  } catch(e) {
    if (e.code === '23505') return res.status(409).json({ success: false, message: 'Already applied' });
    res.status(500).json({ success: false, message: e.message });
  }
});

app.put('/api/applications/:id', auth, async (req, res) => {
  try {
    const { status, stage, recruiterNotes, rejectReason, aiScore, aiSummary } = req.body;
    const sets = [], params = [];
    if (status) { params.push(status); sets.push(`status=$${params.length}`); }
    if (stage) { params.push(stage); sets.push(`stage=$${params.length}`); }
    if (recruiterNotes !== undefined) { params.push(recruiterNotes); sets.push(`recruiter_notes=$${params.length}`); }
    if (rejectReason) { params.push(rejectReason); sets.push(`reject_reason=$${params.length}`); }
    if (aiScore !== undefined) { params.push(aiScore); sets.push(`ai_score=$${params.length}`); }
    if (aiSummary) { params.push(aiSummary); sets.push(`ai_summary=$${params.length}`); }
    if (!sets.length) return res.status(400).json({ success: false, message: 'No fields to update' });
    params.push(req.params.id);
    await db(`UPDATE applications SET ${sets.join(',')}, updated_at=NOW() WHERE id=$${params.length}`, params);
    res.json({ success: true, message: 'Application updated' });
  } catch(e) { res.status(500).json({ success: false, message: e.message }); }
});

// ── AI RESUME SCREENING ───────────────────────────

app.post('/api/applications/:id/ai-screen', auth, async (req, res) => {
  try {
    const appRes = await db(`SELECT a.*, c.first_name, c.last_name, c.current_company, c.current_position, c.experience_yrs, c.current_ctc, c.expected_ctc, c.skills, j.title AS job_title, j.experience_min, j.experience_max, j.salary_max, j.requirements FROM applications a JOIN candidates c ON c.id=a.candidate_id JOIN jobs j ON j.id=a.job_id WHERE a.id=$1`, [req.params.id]);
    if (!appRes.rows.length) return res.status(404).json({ success: false, message: 'Application not found' });
    const app2 = appRes.rows[0];
    const expMatch = app2.experience_yrs >= app2.experience_min && app2.experience_yrs <= app2.experience_max + 2;
    const salMatch = !app2.expected_ctc || !app2.salary_max || app2.expected_ctc <= app2.salary_max * 1.1;
    let score = 50;
    if (expMatch) score += 25;
    if (salMatch) score += 15;
    if (app2.current_company) score += 5;
    if (app2.skills && app2.skills.length > 3) score += 5;
    score = Math.min(100, score);
    const summary = `Candidate ${app2.first_name} ${app2.last_name} has ${app2.experience_yrs} years experience as ${app2.current_position} at ${app2.current_company}. Experience match: ${expMatch ? 'Yes' : 'No'}. Salary match: ${salMatch ? 'Yes' : 'No'}. AI Score: ${score}/100.`;
    await db(`UPDATE applications SET ai_score=$1, ai_summary=$2, stage='Screening', updated_at=NOW() WHERE id=$3`, [score, summary, req.params.id]);
    res.json({ success: true, message: 'AI screening completed', data: { score, summary, expMatch, salMatch } });
  } catch(e) { res.status(500).json({ success: false, message: e.message }); }
});

// ── INTERVIEWS ────────────────────────────────────

app.get('/api/interviews', auth, async (req, res) => {
  try {
    const { applicationId } = req.query;
    let sql = `SELECT i.*, e.first_name AS interviewer_first, e.last_name AS interviewer_last,
               c.first_name AS candidate_first, c.last_name AS candidate_last, j.title AS job_title
               FROM interviews i
               LEFT JOIN employees e ON e.id=i.interviewer_id
               JOIN applications a ON a.id=i.application_id
               JOIN candidates c ON c.id=a.candidate_id
               JOIN jobs j ON j.id=a.job_id WHERE 1=1`;
    const params = [];
    if (applicationId) { params.push(applicationId); sql += ` AND i.application_id=$${params.length}`; }
    sql += ' ORDER BY i.scheduled_at ASC';
    const r = await db(sql, params);
    res.json({ success: true, data: r.rows });
  } catch(e) { res.status(500).json({ success: false, message: e.message }); }
});

app.post('/api/interviews', auth, async (req, res) => {
  try {
    const { applicationId, round, roundName, interviewType, scheduledAt, durationMins, interviewerId, meetLink } = req.body;
    if (!applicationId || !scheduledAt) return res.status(400).json({ success: false, message: 'applicationId and scheduledAt required' });
    const r = await db(`INSERT INTO interviews (application_id, round, round_name, interview_type, scheduled_at, duration_mins, interviewer_id, meet_link)
      VALUES ($1,$2,$3,$4,$5,$6,$7,$8) RETURNING *`,
      [applicationId, round||1, roundName||'HR Round', interviewType||'Video', scheduledAt, durationMins||60, interviewerId||null, meetLink||null]);
    await db(`UPDATE applications SET stage='Interview', updated_at=NOW() WHERE id=$1`, [applicationId]);
    res.status(201).json({ success: true, message: 'Interview scheduled', data: r.rows[0] });
  } catch(e) { res.status(500).json({ success: false, message: e.message }); }
});

app.put('/api/interviews/:id/feedback', auth, async (req, res) => {
  try {
    const { feedback, rating, outcome } = req.body;
    await db(`UPDATE interviews SET feedback=$1, rating=$2, outcome=$3, status='Completed' WHERE id=$4`, [feedback, rating||null, outcome||null, req.params.id]);
    if (outcome === 'Selected') {
      const intRes = await db('SELECT application_id FROM interviews WHERE id=$1', [req.params.id]);
      if (intRes.rows.length) await db(`UPDATE applications SET stage='Offer', updated_at=NOW() WHERE id=$1`, [intRes.rows[0].application_id]);
    }
    res.json({ success: true, message: 'Feedback submitted' });
  } catch(e) { res.status(500).json({ success: false, message: e.message }); }
});

// ── OFFER LETTERS ─────────────────────────────────

app.get('/api/offers', auth, async (req, res) => {
  try {
    const r = await db(`SELECT o.*, c.first_name, c.last_name, c.email, d.name AS department_name FROM offer_letters o JOIN candidates c ON c.id=o.candidate_id LEFT JOIN departments d ON d.id=o.department_id ORDER BY o.created_at DESC`);
    res.json({ success: true, data: r.rows });
  } catch(e) { res.status(500).json({ success: false, message: e.message }); }
});

app.post('/api/offers', auth, async (req, res) => {
  try {
    const { applicationId, candidateId, designation, departmentId, joiningDate, ctc, expiryDate } = req.body;
    if (!candidateId || !ctc) return res.status(400).json({ success: false, message: 'candidateId and ctc required' });
    const monthly = ctc / 12;
    const basic = monthly * 0.5;
    const hra = basic * 0.5;
    const special = monthly - basic - hra;
    const r = await db(`INSERT INTO offer_letters (application_id, candidate_id, designation, department_id, joining_date, ctc, basic, hra, special_allowance, expiry_date, created_by, status)
      VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,'Draft') RETURNING *`,
      [applicationId||null, candidateId, designation||null, departmentId||null, joiningDate||null, ctc, basic.toFixed(2), hra.toFixed(2), special.toFixed(2), expiryDate||null, req.user.id]);
    if (applicationId) await db(`UPDATE applications SET stage='Offer', updated_at=NOW() WHERE id=$1`, [applicationId]);
    res.status(201).json({ success: true, message: 'Offer letter created', data: r.rows[0] });
  } catch(e) { res.status(500).json({ success: false, message: e.message }); }
});

app.put('/api/offers/:id/send', auth, async (req, res) => {
  try {
    await db(`UPDATE offer_letters SET status='Sent', sent_at=NOW() WHERE id=$1`, [req.params.id]);
    res.json({ success: true, message: 'Offer letter sent' });
  } catch(e) { res.status(500).json({ success: false, message: e.message }); }
});

// ── ONBOARDING ────────────────────────────────────

app.get('/api/onboarding/tasks', auth, async (req, res) => {
  try {
    const r = await db('SELECT * FROM onboarding_tasks ORDER BY order_no');
    res.json({ success: true, data: r.rows });
  } catch(e) { res.status(500).json({ success: false, message: e.message }); }
});

app.get('/api/onboarding/:employeeId', auth, async (req, res) => {
  try {
    const tasks = await db('SELECT * FROM onboarding_tasks ORDER BY order_no');
    const progress = await db(`SELECT op.*, ot.name, ot.category, ot.is_required, ot.assigned_to, ot.order_no
      FROM onboarding_progress op JOIN onboarding_tasks ot ON ot.id=op.task_id
      WHERE op.employee_id=$1 ORDER BY ot.order_no`, [req.params.employeeId]);
    const total = tasks.rows.length;
    const done = progress.rows.filter(p => p.status === 'Completed').length;
    const pct = total > 0 ? Math.round(done / total * 100) : 0;
    res.json({ success: true, data: { tasks: tasks.rows, progress: progress.rows, summary: { total, done, pending: total - done, percentage: pct } } });
  } catch(e) { res.status(500).json({ success: false, message: e.message }); }
});

app.post('/api/onboarding/:employeeId/init', auth, async (req, res) => {
  try {
    const tasks = await db('SELECT id FROM onboarding_tasks');
    for (const t of tasks.rows) {
      await db(`INSERT INTO onboarding_progress (employee_id, task_id, status) VALUES ($1,$2,'Pending') ON CONFLICT (employee_id, task_id) DO NOTHING`, [req.params.employeeId, t.id]);
    }
    res.json({ success: true, message: 'Onboarding initialized for employee' });
  } catch(e) { res.status(500).json({ success: false, message: e.message }); }
});

app.put('/api/onboarding/:employeeId/task/:taskId', auth, async (req, res) => {
  try {
    const { status, notes } = req.body;
    const completed = status === 'Completed' ? 'NOW()' : 'NULL';
    await db(`UPDATE onboarding_progress SET status=$1, notes=$2, completed_at=${completed}, verified_by=$3
      WHERE employee_id=$4 AND task_id=$5`, [status, notes||null, req.user.id, req.params.employeeId, req.params.taskId]);
    res.json({ success: true, message: 'Task updated' });
  } catch(e) { res.status(500).json({ success: false, message: e.message }); }
});

// ── IT ASSETS ─────────────────────────────────────

app.get('/api/assets', auth, async (req, res) => {
  try {
    const r = await db(`SELECT a.*, e.first_name, e.last_name, e.employee_id AS emp_code FROM it_assets a LEFT JOIN employees e ON e.id=a.assigned_to ORDER BY a.category, a.asset_code`);
    res.json({ success: true, data: r.rows });
  } catch(e) { res.status(500).json({ success: false, message: e.message }); }
});

app.post('/api/assets', auth, async (req, res) => {
  try {
    const { assetCode, name, category, brand, model, serialNumber, purchaseDate, warrantyTill } = req.body;
    if (!assetCode || !name) return res.status(400).json({ success: false, message: 'assetCode and name required' });
    const r = await db(`INSERT INTO it_assets (asset_code, name, category, brand, model, serial_number, purchase_date, warranty_till)
      VALUES ($1,$2,$3,$4,$5,$6,$7,$8) RETURNING *`,
      [assetCode, name, category||null, brand||null, model||null, serialNumber||null, purchaseDate||null, warrantyTill||null]);
    res.status(201).json({ success: true, message: 'Asset added', data: r.rows[0] });
  } catch(e) {
    if (e.code === '23505') return res.status(409).json({ success: false, message: 'Asset code already exists' });
    res.status(500).json({ success: false, message: e.message });
  }
});

app.put('/api/assets/:id/assign', auth, async (req, res) => {
  try {
    const { employeeId } = req.body;
    if (!employeeId) return res.status(400).json({ success: false, message: 'employeeId required' });
    await db(`UPDATE it_assets SET assigned_to=$1, assigned_at=NOW(), status='Assigned' WHERE id=$2`, [employeeId, req.params.id]);
    res.json({ success: true, message: 'Asset assigned to employee' });
  } catch(e) { res.status(500).json({ success: false, message: e.message }); }
});

app.put('/api/assets/:id/return', auth, async (req, res) => {
  try {
    await db(`UPDATE it_assets SET assigned_to=NULL, assigned_at=NULL, returned_at=NOW(), status='Available' WHERE id=$1`, [req.params.id]);
    res.json({ success: true, message: 'Asset returned' });
  } catch(e) { res.status(500).json({ success: false, message: e.message }); }
});

// ── SKILLS ────────────────────────────────────────

app.get('/api/skills/:employeeId', auth, async (req, res) => {
  try {
    const r = await db('SELECT * FROM employee_skills WHERE employee_id=$1 ORDER BY proficiency DESC', [req.params.employeeId]);
    res.json({ success: true, data: r.rows });
  } catch(e) { res.status(500).json({ success: false, message: e.message }); }
});

app.post('/api/skills', auth, async (req, res) => {
  try {
    const { employeeId, skillName, proficiency, yearsExp } = req.body;
    if (!employeeId || !skillName) return res.status(400).json({ success: false, message: 'employeeId and skillName required' });
    const r = await db(`INSERT INTO employee_skills (employee_id, skill_name, proficiency, years_exp) VALUES ($1,$2,$3,$4)
      ON CONFLICT (employee_id, skill_name) DO UPDATE SET proficiency=$3, years_exp=$4 RETURNING *`,
      [employeeId, skillName, proficiency||'Intermediate', yearsExp||null]);
    res.json({ success: true, message: 'Skill saved', data: r.rows[0] });
  } catch(e) { res.status(500).json({ success: false, message: e.message }); }
});

app.delete('/api/skills/:id', auth, async (req, res) => {
  try {
    await db('DELETE FROM employee_skills WHERE id=$1', [req.params.id]);
    res.json({ success: true, message: 'Skill removed' });
  } catch(e) { res.status(500).json({ success: false, message: e.message }); }
});

// ── CERTIFICATIONS ────────────────────────────────

app.get('/api/certifications/:employeeId', auth, async (req, res) => {
  try {
    const r = await db('SELECT * FROM certifications WHERE employee_id=$1 ORDER BY issue_date DESC', [req.params.employeeId]);
    res.json({ success: true, data: r.rows });
  } catch(e) { res.status(500).json({ success: false, message: e.message }); }
});

app.post('/api/certifications', auth, async (req, res) => {
  try {
    const { employeeId, name, issuer, issueDate, expiryDate, credentialId, credentialUrl } = req.body;
    if (!employeeId || !name) return res.status(400).json({ success: false, message: 'employeeId and name required' });
    const r = await db(`INSERT INTO certifications (employee_id, name, issuer, issue_date, expiry_date, credential_id, credential_url)
      VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING *`,
      [employeeId, name, issuer||null, issueDate||null, expiryDate||null, credentialId||null, credentialUrl||null]);
    res.status(201).json({ success: true, message: 'Certification added', data: r.rows[0] });
  } catch(e) { res.status(500).json({ success: false, message: e.message }); }
});

// ── TALENT POOL ───────────────────────────────────

app.get('/api/talent-pool', auth, async (req, res) => {
  try {
    const r = await db(`SELECT tp.*, c.first_name, c.last_name, c.email, c.current_position, c.experience_yrs, c.location
      FROM talent_pool tp JOIN candidates c ON c.id=tp.candidate_id ORDER BY tp.created_at DESC`);
    res.json({ success: true, data: r.rows });
  } catch(e) { res.status(500).json({ success: false, message: e.message }); }
});

app.post('/api/talent-pool', auth, async (req, res) => {
  try {
    const { candidateId, tags, notes } = req.body;
    if (!candidateId) return res.status(400).json({ success: false, message: 'candidateId required' });
    const r = await db(`INSERT INTO talent_pool (candidate_id, tags, notes, added_by) VALUES ($1,$2,$3,$4) RETURNING *`,
      [candidateId, tags||null, notes||null, req.user.id]);
    res.status(201).json({ success: true, message: 'Added to talent pool', data: r.rows[0] });
  } catch(e) { res.status(500).json({ success: false, message: e.message }); }
});

// ── ORG CHART ─────────────────────────────────────

app.get('/api/org-chart', auth, async (req, res) => {
  try {
    const r = await db(`SELECT e.id, e.employee_id, e.first_name, e.last_name, e.reporting_to,
      e.work_location, e.photo_url, d.name AS department_name, des.title AS designation
      FROM employees e
      LEFT JOIN departments d ON d.id=e.department_id
      LEFT JOIN designations des ON des.id=e.designation_id
      WHERE e.status='Active' ORDER BY e.date_of_joining ASC`);
    res.json({ success: true, data: r.rows });
  } catch(e) { res.status(500).json({ success: false, message: e.message }); }
});

// ── RECRUITMENT DASHBOARD STATS ───────────────────

app.get('/api/recruitment/stats', auth, async (req, res) => {
  try {
    const [jobs, apps, interviews, offers, candidates] = await Promise.all([
      db(`SELECT status, COUNT(*) c FROM jobs GROUP BY status`),
      db(`SELECT stage, COUNT(*) c FROM applications GROUP BY stage`),
      db(`SELECT COUNT(*) c FROM interviews WHERE scheduled_at >= NOW() AND status='Scheduled'`),
      db(`SELECT status, COUNT(*) c FROM offer_letters GROUP BY status`),
      db(`SELECT COUNT(*) c FROM candidates`)
    ]);
    const byJob = {};
    jobs.rows.forEach(r => { byJob[r.status] = parseInt(r.c); });
    const byApp = {};
    apps.rows.forEach(r => { byApp[r.stage] = parseInt(r.c); });
    const byOffer = {};
    offers.rows.forEach(r => { byOffer[r.status] = parseInt(r.c); });
    res.json({
      success: true,
      data: {
        jobs: { active: byJob['Active']||0, draft: byJob['Draft']||0, closed: byJob['Closed']||0, total: Object.values(byJob).reduce((a,b)=>a+b,0) },
        applications: byApp,
        upcomingInterviews: parseInt(interviews.rows[0]?.c||0),
        offers: byOffer,
        totalCandidates: parseInt(candidates.rows[0]?.c||0)
      }
    });
  } catch(e) { res.status(500).json({ success: false, message: e.message }); }
});


// ═══════════════════════════════════════════════════
// PHASE 3 — CAREER PAGE + OFFER LETTERS + SELF SERVICE
// ═══════════════════════════════════════════════════

// ── PUBLIC CAREER PAGE ────────────────────────────
app.get('/api/careers/jobs', async (req, res) => {
  try {
    const r = await db(`SELECT j.id, j.title, j.location, j.job_type, j.experience_min, j.experience_max,
      j.salary_min, j.salary_max, j.description, j.requirements, j.openings, j.closes_at, j.posted_at,
      d.name AS department_name FROM jobs j LEFT JOIN departments d ON d.id=j.department_id
      WHERE j.status='Active' ORDER BY j.created_at DESC`);
    res.json({ success: true, data: r.rows });
  } catch(e) { res.status(500).json({ success: false, message: e.message }); }
});

app.post('/api/careers/apply', async (req, res) => {
  try {
    const { firstName, lastName, email, mobile, currentCompany, currentPosition, experienceYrs, expectedCtc, noticePeriod, jobId, coverLetter } = req.body;
    if (!firstName || !lastName || !email || !jobId) return res.status(400).json({ success: false, message: 'Name, email and job required' });
    let candidateId;
    const existing = await db('SELECT id FROM candidates WHERE email=$1', [email.toLowerCase()]);
    if (existing.rows.length) {
      candidateId = existing.rows[0].id;
    } else {
      const c = await db(`INSERT INTO candidates (first_name, last_name, email, mobile, current_company, current_position, experience_yrs, expected_ctc, notice_period, source)
        VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,'Career Page') RETURNING id`,
        [firstName, lastName, email.toLowerCase(), mobile||null, currentCompany||null, currentPosition||null, experienceYrs||null, expectedCtc||null, noticePeriod||null]);
      candidateId = c.rows[0].id;
    }
    const app2 = await db(`INSERT INTO applications (job_id, candidate_id) VALUES ($1,$2) ON CONFLICT (job_id, candidate_id) DO NOTHING RETURNING id`, [jobId, candidateId]);
    res.json({ success: true, message: 'Application submitted successfully! We will contact you soon.' });
  } catch(e) { res.status(500).json({ success: false, message: e.message }); }
});

// ── OFFER LETTER DATA ──────────────────────────────
app.get('/api/offers/:id', auth, async (req, res) => {
  try {
    const r = await db(`SELECT o.*, c.first_name, c.last_name, c.email, c.mobile, c.current_position,
      d.name AS department_name FROM offer_letters o
      JOIN candidates c ON c.id=o.candidate_id
      LEFT JOIN departments d ON d.id=o.department_id
      WHERE o.id=$1`, [req.params.id]);
    if (!r.rows.length) return res.status(404).json({ success: false, message: 'Offer not found' });
    res.json({ success: true, data: r.rows[0] });
  } catch(e) { res.status(500).json({ success: false, message: e.message }); }
});

// ── CHANGE PASSWORD ────────────────────────────────
// ── UPDATE PROFILE ─────────────────────────────────
app.put('/api/employees/:id/profile', auth, async (req, res) => {
  try {
    const { mobile, bloodGroup, emergencyContact, address } = req.body;
    const sets = [], params = [];
    if (mobile) { params.push(mobile); sets.push(`mobile=$${params.length}`); }
    if (bloodGroup) { params.push(bloodGroup); sets.push(`blood_group=$${params.length}`); }
    if (emergencyContact) { params.push(emergencyContact); sets.push(`emergency_contact=$${params.length}`); }
    if (address) { params.push(address); sets.push(`address=$${params.length}`); }
    if (!sets.length) return res.status(400).json({ success: false, message: 'Nothing to update' });
    params.push(req.params.id);
    await db(`UPDATE employees SET ${sets.join(',')}, updated_at=NOW() WHERE id=$${params.length}`, params);
    res.json({ success: true, message: 'Profile updated successfully' });
  } catch(e) { res.status(500).json({ success: false, message: e.message }); }
});

// ── EMPLOYEE DOCUMENTS ────────────────────────────
app.get('/api/documents/:employeeId', auth, async (req, res) => {
  try {
    const r = await db('SELECT * FROM employee_documents WHERE employee_id=$1 ORDER BY created_at DESC', [req.params.employeeId]);
    res.json({ success: true, data: r.rows });
  } catch(e) { res.status(500).json({ success: false, message: e.message }); }
});

app.post('/api/documents', auth, async (req, res) => {
  try {
    const { employeeId, name, docType, fileUrl } = req.body;
    if (!employeeId || !name) return res.status(400).json({ success: false, message: 'employeeId and name required' });
    const r = await db(`INSERT INTO employee_documents (employee_id, name, doc_type, file_url, uploaded_by)
      VALUES ($1,$2,$3,$4,$5) RETURNING *`,
      [employeeId, name, docType||null, fileUrl||null, req.user.id]);
    res.status(201).json({ success: true, message: 'Document added', data: r.rows[0] });
  } catch(e) { res.status(500).json({ success: false, message: e.message }); }
});

// ── NOTIFICATIONS ─────────────────────────────────
app.get('/api/notifications', auth, async (req, res) => {
  try {
    const r = await db(`SELECT * FROM notifications WHERE user_id=$1 ORDER BY created_at DESC LIMIT 20`, [req.user.id]);
    res.json({ success: true, data: r.rows });
  } catch(e) { res.status(500).json({ success: false, message: e.message }); }
});

app.put('/api/notifications/:id/read', auth, async (req, res) => {
  try {
    await db(`UPDATE notifications SET is_read=true WHERE id=$1 AND user_id=$2`, [req.params.id, req.user.id]);
    res.json({ success: true, message: 'Notification marked as read' });
  } catch(e) { res.status(500).json({ success: false, message: e.message }); }
});

console.log('Phase 3 API routes loaded!');

// ═══════════════════════════════════════════════════
// PHASE 3B — INTERVIEWS + PHOTO + PAYSLIP PDF
// ═══════════════════════════════════════════════════

// ── INTERVIEW FEEDBACK FORM ───────────────────────
app.get('/api/interviews/upcoming', auth, async (req, res) => {
  try {
    const r = await db(`SELECT i.*, 
      e.first_name AS interviewer_first, e.last_name AS interviewer_last,
      c.first_name AS candidate_first, c.last_name AS candidate_last,
      j.title AS job_title, a.id AS application_id
      FROM interviews i
      LEFT JOIN employees e ON e.id=i.interviewer_id
      JOIN applications a ON a.id=i.application_id
      JOIN candidates c ON c.id=a.candidate_id
      JOIN jobs j ON j.id=a.job_id
      WHERE i.status='Scheduled'
      ORDER BY i.scheduled_at ASC LIMIT 20`);
    res.json({ success: true, data: r.rows });
  } catch(e) { res.status(500).json({ success: false, message: e.message }); }
});

app.get('/api/interviews/all', auth, async (req, res) => {
  try {
    const r = await db(`SELECT i.*, 
      e.first_name AS interviewer_first, e.last_name AS interviewer_last,
      c.first_name AS candidate_first, c.last_name AS candidate_last,
      c.email AS candidate_email,
      j.title AS job_title
      FROM interviews i
      LEFT JOIN employees e ON e.id=i.interviewer_id
      JOIN applications a ON a.id=i.application_id
      JOIN candidates c ON c.id=a.candidate_id
      JOIN jobs j ON j.id=a.job_id
      ORDER BY i.scheduled_at DESC LIMIT 50`);
    res.json({ success: true, data: r.rows });
  } catch(e) { res.status(500).json({ success: false, message: e.message }); }
});

// ── PROFILE PHOTO (Base64 stored in DB) ──────────
app.put('/api/employees/:id/photo', auth, async (req, res) => {
  try {
    const { photoBase64 } = req.body;
    if (!photoBase64) return res.status(400).json({ success: false, message: 'Photo data required' });
    if (photoBase64.length > 500000) return res.status(400).json({ success: false, message: 'Photo too large. Max 500KB.' });
    await db(`UPDATE employees SET photo_url=$1, updated_at=NOW() WHERE id=$2`, [photoBase64, req.params.id]);
    res.json({ success: true, message: 'Profile photo updated!' });
  } catch(e) { res.status(500).json({ success: false, message: e.message }); }
});

// ── PAYSLIP PDF DATA ──────────────────────────────
app.get('/api/payroll/payslip/pdf/:employeeId/:month/:year', auth, async (req, res) => {
  try {
    const { employeeId, month, year } = req.params;
    const r = await db(`SELECT ps.*, 
      e.first_name, e.last_name, e.employee_id AS emp_code, e.work_location,
      e.work_email, e.mobile, e.date_of_joining,
      d.name AS department_name
      FROM payslips ps
      JOIN employees e ON e.id=ps.employee_id
      LEFT JOIN departments d ON d.id=e.department_id
      WHERE ps.employee_id=$1 AND ps.month=$2 AND ps.year=$3`, 
      [employeeId, parseInt(month), parseInt(year)]);
    if (!r.rows.length) return res.status(404).json({ success: false, message: 'Payslip not found' });
    res.json({ success: true, data: r.rows[0] });
  } catch(e) { res.status(500).json({ success: false, message: e.message }); }
});

// ── SCHEDULE INTERVIEW ────────────────────────────
app.post('/api/interviews/schedule', auth, async (req, res) => {
  try {
    const { applicationId, round, roundName, interviewType, scheduledAt, durationMins, interviewerId, meetLink } = req.body;
    if (!applicationId || !scheduledAt) return res.status(400).json({ success: false, message: 'applicationId and scheduledAt required' });
    const r = await db(`INSERT INTO interviews (application_id, round, round_name, interview_type, scheduled_at, duration_mins, interviewer_id, meet_link)
      VALUES ($1,$2,$3,$4,$5,$6,$7,$8) RETURNING *`,
      [applicationId, round||1, roundName||'HR Round', interviewType||'Video', scheduledAt, durationMins||60, interviewerId||null, meetLink||null]);
    await db(`UPDATE applications SET stage='Interview', updated_at=NOW() WHERE id=$1`, [applicationId]);
    res.status(201).json({ success: true, message: 'Interview scheduled!', data: r.rows[0] });
  } catch(e) { res.status(500).json({ success: false, message: e.message }); }
});

console.log('Phase 3B routes loaded!');


// ── DELETE EMPLOYEE ───────────────────────────────
app.delete('/api/employees/:id', auth, async (req, res) => {
  try {
    if (req.user.role !== 'admin' && req.user.role !== 'hr') return res.status(403).json({ success: false, message: 'Access denied' });
    const { id } = req.params;
    // Delete related records first
    await db('DELETE FROM users WHERE employee_id=$1', [id]);
    await db('DELETE FROM attendance WHERE employee_id=$1', [id]);
    await db('DELETE FROM leave_balances WHERE employee_id=$1', [id]);
    await db('DELETE FROM leave_requests WHERE employee_id=$1', [id]);
    await db('DELETE FROM employee_documents WHERE employee_id=$1', [id]);
    await db('DELETE FROM employee_skills WHERE employee_id=$1', [id]);
    await db('DELETE FROM certifications WHERE employee_id=$1', [id]);
    // Delete employee
    const r = await db('DELETE FROM employees WHERE id=$1 RETURNING id', [id]);
    if (!r.rows.length) return res.status(404).json({ success: false, message: 'Employee not found' });
    res.json({ success: true, message: 'Employee removed successfully' });
  } catch(e) { res.status(500).json({ success: false, message: e.message }); }
});


// ── EMPLOYEE EDUCATION ────────────────────────────
app.get('/api/employees/:id/education', auth, async (req, res) => {
  try {
    const r = await db('SELECT * FROM employee_education WHERE employee_id=$1 ORDER BY year DESC', [req.params.id]);
    res.json({ success: true, data: r.rows });
  } catch(e) { 
    // Table may not exist yet
    res.json({ success: true, data: [] }); 
  }
});

app.post('/api/employees/:id/education', auth, async (req, res) => {
  try {
    const { items } = req.body;
    // Create table if not exists
    await db(`CREATE TABLE IF NOT EXISTS employee_education (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      employee_id UUID REFERENCES employees(id) ON DELETE CASCADE,
      type VARCHAR(50), inst VARCHAR(200), course VARCHAR(200),
      spec VARCHAR(200), year INTEGER, score VARCHAR(50),
      certno VARCHAR(100), board VARCHAR(200),
      cert_file TEXT, cert_file_name VARCHAR(200),
      created_at TIMESTAMPTZ DEFAULT NOW()
    )`);
    // Delete existing and re-insert
    await db('DELETE FROM employee_education WHERE employee_id=$1', [req.params.id]);
    for (const item of (items||[])) {
      if (!item.inst && !item.type) continue;
      await db(`INSERT INTO employee_education (employee_id,type,inst,course,spec,year,score,certno,board,cert_file,cert_file_name)
        VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`,
        [req.params.id, item.type||null, item.inst||null, item.course||null, item.spec||null,
         item.year?parseInt(item.year):null, item.score||null, item.certno||null, item.board||null,
         item.certFile||null, item.certFileName||null]);
    }
    res.json({ success: true, message: 'Education saved!' });
  } catch(e) { res.status(500).json({ success: false, message: e.message }); }
});

// ── EMPLOYEE EXPERIENCE ───────────────────────────
app.get('/api/employees/:id/experience', auth, async (req, res) => {
  try {
    const r = await db('SELECT * FROM employee_experience WHERE employee_id=$1 ORDER BY from_date DESC', [req.params.id]);
    res.json({ success: true, data: r.rows });
  } catch(e) { 
    res.json({ success: true, data: [] }); 
  }
});

app.post('/api/employees/:id/experience', auth, async (req, res) => {
  try {
    const { items } = req.body;
    await db(`CREATE TABLE IF NOT EXISTS employee_experience (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      employee_id UUID REFERENCES employees(id) ON DELETE CASCADE,
      company VARCHAR(200), role VARCHAR(200), dept VARCHAR(100),
      loc VARCHAR(100), from_date VARCHAR(20), to_date VARCHAR(20),
      is_current BOOLEAN DEFAULT false, ctc NUMERIC,
      reason VARCHAR(200), responsibilities TEXT,
      exp_file TEXT, exp_file_name VARCHAR(200),
      created_at TIMESTAMPTZ DEFAULT NOW()
    )`);
    await db('DELETE FROM employee_experience WHERE employee_id=$1', [req.params.id]);
    for (const item of (items||[])) {
      if (!item.company && !item.role) continue;
      await db(`INSERT INTO employee_experience (employee_id,company,role,dept,loc,from_date,to_date,is_current,ctc,reason,responsibilities,exp_file,exp_file_name)
        VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)`,
        [req.params.id, item.company||null, item.role||null, item.dept||null, item.loc||null,
         item.from||null, item.to||null, item.current||false,
         item.ctc?parseFloat(item.ctc):null, item.reason||null, item.resp||null,
         item.expFile||null, item.expFileName||null]);
    }
    res.json({ success: true, message: 'Experience saved!' });
  } catch(e) { res.status(500).json({ success: false, message: e.message }); }
});


// ═══════════════════════════════════════════════════
// PHASE 6 — PERFORMANCE MANAGEMENT
// ═══════════════════════════════════════════════════

// ── PERFORMANCE GOALS ─────────────────────────────
app.get('/api/performance/goals', auth, async (req, res) => {
  try {
    await db(`CREATE TABLE IF NOT EXISTS performance_goals (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      employee_id UUID REFERENCES employees(id) ON DELETE CASCADE,
      set_by UUID REFERENCES employees(id),
      title VARCHAR(300) NOT NULL,
      description TEXT,
      category VARCHAR(100),
      priority VARCHAR(20) DEFAULT 'Medium',
      target NUMERIC,
      progress INTEGER DEFAULT 0,
      status VARCHAR(30) DEFAULT 'Pending',
      target_date DATE,
      completed_at TIMESTAMPTZ,
      created_at TIMESTAMPTZ DEFAULT NOW(),
      updated_at TIMESTAMPTZ DEFAULT NOW()
    )`);
    let query, params = [];
    if (req.user.role === 'employee') {
      query = `SELECT g.*, e.first_name, e.last_name FROM performance_goals g
        JOIN employees e ON e.id=g.employee_id
        WHERE g.employee_id=(SELECT id FROM employees WHERE id=(SELECT employee_id FROM users WHERE id=$1))
        ORDER BY g.created_at DESC`;
      params = [req.user.userId];
    } else {
      query = `SELECT g.*, e.first_name, e.last_name FROM performance_goals g
        JOIN employees e ON e.id=g.employee_id ORDER BY g.created_at DESC`;
    }
    const r = await db(query, params);
    res.json({ success: true, data: r.rows });
  } catch(e) { res.status(500).json({ success: false, message: e.message }); }
});

app.post('/api/performance/goals', auth, async (req, res) => {
  try {
    const { employeeId, title, description, category, priority, target, targetDate } = req.body;
    if (!employeeId || !title) return res.status(400).json({ success: false, message: 'Employee and title required' });
    const setter = await db('SELECT id FROM employees WHERE id=(SELECT employee_id FROM users WHERE id=$1)', [req.user.userId]);
    const setById = setter.rows[0]?.id || null;
    const r = await db(`INSERT INTO performance_goals (employee_id,set_by,title,description,category,priority,target,target_date)
      VALUES ($1,$2,$3,$4,$5,$6,$7,$8) RETURNING *`,
      [employeeId, setById, title, description||null, category||null, priority||'Medium', target||null, targetDate||null]);
    // Create notification
    try {
      const u = await db('SELECT id FROM users WHERE employee_id=$1', [employeeId]);
      if (u.rows.length) {
        await db(`INSERT INTO notifications (user_id,title,message) VALUES ($1,$2,$3)`,
          [u.rows[0].id, 'New Goal Assigned', title]);
      }
    } catch(e2) {}
    res.status(201).json({ success: true, message: 'Goal set!', data: r.rows[0] });
  } catch(e) { res.status(500).json({ success: false, message: e.message }); }
});

app.put('/api/performance/goals/:id', auth, async (req, res) => {
  try {
    const { progress, status, description } = req.body;
    const sets = [], params = [];
    if (progress !== undefined) { params.push(progress); sets.push('progress=$' + params.length); }
    if (status) { params.push(status); sets.push('status=$' + params.length); }
    if (description) { params.push(description); sets.push('description=$' + params.length); }
    if (!sets.length) return res.status(400).json({ success: false, message: 'Nothing to update' });
    if (status === 'Completed') { sets.push('completed_at=NOW()'); }
    params.push(req.params.id);
    await db(`UPDATE performance_goals SET ${sets.join(',')},updated_at=NOW() WHERE id=$${params.length}`, params);
    res.json({ success: true, message: 'Goal updated!' });
  } catch(e) { res.status(500).json({ success: false, message: e.message }); }
});

// ── PERFORMANCE RATINGS ───────────────────────────
app.get('/api/performance/ratings', auth, async (req, res) => {
  try {
    await db(`CREATE TABLE IF NOT EXISTS performance_ratings (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      employee_id UUID REFERENCES employees(id) ON DELETE CASCADE,
      reviewer_id UUID REFERENCES employees(id),
      rating INTEGER CHECK(rating>=1 AND rating<=5),
      comments TEXT,
      period INTEGER DEFAULT EXTRACT(YEAR FROM NOW()),
      created_at TIMESTAMPTZ DEFAULT NOW()
    )`);
    const r = await db(`SELECT pr.*, 
      e.first_name||' '||e.last_name AS emp_name,
      r.first_name||' '||r.last_name AS reviewer_name
      FROM performance_ratings pr
      JOIN employees e ON e.id=pr.employee_id
      LEFT JOIN employees r ON r.id=pr.reviewer_id
      ORDER BY pr.created_at DESC LIMIT 50`);
    res.json({ success: true, data: r.rows });
  } catch(e) { res.status(500).json({ success: false, message: e.message }); }
});

app.post('/api/performance/ratings', auth, async (req, res) => {
  try {
    const { employeeId, rating, comments, period } = req.body;
    if (!employeeId || !rating) return res.status(400).json({ success: false, message: 'Employee and rating required' });
    const reviewer = await db('SELECT id FROM employees WHERE id=(SELECT employee_id FROM users WHERE id=$1)', [req.user.userId]);
    const r = await db(`INSERT INTO performance_ratings (employee_id,reviewer_id,rating,comments,period)
      VALUES ($1,$2,$3,$4,$5) RETURNING *`,
      [employeeId, reviewer.rows[0]?.id||null, rating, comments||null, period||new Date().getFullYear()]);
    res.status(201).json({ success: true, message: 'Rating submitted!', data: r.rows[0] });
  } catch(e) { res.status(500).json({ success: false, message: e.message }); }
});

console.log('Phase 6 Performance API loaded!');


// ═══════════════════════════════════════════════════
// PHASE 7 — HELPDESK API
// ═══════════════════════════════════════════════════

app.get('/api/helpdesk/tickets', auth, async (req, res) => {
  try {
    await db(`CREATE TABLE IF NOT EXISTS helpdesk_tickets (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      ticket_no SERIAL,
      employee_id UUID REFERENCES employees(id) ON DELETE SET NULL,
      category VARCHAR(50), priority VARCHAR(20) DEFAULT 'Medium',
      subject VARCHAR(300) NOT NULL, description TEXT,
      status VARCHAR(30) DEFAULT 'Open',
      assigned_to UUID REFERENCES employees(id),
      resolution TEXT, resolved_at TIMESTAMPTZ,
      created_at TIMESTAMPTZ DEFAULT NOW(), updated_at TIMESTAMPTZ DEFAULT NOW()
    )`);
    let query, params = [];
    const { my, category } = req.query;
    if (my === 'true') {
      query = `SELECT h.*, e.first_name, e.last_name FROM helpdesk_tickets h
        LEFT JOIN employees e ON e.id=h.employee_id
        WHERE h.employee_id=(SELECT id FROM employees WHERE id=(SELECT employee_id FROM users WHERE id=$1))
        ORDER BY h.created_at DESC LIMIT 50`;
      params = [req.user.userId];
    } else if (category) {
      query = `SELECT h.*, e.first_name, e.last_name FROM helpdesk_tickets h
        LEFT JOIN employees e ON e.id=h.employee_id WHERE h.category=$1 ORDER BY h.created_at DESC LIMIT 50`;
      params = [category];
    } else {
      query = `SELECT h.*, e.first_name, e.last_name FROM helpdesk_tickets h
        LEFT JOIN employees e ON e.id=h.employee_id ORDER BY h.created_at DESC LIMIT 100`;
    }
    const r = await db(query, params);
    res.json({ success: true, data: r.rows });
  } catch(e) { res.status(500).json({ success: false, message: e.message }); }
});

app.get('/api/helpdesk/tickets/:id', auth, async (req, res) => {
  try {
    const r = await db(`SELECT h.*, e.first_name, e.last_name FROM helpdesk_tickets h
      LEFT JOIN employees e ON e.id=h.employee_id WHERE h.id=$1`, [req.params.id]);
    if (!r.rows.length) return res.status(404).json({ success: false, message: 'Ticket not found' });
    res.json({ success: true, data: r.rows[0] });
  } catch(e) { res.status(500).json({ success: false, message: e.message }); }
});

app.post('/api/helpdesk/tickets', auth, async (req, res) => {
  try {
    const { category, priority, subject, description } = req.body;
    if (!subject || !description) return res.status(400).json({ success: false, message: 'Subject and description required' });
    const emp = await db('SELECT id FROM employees WHERE id=(SELECT employee_id FROM users WHERE id=$1)', [req.user.userId]);
    const empId = emp.rows[0]?.id || null;
    const r = await db(`INSERT INTO helpdesk_tickets (employee_id,category,priority,subject,description)
      VALUES ($1,$2,$3,$4,$5) RETURNING *`,
      [empId, category||'Other', priority||'Medium', subject, description]);
    // Notify HR
    try {
      const hrs = await db("SELECT id FROM users WHERE role='hr' OR role='admin' LIMIT 3");
      for (const u of hrs.rows) {
        await db('INSERT INTO notifications (user_id,title,message) VALUES ($1,$2,$3)',
          [u.id, 'New Helpdesk Ticket', subject]);
      }
    } catch(e2) {}
    res.status(201).json({ success: true, message: 'Ticket raised!', data: r.rows[0] });
  } catch(e) { res.status(500).json({ success: false, message: e.message }); }
});

app.put('/api/helpdesk/tickets/:id', auth, async (req, res) => {
  try {
    const { status, resolution, assignedTo } = req.body;
    const sets = [], params = [];
    if (status) { params.push(status); sets.push('status=$'+params.length); }
    if (resolution) { params.push(resolution); sets.push('resolution=$'+params.length); }
    if (assignedTo) { params.push(assignedTo); sets.push('assigned_to=$'+params.length); }
    if (status === 'Resolved') sets.push('resolved_at=NOW()');
    if (!sets.length) return res.status(400).json({ success: false, message: 'Nothing to update' });
    params.push(req.params.id);
    await db(`UPDATE helpdesk_tickets SET ${sets.join(',')},updated_at=NOW() WHERE id=$${params.length}`, params);
    res.json({ success: true, message: 'Ticket updated!' });
  } catch(e) { res.status(500).json({ success: false, message: e.message }); }
});

// Attendance my-today endpoint
app.get('/api/attendance/my-today', auth, async (req, res) => {
  try {
    const today = new Date().toISOString().split('T')[0];
    const r = await db(`SELECT a.* FROM attendance a
      JOIN employees e ON e.id=a.employee_id
      WHERE e.id=(SELECT employee_id FROM users WHERE id=$1)
      AND DATE(a.punch_in)=$2 ORDER BY a.punch_in DESC LIMIT 1`,
      [req.user.userId, today]);
    if (!r.rows.length) return res.json({ success: false, message: 'No record today' });
    res.json({ success: true, data: r.rows[0] });
  } catch(e) { res.status(500).json({ success: false, message: e.message }); }
});

// Attendance my records
app.get('/api/attendance/my', auth, async (req, res) => {
  try {
    const limit = parseInt(req.query.limit)||30;
    const r = await db(`SELECT a.*, e.first_name, e.last_name FROM attendance a
      JOIN employees e ON e.id=a.employee_id
      WHERE e.id=(SELECT employee_id FROM users WHERE id=$1)
      ORDER BY a.punch_in DESC LIMIT $2`,
      [req.user.userId, limit]);
    res.json({ success: true, data: r.rows });
  } catch(e) { res.status(500).json({ success: false, message: e.message }); }
});

// Payroll my slips
app.get('/api/payroll/my', auth, async (req, res) => {
  try {
    const r = await db(`SELECT ps.* FROM payslips ps
      JOIN employees e ON e.id=ps.employee_id
      WHERE e.id=(SELECT employee_id FROM users WHERE id=$1)
      ORDER BY ps.year DESC, ps.month DESC LIMIT 12`,
      [req.user.userId]);
    res.json({ success: true, data: r.rows });
  } catch(e) { res.status(500).json({ success: false, message: e.message }); }
});

console.log('Phase 7 Helpdesk + Attendance + Payroll API loaded!');

// ── 404 & ERROR ───────────────────────────────────

app.use((req, res) => {
  res.status(404).json({
    success: false,
    message: `${req.method} ${req.path} not found`,
    hint: 'See /api/docs for all available endpoints'
  });
});

app.use((err, req, res, next) => {
  console.error('Unhandled error:', err.message);
  res.status(500).json({ success: false, message: err.message });
});

module.exports = app;
