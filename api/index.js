// PayPe HRMS API - hr.paype.co.in
// Single-file Vercel deployment

const express      = require('express');
const cors         = require('cors');
const bcrypt       = require('bcryptjs');
const jwt          = require('jsonwebtoken');
const { Pool }     = require('pg');

const app = express();
app.set('trust proxy', 1);

// ── MIDDLEWARE ────────────────────────────────────────────────
app.use(cors({
  origin: true,
  credentials: true,
  methods: ['GET','POST','PUT','PATCH','DELETE','OPTIONS'],
  allowedHeaders: ['Content-Type','Authorization']
}));
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));

// ── DATABASE ──────────────────────────────────────────────────
let pool;
const getPool = () => {
  if (!pool) {
    pool = new Pool({
      connectionString: process.env.DATABASE_URL,
      ssl: { rejectUnauthorized: false },
      max: 1,
      idleTimeoutMillis: 10000,
      connectionTimeoutMillis: 10000
    });
    pool.on('error', (err) => console.error('DB pool error:', err.message));
  }
  return pool;
};

const db = async (text, params) => {
  const p = getPool();
  const res = await p.query(text, params);
  return res;
};

// ── AUTH HELPERS ──────────────────────────────────────────────
const JWT_SECRET  = process.env.JWT_SECRET  || 'paype_hrms_secret_2026';
const JWT_REFRESH = process.env.JWT_REFRESH_SECRET || 'paype_hrms_refresh_2026';

const makeTokens = (userId, role) => ({
  access:  jwt.sign({ userId, role }, JWT_SECRET,  { expiresIn: '7d' }),
  refresh: jwt.sign({ userId },       JWT_REFRESH, { expiresIn: '30d' })
});

const auth = async (req, res, next) => {
  try {
    const header = req.headers.authorization;
    if (!header || !header.startsWith('Bearer ')) {
      return res.status(401).json({ success: false, message: 'No token provided' });
    }
    const decoded = jwt.verify(header.split(' ')[1], JWT_SECRET);
    const r = await db(
      `SELECT u.id, u.username, u.role, u.is_active, u.employee_id,
              e.first_name, e.last_name, e.work_email
       FROM users u LEFT JOIN employees e ON e.id = u.employee_id
       WHERE u.id = $1`, [decoded.userId]
    );
    if (!r.rows.length || !r.rows[0].is_active) {
      return res.status(401).json({ success: false, message: 'Unauthorized' });
    }
    req.user = r.rows[0];
    next();
  } catch (err) {
    if (err.name === 'TokenExpiredError') {
      return res.status(401).json({ success: false, message: 'Token expired', code: 'TOKEN_EXPIRED' });
    }
    return res.status(401).json({ success: false, message: 'Invalid token' });
  }
};

const role = (...roles) => (req, res, next) => {
  if (!roles.includes(req.user.role)) {
    return res.status(403).json({ success: false, message: 'Access denied' });
  }
  next();
};

// ═══════════════════════════════════════════════════
// ── ROUTES ─────────────────────────────────────────
// ═══════════════════════════════════════════════════

// ── ROOT ──────────────────────────────────────────
app.get('/', (req, res) => {
  res.json({
    success: true,
    message: '🚀 PayPe HRMS API is running!',
    version: '1.0.0',
    company: 'PayPe Technologies Pvt. Ltd.',
    domain: 'hr.paype.co.in',
    links: { health: '/api/health', docs: '/api/docs', login: 'POST /api/auth/login' }
  });
});

// ── HEALTH ────────────────────────────────────────
app.get('/api/health', async (req, res) => {
  let dbOk = false;
  let dbMsg = 'not configured';
  try {
    if (process.env.DATABASE_URL) {
      await db('SELECT 1');
      dbOk = true;
      dbMsg = 'connected';
    }
  } catch (err) {
    dbMsg = err.message;
  }
  res.json({
    success: true,
    status: 'healthy',
    service: 'PayPe HRMS API',
    version: '1.0.0',
    domain: 'hr.paype.co.in',
    database: { status: dbOk ? 'connected' : 'error', message: dbMsg },
    environment: process.env.NODE_ENV || 'production',
    timestamp: new Date().toISOString()
  });
});

// ── DOCS ──────────────────────────────────────────
app.get('/api/docs', (req, res) => {
  res.json({
    name: 'PayPe HRMS API',
    version: '1.0.0',
    baseUrl: 'https://hr.paype.co.in/api',
    endpoints: {
      'GET  /api/health':                        'Health check',
      'POST /api/auth/login':                    'Login',
      'POST /api/auth/refresh':                  'Refresh token',
      'GET  /api/auth/me':                       'My profile',
      'GET  /api/dashboard/stats':               'KPIs (auth)',
      'GET  /api/employees':                     'List employees (HR)',
      'POST /api/employees':                     'Add employee (HR)',
      'GET  /api/employees/:id':                 'Get employee (auth)',
      'PUT  /api/employees/:id':                 'Update employee (HR)',
      'POST /api/attendance/punch':              'Punch in/out (auth)',
      'GET  /api/attendance/today':              'Today summary (HR)',
      'GET  /api/attendance/my':                 'My records (auth)',
      'GET  /api/leave/policies':                'Leave policies (auth)',
      'GET  /api/leave/balances/my':             'My balance (auth)',
      'POST /api/leave/apply':                   'Apply leave (auth)',
      'GET  /api/leave/requests':                'All requests (HR)',
      'POST /api/leave/requests/:id/approve':    'Approve/Reject (HR)',
      'POST /api/payroll/calculate':             'Preview salary (HR)',
      'POST /api/payroll/run':                   'Process payroll (HR)',
      'GET  /api/payroll/payslip/my/:m/:y':      'My payslip (auth)'
    }
  });
});

// ── AUTH: LOGIN ───────────────────────────────────
app.post('/api/auth/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) {
      return res.status(400).json({ success: false, message: 'Username and password required' });
    }
    const r = await db(
      `SELECT u.id, u.username, u.password_hash, u.role, u.is_active, u.employee_id,
              e.first_name, e.last_name, e.work_email, e.photo_url,
              e.employee_id AS emp_code, e.work_location,
              d.name AS department_name, des.title AS designation
       FROM users u
       LEFT JOIN employees e ON e.id = u.employee_id
       LEFT JOIN departments d ON d.id = e.department_id
       LEFT JOIN designations des ON des.id = e.designation_id
       WHERE LOWER(u.username) = LOWER($1)`, [username.trim()]
    );
    if (!r.rows.length) {
      return res.status(401).json({ success: false, message: 'Invalid credentials' });
    }
    const user = r.rows[0];
    if (!user.is_active) {
      return res.status(401).json({ success: false, message: 'Account deactivated. Contact HR.' });
    }
    const valid = await bcrypt.compare(password, user.password_hash);
    if (!valid) {
      return res.status(401).json({ success: false, message: 'Invalid credentials' });
    }
    const { access, refresh } = makeTokens(user.id, user.role);
    const exp = new Date(Date.now() + 30*24*60*60*1000);
    await db('DELETE FROM refresh_tokens WHERE user_id = $1 AND expires_at < NOW()', [user.id]);
    await db(
      'INSERT INTO refresh_tokens (id, user_id, token, expires_at) VALUES (gen_random_uuid(),$1,$2,$3)',
      [user.id, refresh, exp]
    );
    await db('UPDATE users SET last_login = NOW() WHERE id = $1', [user.id]);
    return res.json({
      success: true,
      message: 'Login successful',
      data: {
        accessToken: access,
        refreshToken: refresh,
        user: {
          id: user.id,
          employeeId: user.employee_id,
          empCode: user.emp_code,
          firstName: user.first_name,
          lastName: user.last_name,
          fullName: `${user.first_name} ${user.last_name}`,
          email: user.work_email,
          role: user.role,
          department: user.department_name,
          designation: user.designation,
          location: user.work_location,
          photoUrl: user.photo_url
        }
      }
    });
  } catch (err) {
    console.error('Login error:', err.message);
    return res.status(500).json({ success: false, message: 'Server error: ' + err.message });
  }
});

// ── AUTH: REFRESH ─────────────────────────────────
app.post('/api/auth/refresh', async (req, res) => {
  try {
    const { refreshToken } = req.body;
    if (!refreshToken) return res.status(400).json({ success: false, message: 'Refresh token required' });
    const decoded = jwt.verify(refreshToken, JWT_REFRESH);
    const stored = await db(
      'SELECT * FROM refresh_tokens WHERE token = $1 AND user_id = $2 AND expires_at > NOW()',
      [refreshToken, decoded.userId]
    );
    if (!stored.rows.length) return res.status(401).json({ success: false, message: 'Invalid refresh token' });
    const userR = await db('SELECT id, role FROM users WHERE id = $1', [decoded.userId]);
    if (!userR.rows.length) return res.status(401).json({ success: false, message: 'User not found' });
    const { access, refresh: newRefresh } = makeTokens(decoded.userId, userR.rows[0].role);
    await db('DELETE FROM refresh_tokens WHERE token = $1', [refreshToken]);
    const exp = new Date(Date.now() + 30*24*60*60*1000);
    await db('INSERT INTO refresh_tokens (id,user_id,token,expires_at) VALUES (gen_random_uuid(),$1,$2,$3)',
      [decoded.userId, newRefresh, exp]);
    return res.json({ success: true, data: { accessToken: access, refreshToken: newRefresh } });
  } catch (err) {
    return res.status(401).json({ success: false, message: 'Invalid refresh token' });
  }
});

// ── AUTH: LOGOUT ──────────────────────────────────
app.post('/api/auth/logout', async (req, res) => {
  try {
    const { refreshToken } = req.body;
    if (refreshToken) await db('DELETE FROM refresh_tokens WHERE token = $1', [refreshToken]);
    return res.json({ success: true, message: 'Logged out' });
  } catch (err) {
    return res.status(500).json({ success: false, message: err.message });
  }
});

// ── AUTH: ME ──────────────────────────────────────
app.get('/api/auth/me', auth, (req, res) => {
  res.json({ success: true, data: req.user });
});

// ── DASHBOARD ─────────────────────────────────────
app.get('/api/dashboard/stats', auth, async (req, res) => {
  try {
    const today = new Date().toISOString().slice(0,10);
    const [emp, att, lv, pending, payroll, depts] = await Promise.all([
      db(`SELECT status, COUNT(*) c FROM employees GROUP BY status`),
      db(`SELECT COUNT(*) c FROM attendance WHERE date=$1 AND status='Present'`,[today]),
      db(`SELECT COUNT(*) c FROM leave_requests WHERE status='Approved' AND $1 BETWEEN from_date AND to_date`,[today]),
      db(`SELECT COUNT(*) c FROM leave_requests WHERE status='Pending'`),
      db(`SELECT * FROM payroll_runs WHERE status='Processed' ORDER BY year DESC, month DESC LIMIT 1`),
      db(`SELECT d.name, COUNT(e.id) c FROM departments d LEFT JOIN employees e ON e.department_id=d.id AND e.status='Active' GROUP BY d.id,d.name ORDER BY c DESC`)
    ]);
    const byStatus = {};
    emp.rows.forEach(r => { byStatus[r.status] = parseInt(r.c); });
    const total = Object.values(byStatus).reduce((a,b)=>a+b,0);
    return res.json({
      success: true,
      data: {
        employees: { total, active: byStatus['Active']||0, probation: byStatus['Probation']||0 },
        attendance: { present: parseInt(att.rows[0]?.c||0), onLeave: parseInt(lv.rows[0]?.c||0) },
        leave: { pendingApprovals: parseInt(pending.rows[0]?.c||0) },
        payroll: payroll.rows[0] || null,
        departmentStats: depts.rows
      }
    });
  } catch (err) {
    return res.status(500).json({ success: false, message: err.message });
  }
});

// ── EMPLOYEES: LIST ───────────────────────────────
app.get('/api/employees', auth, role('admin','hr','manager'), async (req, res) => {
  try {
    const { department, status, search, page=1, limit=20 } = req.query;
    const conditions = [], params = [];
    if (department) { params.push(department); conditions.push(`e.department_id=$${params.length}`); }
    if (status)     { params.push(status);     conditions.push(`e.status=$${params.length}`); }
    if (search) {
      params.push(`%${search}%`);
      conditions.push(`(e.first_name ILIKE $${params.length} OR e.last_name ILIKE $${params.length} OR e.work_email ILIKE $${params.length} OR e.employee_id ILIKE $${params.length})`);
    }
    const where = conditions.length ? 'WHERE '+conditions.join(' AND ') : '';
    params.push(parseInt(limit), (parseInt(page)-1)*parseInt(limit));
    const [data, count] = await Promise.all([
      db(`SELECT e.id,e.employee_id,e.first_name,e.last_name,e.work_email,e.mobile,
               e.work_location,e.employment_type,e.date_of_joining,e.status,e.photo_url,
               d.name AS department_name, des.title AS designation
          FROM employees e
          LEFT JOIN departments d ON d.id=e.department_id
          LEFT JOIN designations des ON des.id=e.designation_id
          ${where} ORDER BY e.date_of_joining DESC LIMIT $${params.length-1} OFFSET $${params.length}`, params),
      db(`SELECT COUNT(*) c FROM employees e ${where}`, params.slice(0,-2))
    ]);
    return res.json({
      success: true,
      data: {
        employees: data.rows,
        pagination: { total: parseInt(count.rows[0].c), page: parseInt(page), limit: parseInt(limit) }
      }
    });
  } catch (err) {
    return res.status(500).json({ success: false, message: err.message });
  }
});

// ── EMPLOYEES: GET ONE ────────────────────────────
app.get('/api/employees/:id', auth, async (req, res) => {
  try {
    const r = await db(
      `SELECT e.*,d.name AS department_name,des.title AS designation
       FROM employees e
       LEFT JOIN departments d ON d.id=e.department_id
       LEFT JOIN designations des ON des.id=e.designation_id
       WHERE e.id=$1`, [req.params.id]
    );
    if (!r.rows.length) return res.status(404).json({ success: false, message: 'Employee not found' });
    const sal = await db('SELECT * FROM salary_structures WHERE employee_id=$1 AND is_active=true LIMIT 1',[req.params.id]);
    const lv  = await db(`SELECT lb.*,lp.name,lp.code FROM leave_balances lb JOIN leave_policies lp ON lp.id=lb.leave_policy_id WHERE lb.employee_id=$1 AND lb.year=EXTRACT(YEAR FROM NOW())`,[req.params.id]);
    return res.json({ success: true, data: { ...r.rows[0], salary: sal.rows[0]||null, leaveBalances: lv.rows } });
  } catch (err) {
    return res.status(500).json({ success: false, message: err.message });
  }
});

// ── EMPLOYEES: CREATE ─────────────────────────────
app.post('/api/employees', auth, role('admin','hr'), async (req, res) => {
  try {
    const { firstName,lastName,workEmail,mobile,departmentId,designationId,workLocation,dateOfJoining,employmentType,annualCtc } = req.body;
    if (!firstName||!lastName||!workEmail||!mobile) {
      return res.status(400).json({ success: false, message: 'firstName, lastName, workEmail, mobile required' });
    }
    const cnt = await db('SELECT COUNT(*) c FROM employees');
    const empCode = 'PPC' + String(parseInt(cnt.rows[0].c)+1).padStart(3,'0');
    const r = await db(
      `INSERT INTO employees (id,employee_id,first_name,last_name,work_email,mobile,department_id,designation_id,work_location,employment_type,date_of_joining,created_by)
       VALUES (gen_random_uuid(),$1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
       RETURNING id,employee_id,first_name,last_name,work_email`,
      [empCode,firstName,lastName,workEmail.toLowerCase(),mobile,departmentId||null,designationId||null,workLocation||null,employmentType||'Full-Time',dateOfJoining||null,req.user.id]
    );
    const empId = r.rows[0].id;
    const tempPass = firstName.toLowerCase()+new Date().getFullYear();
    const hash = await bcrypt.hash(tempPass,12);
    await db('INSERT INTO users (id,employee_id,username,password_hash,role) VALUES (gen_random_uuid(),$1,$2,$3,$4)',
      [empId,workEmail.toLowerCase(),hash,'employee']);
    if (annualCtc) {
      const gm=annualCtc/12, basic=gm*0.5, hra=basic*0.5, rem=gm-basic-hra, spl=rem*0.5, conv=rem*0.5;
      const pfe=basic*0.12, pfer=basic*0.0425, esic=gm<=21000?gm*0.0075:0, net=gm-pfe-esic;
      await db(`INSERT INTO salary_structures (id,employee_id,effective_from,annual_ctc,basic,hra,special_allowance,conveyance,pf_employee,pf_employer,esic_employee,net_salary,is_active)
                VALUES (gen_random_uuid(),$1,NOW(),$2,$3,$4,$5,$6,$7,$8,$9,$10,true)`,
        [empId,annualCtc,basic.toFixed(2),hra.toFixed(2),spl.toFixed(2),conv.toFixed(2),pfe.toFixed(2),pfer.toFixed(2),esic.toFixed(2),net.toFixed(2)]);
    }
    return res.status(201).json({
      success: true,
      message: `Employee ${empCode} created. Temp password: ${tempPass}`,
      data: r.rows[0]
    });
  } catch (err) {
    if (err.code==='23505') return res.status(409).json({ success:false, message:'Email already exists' });
    return res.status(500).json({ success: false, message: err.message });
  }
});

// ── EMPLOYEES: UPDATE ─────────────────────────────
app.put('/api/employees/:id', auth, role('admin','hr'), async (req, res) => {
  try {
    const map = {firstName:'first_name',lastName:'last_name',mobile:'mobile',workLocation:'work_location',bloodGroup:'blood_group',status:'status',departmentId:'department_id',designationId:'designation_id'};
    const sets=[],params=[];
    for(const[k,v] of Object.entries(req.body)){
      const col=map[k]||null;
      if(col&&v!==undefined){params.push(v);sets.push(`${col}=$${params.length}`);}
    }
    if(!sets.length) return res.status(400).json({success:false,message:'No valid fields'});
    params.push(req.params.id);
    await db(`UPDATE employees SET ${sets.join(',')},updated_at=NOW() WHERE id=$${params.length}`,params);
    return res.json({success:true,message:'Employee updated'});
  } catch(err){
    return res.status(500).json({success:false,message:err.message});
  }
});

// ── ATTENDANCE: PUNCH IN/OUT ──────────────────────
app.post('/api/attendance/punch', auth, async (req, res) => {
  try {
    const today = new Date().toISOString().slice(0,10);
    const { location } = req.body;
    const existing = await db('SELECT * FROM attendance WHERE employee_id=$1 AND date=$2',[req.user.employee_id,today]);
    if (!existing.rows.length) {
      await db(`INSERT INTO attendance (id,employee_id,date,punch_in,status,location_in) VALUES (gen_random_uuid(),$1,$2,NOW(),'Present',$3)`,
        [req.user.employee_id,today,location||null]);
      return res.json({success:true,message:'Punched In!',data:{action:'punch_in',time:new Date().toISOString()}});
    }
    const rec = existing.rows[0];
    if (rec.punch_out) return res.status(400).json({success:false,message:'Already punched out today'});
    const hrs = ((new Date()-new Date(rec.punch_in))/3600000).toFixed(2);
    await db('UPDATE attendance SET punch_out=NOW(),hours_worked=$1,location_out=$2,updated_at=NOW() WHERE employee_id=$3 AND date=$4',
      [hrs,location||null,req.user.employee_id,today]);
    return res.json({success:true,message:'Punched Out!',data:{action:'punch_out',hoursWorked:parseFloat(hrs)}});
  } catch(err){
    return res.status(500).json({success:false,message:err.message});
  }
});

// ── ATTENDANCE: TODAY ─────────────────────────────
app.get('/api/attendance/today', auth, role('admin','hr','manager'), async (req, res) => {
  try {
    const today = new Date().toISOString().slice(0,10);
    const [recs, total] = await Promise.all([
      db(`SELECT a.*,e.first_name,e.last_name,e.employee_id AS emp_code,d.name AS dept FROM attendance a
          JOIN employees e ON e.id=a.employee_id LEFT JOIN departments d ON d.id=e.department_id
          WHERE a.date=$1 ORDER BY a.punch_in ASC NULLS LAST`,[today]),
      db(`SELECT COUNT(*) c FROM employees WHERE status='Active'`)
    ]);
    const present=recs.rows.filter(r=>r.status==='Present').length;
    return res.json({success:true,data:{date:today,summary:{total:parseInt(total.rows[0].c),present,absent:parseInt(total.rows[0].c)-present},records:recs.rows}});
  } catch(err){
    return res.status(500).json({success:false,message:err.message});
  }
});

// ── ATTENDANCE: MINE ──────────────────────────────
app.get('/api/attendance/my', auth, async (req, res) => {
  try {
    const m=parseInt(req.query.month)||new Date().getMonth()+1;
    const y=parseInt(req.query.year)||new Date().getFullYear();
    const r=await db(`SELECT * FROM attendance WHERE employee_id=$1 AND EXTRACT(MONTH FROM date)=$2 AND EXTRACT(YEAR FROM date)=$3 ORDER BY date DESC`,[req.user.employee_id,m,y]);
    const today=new Date().toISOString().slice(0,10);
    const td=await db('SELECT * FROM attendance WHERE employee_id=$1 AND date=$2',[req.user.employee_id,today]);
    return res.json({success:true,data:{month:m,year:y,today:td.rows[0]||null,records:r.rows,
      summary:{present:r.rows.filter(x=>x.status==='Present').length,totalHours:r.rows.reduce((s,x)=>s+(parseFloat(x.hours_worked)||0),0).toFixed(1)}}});
  } catch(err){
    return res.status(500).json({success:false,message:err.message});
  }
});

// ── LEAVE: POLICIES ───────────────────────────────
app.get('/api/leave/policies', auth, async (req, res) => {
  try {
    const r=await db('SELECT * FROM leave_policies ORDER BY name');
    return res.json({success:true,data:r.rows});
  } catch(err){ return res.status(500).json({success:false,message:err.message}); }
});

// ── LEAVE: MY BALANCE ─────────────────────────────
app.get('/api/leave/balances/my', auth, async (req, res) => {
  try {
    const y=new Date().getFullYear();
    const r=await db(`SELECT lb.*,lp.name,lp.code,lp.days_per_year FROM leave_balances lb JOIN leave_policies lp ON lp.id=lb.leave_policy_id WHERE lb.employee_id=$1 AND lb.year=$2 ORDER BY lp.name`,[req.user.employee_id,y]);
    return res.json({success:true,data:r.rows});
  } catch(err){ return res.status(500).json({success:false,message:err.message}); }
});

// ── LEAVE: MY REQUESTS ────────────────────────────
app.get('/api/leave/requests/my', auth, async (req, res) => {
  try {
    const r=await db(`SELECT lr.*,lp.name AS leave_type FROM leave_requests lr JOIN leave_policies lp ON lp.id=lr.leave_policy_id WHERE lr.employee_id=$1 ORDER BY lr.created_at DESC LIMIT 20`,[req.user.employee_id]);
    return res.json({success:true,data:r.rows});
  } catch(err){ return res.status(500).json({success:false,message:err.message}); }
});

// ── LEAVE: ALL REQUESTS (HR) ──────────────────────
app.get('/api/leave/requests', auth, role('admin','hr','manager'), async (req, res) => {
  try {
    const status=req.query.status||'Pending';
    const r=await db(`SELECT lr.*,lp.name AS leave_type,e.first_name||' '||e.last_name AS employee_name,e.employee_id AS emp_code
      FROM leave_requests lr JOIN leave_policies lp ON lp.id=lr.leave_policy_id JOIN employees e ON e.id=lr.employee_id
      WHERE ($1='All' OR lr.status=$1) ORDER BY lr.created_at DESC LIMIT 50`,[status]);
    return res.json({success:true,data:r.rows});
  } catch(err){ return res.status(500).json({success:false,message:err.message}); }
});

// ── LEAVE: APPLY ──────────────────────────────────
app.post('/api/leave/apply', auth, async (req, res) => {
  try {
    const {leavePolicyId,fromDate,toDate,reason}=req.body;
    if(!leavePolicyId||!fromDate||!toDate||!reason) return res.status(400).json({success:false,message:'All fields required'});
    let d=new Date(fromDate),days=0;
    const end=new Date(toDate);
    while(d<=end){ if(d.getDay()!==0&&d.getDay()!==6)days++; d.setDate(d.getDate()+1); }
    if(days<=0) return res.status(400).json({success:false,message:'Invalid date range'});
    const bal=await db('SELECT * FROM leave_balances WHERE employee_id=$1 AND leave_policy_id=$2 AND year=EXTRACT(YEAR FROM NOW())',[req.user.employee_id,leavePolicyId]);
    if(bal.rows.length&&parseFloat(bal.rows[0].balance)<days) return res.status(400).json({success:false,message:`Insufficient balance. Available: ${bal.rows[0].balance} days, Requested: ${days}`});
    await db(`INSERT INTO leave_requests (id,employee_id,leave_policy_id,from_date,to_date,days,reason,status) VALUES (gen_random_uuid(),$1,$2,$3,$4,$5,$6,'Pending')`,[req.user.employee_id,leavePolicyId,fromDate,toDate,days,reason]);
    return res.status(201).json({success:true,message:`Leave applied for ${days} day(s). Pending approval.`});
  } catch(err){ return res.status(500).json({success:false,message:err.message}); }
});

// ── LEAVE: APPROVE / REJECT ───────────────────────
app.post('/api/leave/requests/:id/approve', auth, role('admin','hr','manager'), async (req, res) => {
  try {
    const {action,rejectionNote}=req.body;
    if(!['Approved','Rejected'].includes(action)) return res.status(400).json({success:false,message:'Action must be Approved or Rejected'});
    const lr=await db('SELECT * FROM leave_requests WHERE id=$1',[req.params.id]);
    if(!lr.rows.length) return res.status(404).json({success:false,message:'Request not found'});
    if(lr.rows[0].status!=='Pending') return res.status(400).json({success:false,message:'Already processed'});
    await db('UPDATE leave_requests SET status=$1,approved_by=$2,approved_at=NOW(),rejection_note=$3 WHERE id=$4',[action,req.user.employee_id,rejectionNote||null,req.params.id]);
    if(action==='Approved'){
      await db(`UPDATE leave_balances SET used=used+$1,balance=GREATEST(balance-$1,0) WHERE employee_id=$2 AND leave_policy_id=$3 AND year=EXTRACT(YEAR FROM NOW())`,[lr.rows[0].days,lr.rows[0].employee_id,lr.rows[0].leave_policy_id]);
    }
    return res.json({success:true,message:`Leave ${action.toLowerCase()}`});
  } catch(err){ return res.status(500).json({success:false,message:err.message}); }
});

// ── PAYROLL: CALCULATE ────────────────────────────
app.post('/api/payroll/calculate', auth, async (req, res) => {
  try {
    const ctc=parseFloat(req.body.annualCtc)||0;
    if(!ctc) return res.status(400).json({success:false,message:'annualCtc required'});
    const bp=parseFloat(req.body.basicPct)||0.5;
    const gm=ctc/12,basic=gm*bp,hra=basic*0.5,rem=gm-basic-hra,spl=rem*0.5,conv=rem*0.5;
    const pfe=basic*0.12,pfer=basic*0.0425,esic=gm<=21000?gm*0.0075:0,pt=gm>15000?200:0;
    const ded=pfe+esic+pt,net=gm-ded;
    return res.json({success:true,data:{annualCtc:ctc,monthly:+gm.toFixed(2),basic:+basic.toFixed(2),hra:+hra.toFixed(2),specialAllowance:+spl.toFixed(2),conveyance:+conv.toFixed(2),pfEmployee:+pfe.toFixed(2),pfEmployer:+pfer.toFixed(2),esicEmployee:+esic.toFixed(2),professionalTax:pt,totalDeductions:+ded.toFixed(2),netSalary:+net.toFixed(2)}});
  } catch(err){ return res.status(500).json({success:false,message:err.message}); }
});

// ── PAYROLL: RUN ──────────────────────────────────
app.post('/api/payroll/run', auth, role('admin','hr'), async (req, res) => {
  try {
    const m=parseInt(req.body.month)||new Date().getMonth()+1;
    const y=parseInt(req.body.year)||new Date().getFullYear();
    const existing=await db('SELECT id,status FROM payroll_runs WHERE month=$1 AND year=$2',[m,y]);
    if(existing.rows.length&&existing.rows[0].status==='Processed') return res.status(409).json({success:false,message:`Payroll for ${m}/${y} already processed`});
    const emps=await db(`SELECT e.id,ss.basic,ss.hra,ss.special_allowance,ss.conveyance,ss.pf_employee,ss.esic_employee,ss.professional_tax FROM employees e JOIN salary_structures ss ON ss.employee_id=e.id AND ss.is_active=true WHERE e.status='Active'`);
    let tg=0,td=0,tn=0;
    let runId;
    if(existing.rows.length){ runId=existing.rows[0].id; await db('UPDATE payroll_runs SET status=$1 WHERE id=$2',['Processing',runId]); }
    else { const rr=await db(`INSERT INTO payroll_runs (id,month,year,status) VALUES (gen_random_uuid(),$1,$2,'Processing') RETURNING id`,[m,y]); runId=rr.rows[0].id; }
    for(const e of emps.rows){
      const g=+e.basic+ +e.hra+ +e.special_allowance+ +e.conveyance;
      const d=+e.pf_employee+ +e.esic_employee+ +e.professional_tax;
      const n=g-d; tg+=g; td+=d; tn+=n;
      await db('DELETE FROM payslips WHERE employee_id=$1 AND month=$2 AND year=$3',[e.id,m,y]);
      await db(`INSERT INTO payslips (id,payroll_run_id,employee_id,month,year,basic,hra,special_allowance,conveyance,gross_salary,pf_employee,esic_employee,professional_tax,total_deductions,net_salary,status) VALUES (gen_random_uuid(),$1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,'Generated')`,
        [runId,e.id,m,y,e.basic,e.hra,e.special_allowance,e.conveyance,g.toFixed(2),e.pf_employee,e.esic_employee,e.professional_tax,d.toFixed(2),n.toFixed(2)]);
    }
    await db('UPDATE payroll_runs SET status=$1,total_gross=$2,total_deduct=$3,total_net=$4,processed_at=NOW(),processed_by=$5 WHERE id=$6',['Processed',tg.toFixed(2),td.toFixed(2),tn.toFixed(2),req.user.id,runId]);
    return res.json({success:true,message:`Payroll processed for ${emps.rows.length} employees`,data:{month:m,year:y,totalEmployees:emps.rows.length,totalGross:+tg.toFixed(2),totalNet:+tn.toFixed(2)}});
  } catch(err){ return res.status(500).json({success:false,message:err.message}); }
});

// ── PAYROLL: MY PAYSLIP ───────────────────────────
app.get('/api/payroll/payslip/my/:month/:year', auth, async (req, res) => {
  try {
    const r=await db(`SELECT ps.*,e.first_name,e.last_name,e.employee_id AS emp_code,e.work_email,d.name AS department_name,des.title AS designation FROM payslips ps JOIN employees e ON e.id=ps.employee_id LEFT JOIN departments d ON d.id=e.department_id LEFT JOIN designations des ON des.id=e.designation_id WHERE ps.employee_id=$1 AND ps.month=$2 AND ps.year=$3`,[req.user.employee_id,req.params.month,req.params.year]);
    if(!r.rows.length) return res.status(404).json({success:false,message:'Payslip not found'});
    return res.json({success:true,data:r.rows[0]});
  } catch(err){ return res.status(500).json({success:false,message:err.message}); }
});

// ── DEPARTMENTS ───────────────────────────────────
app.get('/api/departments', auth, async (req, res) => {
  try { const r=await db('SELECT * FROM departments ORDER BY name'); res.json({success:true,data:r.rows}); }
  catch(err){ res.status(500).json({success:false,message:err.message}); }
});

// ── NOTIFICATIONS ─────────────────────────────────
app.get('/api/notifications', auth, async (req, res) => {
  try { const r=await db('SELECT * FROM notifications WHERE user_id=$1 ORDER BY created_at DESC LIMIT 20',[req.user.id]); res.json({success:true,data:r.rows}); }
  catch(err){ res.status(500).json({success:false,message:err.message}); }
});

// ── 404 ───────────────────────────────────────────
app.use((req, res) => {
  res.status(404).json({ success: false, message: `${req.method} ${req.path} not found. See /api/docs` });
});

// ── ERROR ─────────────────────────────────────────
app.use((err, req, res, next) => {
  console.error('Error:', err.message);
  res.status(500).json({ success: false, message: err.message });
});

module.exports = app;
