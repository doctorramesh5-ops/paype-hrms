const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const { Pool } = require('pg');

const app = express();
const JWT = process.env.JWT_SECRET || 'PayPeERP@2026#SecretKey';
const PORT = process.env.PORT || 3000;

// ── MIDDLEWARE ─────────────────────────────────────────
app.use(cors({ origin: '*', methods: ['GET','POST','PUT','DELETE','PATCH'], allowedHeaders: ['Content-Type','Authorization'] }));
app.use(express.json({ limit: '10mb' }));

// ── DATABASE ───────────────────────────────────────────
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false },
  max: 5,
  idleTimeoutMillis: 30000,
});

const db = (text, params) => pool.query(text, params);

// ── AUTH MIDDLEWARE ────────────────────────────────────
async function auth(req, res, next) {
  try {
    const h = req.headers.authorization;
    if (!h || !h.startsWith('Bearer ')) return res.status(401).json({ success: false, message: 'No token' });
    const d = jwt.verify(h.split(' ')[1], JWT);
    const r = await db('SELECT u.*, c.name AS company_name FROM erp_users u LEFT JOIN erp_companies c ON c.id=u.company_id WHERE u.id=$1 AND u.is_active=true', [d.userId]);
    if (!r.rows.length) return res.status(401).json({ success: false, message: 'Unauthorized' });
    req.user = r.rows[0];
    next();
  } catch(e) { return res.status(401).json({ success: false, message: 'Invalid token' }); }
}

function canAdmin(req, res, next) {
  if (req.user.role !== 'admin') return res.status(403).json({ success: false, message: 'Admin only' });
  next();
}

// ── HEALTH & MIGRATIONS ────────────────────────────────
app.get('/api/health', async (req, res) => {
  let dbStatus = 'not configured';
  if (process.env.DATABASE_URL) {
    try {
      await db('SELECT 1');
      dbStatus = 'connected ✅';

      // Auto-migrate all tables
      const migrations = [
        // Companies (multi-tenant)
        `CREATE TABLE IF NOT EXISTS erp_companies (
          id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
          name VARCHAR(200) NOT NULL,
          gstin VARCHAR(20), pan VARCHAR(15), tan VARCHAR(10),
          address TEXT, state VARCHAR(50), email VARCHAR(200),
          mobile VARCHAR(15), website VARCHAR(200),
          financial_year VARCHAR(10) DEFAULT '2026-27',
          logo_url TEXT,
          created_at TIMESTAMPTZ DEFAULT NOW()
        )`,
        // Users
        `CREATE TABLE IF NOT EXISTS erp_users (
          id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
          company_id UUID REFERENCES erp_companies(id) ON DELETE CASCADE,
          name VARCHAR(200) NOT NULL,
          email VARCHAR(200) UNIQUE NOT NULL,
          password VARCHAR(200) NOT NULL,
          role VARCHAR(30) DEFAULT 'user',
          is_active BOOLEAN DEFAULT true,
          created_at TIMESTAMPTZ DEFAULT NOW()
        )`,
        // Chart of Accounts
        `CREATE TABLE IF NOT EXISTS coa (
          id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
          company_id UUID REFERENCES erp_companies(id) ON DELETE CASCADE,
          code VARCHAR(20) NOT NULL,
          name VARCHAR(200) NOT NULL,
          type VARCHAR(30) NOT NULL,
          subtype VARCHAR(50),
          balance_type VARCHAR(10) DEFAULT 'Debit',
          opening_balance NUMERIC(15,2) DEFAULT 0,
          current_balance NUMERIC(15,2) DEFAULT 0,
          is_active BOOLEAN DEFAULT true,
          description TEXT,
          created_at TIMESTAMPTZ DEFAULT NOW()
        )`,
        // Parties (customers + vendors)
        `CREATE TABLE IF NOT EXISTS parties (
          id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
          company_id UUID REFERENCES erp_companies(id) ON DELETE CASCADE,
          type VARCHAR(20) NOT NULL,
          name VARCHAR(200) NOT NULL,
          gstin VARCHAR(20), pan VARCHAR(15),
          email VARCHAR(200), mobile VARCHAR(15),
          address TEXT, state VARCHAR(50),
          opening_balance NUMERIC(15,2) DEFAULT 0,
          current_balance NUMERIC(15,2) DEFAULT 0,
          is_active BOOLEAN DEFAULT true,
          created_at TIMESTAMPTZ DEFAULT NOW()
        )`,
        // Journal Entries
        `CREATE TABLE IF NOT EXISTS journal_entries (
          id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
          company_id UUID REFERENCES erp_companies(id) ON DELETE CASCADE,
          entry_no VARCHAR(50),
          date DATE NOT NULL,
          reference VARCHAR(100),
          description TEXT NOT NULL,
          type VARCHAR(30) DEFAULT 'General',
          status VARCHAR(20) DEFAULT 'Posted',
          total_debit NUMERIC(15,2) DEFAULT 0,
          total_credit NUMERIC(15,2) DEFAULT 0,
          created_by UUID REFERENCES erp_users(id),
          created_at TIMESTAMPTZ DEFAULT NOW()
        )`,
        // Journal Lines
        `CREATE TABLE IF NOT EXISTS journal_lines (
          id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
          entry_id UUID REFERENCES journal_entries(id) ON DELETE CASCADE,
          account_id UUID REFERENCES coa(id),
          debit NUMERIC(15,2) DEFAULT 0,
          credit NUMERIC(15,2) DEFAULT 0,
          narration TEXT
        )`,
        // Invoices (sales + purchase)
        `CREATE TABLE IF NOT EXISTS invoices (
          id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
          company_id UUID REFERENCES erp_companies(id) ON DELETE CASCADE,
          invoice_no VARCHAR(50),
          type VARCHAR(20) NOT NULL,
          party_id UUID REFERENCES parties(id),
          party_name VARCHAR(200),
          date DATE NOT NULL,
          due_date DATE,
          subtotal NUMERIC(15,2) DEFAULT 0,
          cgst NUMERIC(15,2) DEFAULT 0,
          sgst NUMERIC(15,2) DEFAULT 0,
          igst NUMERIC(15,2) DEFAULT 0,
          total NUMERIC(15,2) DEFAULT 0,
          paid NUMERIC(15,2) DEFAULT 0,
          status VARCHAR(20) DEFAULT 'Unpaid',
          notes TEXT,
          created_by UUID REFERENCES erp_users(id),
          created_at TIMESTAMPTZ DEFAULT NOW()
        )`,
        // Invoice Lines
        `CREATE TABLE IF NOT EXISTS invoice_lines (
          id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
          invoice_id UUID REFERENCES invoices(id) ON DELETE CASCADE,
          description TEXT,
          hsn_sac VARCHAR(20),
          qty NUMERIC(10,2) DEFAULT 1,
          rate NUMERIC(15,2) DEFAULT 0,
          amount NUMERIC(15,2) DEFAULT 0,
          gst_rate NUMERIC(5,2) DEFAULT 18,
          gst_amount NUMERIC(15,2) DEFAULT 0,
          total NUMERIC(15,2) DEFAULT 0
        )`,
        // Payments
        `CREATE TABLE IF NOT EXISTS erp_payments (
          id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
          company_id UUID REFERENCES erp_companies(id) ON DELETE CASCADE,
          invoice_id UUID REFERENCES invoices(id),
          party_id UUID REFERENCES parties(id),
          type VARCHAR(20),
          date DATE NOT NULL,
          amount NUMERIC(15,2) NOT NULL,
          mode VARCHAR(30),
          reference VARCHAR(100),
          bank_account VARCHAR(100),
          notes TEXT,
          created_at TIMESTAMPTZ DEFAULT NOW()
        )`,
        // Bank Accounts
        `CREATE TABLE IF NOT EXISTS bank_accounts (
          id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
          company_id UUID REFERENCES erp_companies(id) ON DELETE CASCADE,
          name VARCHAR(200) NOT NULL,
          bank_name VARCHAR(100),
          account_no VARCHAR(50),
          ifsc VARCHAR(20),
          swift VARCHAR(20),
          branch VARCHAR(100),
          balance NUMERIC(15,2) DEFAULT 0,
          type VARCHAR(20) DEFAULT 'Current',
          is_active BOOLEAN DEFAULT true,
          created_at TIMESTAMPTZ DEFAULT NOW()
        )`,
        // Bank Transactions
        `CREATE TABLE IF NOT EXISTS bank_transactions (
          id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
          bank_account_id UUID REFERENCES bank_accounts(id) ON DELETE CASCADE,
          date DATE NOT NULL,
          description TEXT,
          debit NUMERIC(15,2) DEFAULT 0,
          credit NUMERIC(15,2) DEFAULT 0,
          balance NUMERIC(15,2) DEFAULT 0,
          reference VARCHAR(100),
          is_reconciled BOOLEAN DEFAULT false,
          created_at TIMESTAMPTZ DEFAULT NOW()
        )`,
        // TDS
        `CREATE TABLE IF NOT EXISTS tds_entries (
          id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
          company_id UUID REFERENCES erp_companies(id) ON DELETE CASCADE,
          party_id UUID REFERENCES parties(id),
          section VARCHAR(10),
          payment_amount NUMERIC(15,2),
          tds_rate NUMERIC(5,2),
          tds_amount NUMERIC(15,2),
          date DATE,
          description TEXT,
          status VARCHAR(20) DEFAULT 'Deducted',
          created_at TIMESTAMPTZ DEFAULT NOW()
        )`,
        // Fixed Assets
        `CREATE TABLE IF NOT EXISTS fixed_assets (
          id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
          company_id UUID REFERENCES erp_companies(id) ON DELETE CASCADE,
          name VARCHAR(200) NOT NULL,
          category VARCHAR(100),
          purchase_date DATE,
          cost NUMERIC(15,2),
          depreciation_rate NUMERIC(5,2),
          current_value NUMERIC(15,2),
          serial_no VARCHAR(100),
          location VARCHAR(200),
          status VARCHAR(20) DEFAULT 'Active',
          created_at TIMESTAMPTZ DEFAULT NOW()
        )`,
        // Audit Log
        `CREATE TABLE IF NOT EXISTS audit_log (
          id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
          company_id UUID REFERENCES erp_companies(id) ON DELETE CASCADE,
          user_id UUID REFERENCES erp_users(id),
          action VARCHAR(100),
          detail TEXT,
          ip VARCHAR(50),
          created_at TIMESTAMPTZ DEFAULT NOW()
        )`,
      ];

      for (const sql of migrations) {
        try { await db(sql); } catch(e2) { console.log('Migration warning:', e2.message.slice(0,80)); }
      }

      // Seed default company if none exists
      const co = await db('SELECT id FROM erp_companies LIMIT 1');
      if (!co.rows.length) {
        const newCo = await db(`INSERT INTO erp_companies (name,gstin,pan,tan,email,state,financial_year)
          VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING id`,
          ['PayPe Technologies Pvt. Ltd.','33AAMCP7960K1ZU','AAMCP7960K','CHEP24000E','accounts@paype.co.in','Tamil Nadu','2026-27']);
        const coId = newCo.rows[0].id;

        // Seed default users
        const hash = await bcrypt.hash('Admin@PayPe2026', 10);
        const hashMgr = await bcrypt.hash('Manager@PayPe2026', 10);
        const hashEmp = await bcrypt.hash('Employee@PayPe2026', 10);
        await db(`INSERT INTO erp_users (company_id,name,email,password,role) VALUES ($1,$2,$3,$4,$5)`,
          [coId,'Ramesh Muthuvel','admin@paype.co.in',hash,'admin']);
        await db(`INSERT INTO erp_users (company_id,name,email,password,role) VALUES ($1,$2,$3,$4,$5)`,
          [coId,'Accounts Manager','accounts@paype.co.in',hashMgr,'manager']);
        await db(`INSERT INTO erp_users (company_id,name,email,password,role) VALUES ($1,$2,$3,$4,$5)`,
          [coId,'Employee','employee@paype.co.in',hashEmp,'employee']);

        // Seed default Chart of Accounts
        const accounts = [
          ['1001','Cash in Hand','Asset','Current Asset','Debit',250000],
          ['1002','Yes Bank - Current Account','Asset','Current Asset','Debit',4850000],
          ['1101','Accounts Receivable','Asset','Current Asset','Debit',1250000],
          ['1201','GST Input Credit (ITC)','Asset','Current Asset','Debit',85000],
          ['1301','Prepaid Expenses','Asset','Current Asset','Debit',0],
          ['1501','Computer & IT Equipment','Asset','Fixed Asset','Debit',85000],
          ['1502','Furniture & Fixtures','Asset','Fixed Asset','Debit',120000],
          ['2001','Accounts Payable','Liability','Current Liability','Credit',450000],
          ['2101','CGST Payable','Liability','Current Liability','Credit',95000],
          ['2102','SGST Payable','Liability','Current Liability','Credit',95000],
          ['2103','IGST Payable','Liability','Current Liability','Credit',0],
          ['2201','TDS Payable','Liability','Current Liability','Credit',25000],
          ['2301','Salary Payable','Liability','Current Liability','Credit',0],
          ['3001','Share Capital','Equity','Capital','Credit',1000000],
          ['3101','Retained Earnings','Equity','Capital','Credit',850000],
          ['4001','Software Services Revenue','Revenue','Income','Credit',3500000],
          ['4002','Consulting Revenue','Revenue','Income','Credit',850000],
          ['4003','Subscription Revenue','Revenue','Income','Credit',0],
          ['5001','Salaries & Wages','Expense','Direct Expense','Debit',1200000],
          ['5101','Office Rent','Expense','Indirect Expense','Debit',180000],
          ['5102','Internet & Utilities','Expense','Indirect Expense','Debit',45000],
          ['5103','Travel & Conveyance','Expense','Indirect Expense','Debit',0],
          ['5201','Professional Fees','Expense','Indirect Expense','Debit',120000],
          ['5202','Depreciation','Expense','Indirect Expense','Debit',7826],
        ];
        for (const [code,name,type,subtype,bt,bal] of accounts) {
          await db(`INSERT INTO coa (company_id,code,name,type,subtype,balance_type,opening_balance,current_balance)
            VALUES ($1,$2,$3,$4,$5,$6,$7,$7)`, [coId,code,name,type,subtype,bt,bal]);
        }

        // Seed default parties
        const pts = [
          ['customer','MSBS Energy Pvt Ltd','22AABCM1234A1Z5','AABCM1234A','accounts@msbsenergy.com','9876543210','Tamil Nadu',5675000],
          ['vendor','AWS India','27AAAAA1234A1Z5','AAAAA1234A','billing@aws.com','1800123456','Maharashtra',85000],
          ['vendor','Yes Bank','33YESB0001367A1Z','YESBA1234A','accounts@yesbank.in','1800200000','Tamil Nadu',0],
        ];
        for (const [type,name,gstin,pan,email,mobile,state,bal] of pts) {
          await db(`INSERT INTO parties (company_id,type,name,gstin,pan,email,mobile,state,opening_balance,current_balance)
            VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$9)`, [coId,type,name,gstin,pan,email,mobile,state,bal]);
        }

        // Seed bank account
        await db(`INSERT INTO bank_accounts (company_id,name,bank_name,account_no,ifsc,swift,branch,balance,type)
          VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
          [coId,'Yes Bank - Current Account','Yes Bank','136727000000112','YESB0001367','YESBINBB','Vadavalli, Coimbatore',4850000,'Current']);

  
      // ── INVENTORY TABLES ──────────────────────────────
      const inv_migrations = [
        `CREATE TABLE IF NOT EXISTS products (
          id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
          company_id UUID REFERENCES erp_companies(id) ON DELETE CASCADE,
          name VARCHAR(200) NOT NULL,
          sku VARCHAR(100),
          hsn VARCHAR(20),
          category VARCHAR(100),
          unit VARCHAR(30) DEFAULT 'Nos',
          sale_price NUMERIC(15,2) DEFAULT 0,
          cost_price NUMERIC(15,2) DEFAULT 0,
          stock NUMERIC(10,2) DEFAULT 0,
          reorder_level NUMERIC(10,2) DEFAULT 10,
          description TEXT,
          barcode VARCHAR(100),
          is_active BOOLEAN DEFAULT true,
          created_at TIMESTAMPTZ DEFAULT NOW()
        )`,
        `CREATE TABLE IF NOT EXISTS warehouses (
          id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
          company_id UUID REFERENCES erp_companies(id) ON DELETE CASCADE,
          name VARCHAR(200) NOT NULL,
          location VARCHAR(300),
          manager VARCHAR(200),
          is_active BOOLEAN DEFAULT true,
          created_at TIMESTAMPTZ DEFAULT NOW()
        )`,
        `CREATE TABLE IF NOT EXISTS stock_movements (
          id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
          company_id UUID REFERENCES erp_companies(id) ON DELETE CASCADE,
          product_id UUID REFERENCES products(id),
          warehouse_id UUID REFERENCES warehouses(id),
          type VARCHAR(20) NOT NULL,
          qty NUMERIC(10,2) NOT NULL,
          rate NUMERIC(15,2) DEFAULT 0,
          reference VARCHAR(100),
          notes TEXT,
          date DATE NOT NULL,
          created_by UUID REFERENCES erp_users(id),
          created_at TIMESTAMPTZ DEFAULT NOW()
        )`,
        `CREATE TABLE IF NOT EXISTS purchase_orders (
          id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
          company_id UUID REFERENCES erp_companies(id) ON DELETE CASCADE,
          po_no VARCHAR(50),
          vendor_id UUID REFERENCES parties(id),
          vendor_name VARCHAR(200),
          date DATE NOT NULL,
          expected_date DATE,
          status VARCHAR(30) DEFAULT 'Draft',
          subtotal NUMERIC(15,2) DEFAULT 0,
          cgst NUMERIC(15,2) DEFAULT 0,
          sgst NUMERIC(15,2) DEFAULT 0,
          total NUMERIC(15,2) DEFAULT 0,
          notes TEXT,
          created_by UUID REFERENCES erp_users(id),
          created_at TIMESTAMPTZ DEFAULT NOW()
        )`,
        `CREATE TABLE IF NOT EXISTS purchase_order_lines (
          id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
          po_id UUID REFERENCES purchase_orders(id) ON DELETE CASCADE,
          product_id UUID REFERENCES products(id),
          description TEXT,
          qty NUMERIC(10,2) DEFAULT 1,
          rate NUMERIC(15,2) DEFAULT 0,
          gst_rate NUMERIC(5,2) DEFAULT 18,
          amount NUMERIC(15,2) DEFAULT 0,
          received_qty NUMERIC(10,2) DEFAULT 0
        )`,
        `CREATE TABLE IF NOT EXISTS sales_orders (
          id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
          company_id UUID REFERENCES erp_companies(id) ON DELETE CASCADE,
          so_no VARCHAR(50),
          customer_id UUID REFERENCES parties(id),
          customer_name VARCHAR(200),
          date DATE NOT NULL,
          delivery_date DATE,
          status VARCHAR(30) DEFAULT 'Draft',
          subtotal NUMERIC(15,2) DEFAULT 0,
          cgst NUMERIC(15,2) DEFAULT 0,
          sgst NUMERIC(15,2) DEFAULT 0,
          total NUMERIC(15,2) DEFAULT 0,
          notes TEXT,
          created_by UUID REFERENCES erp_users(id),
          created_at TIMESTAMPTZ DEFAULT NOW()
        )`,
        `CREATE TABLE IF NOT EXISTS sales_order_lines (
          id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
          so_id UUID REFERENCES sales_orders(id) ON DELETE CASCADE,
          product_id UUID REFERENCES products(id),
          description TEXT,
          qty NUMERIC(10,2) DEFAULT 1,
          rate NUMERIC(15,2) DEFAULT 0,
          gst_rate NUMERIC(5,2) DEFAULT 18,
          amount NUMERIC(15,2) DEFAULT 0
        )`,
        // ── CRM TABLES ──────────────────────────────────
        `CREATE TABLE IF NOT EXISTS leads (
          id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
          company_id UUID REFERENCES erp_companies(id) ON DELETE CASCADE,
          name VARCHAR(200) NOT NULL,
          company_name VARCHAR(200),
          email VARCHAR(200),
          phone VARCHAR(20),
          source VARCHAR(50),
          status VARCHAR(30) DEFAULT 'New',
          value NUMERIC(15,2) DEFAULT 0,
          assigned_to UUID REFERENCES erp_users(id),
          notes TEXT,
          created_at TIMESTAMPTZ DEFAULT NOW()
        )`,
        `CREATE TABLE IF NOT EXISTS opportunities (
          id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
          company_id UUID REFERENCES erp_companies(id) ON DELETE CASCADE,
          lead_id UUID REFERENCES leads(id),
          title VARCHAR(200) NOT NULL,
          value NUMERIC(15,2) DEFAULT 0,
          stage VARCHAR(50) DEFAULT 'Prospect',
          probability NUMERIC(5,2) DEFAULT 10,
          close_date DATE,
          assigned_to UUID REFERENCES erp_users(id),
          notes TEXT,
          created_at TIMESTAMPTZ DEFAULT NOW()
        )`,
        `CREATE TABLE IF NOT EXISTS quotations (
          id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
          company_id UUID REFERENCES erp_companies(id) ON DELETE CASCADE,
          quote_no VARCHAR(50),
          lead_id UUID REFERENCES leads(id),
          customer_id UUID REFERENCES parties(id),
          customer_name VARCHAR(200),
          date DATE NOT NULL,
          valid_until DATE,
          status VARCHAR(30) DEFAULT 'Draft',
          subtotal NUMERIC(15,2) DEFAULT 0,
          cgst NUMERIC(15,2) DEFAULT 0,
          sgst NUMERIC(15,2) DEFAULT 0,
          total NUMERIC(15,2) DEFAULT 0,
          notes TEXT,
          created_by UUID REFERENCES erp_users(id),
          created_at TIMESTAMPTZ DEFAULT NOW()
        )`,
        `CREATE TABLE IF NOT EXISTS quotation_lines (
          id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
          quotation_id UUID REFERENCES quotations(id) ON DELETE CASCADE,
          product_id UUID REFERENCES products(id),
          description TEXT,
          qty NUMERIC(10,2) DEFAULT 1,
          rate NUMERIC(15,2) DEFAULT 0,
          gst_rate NUMERIC(5,2) DEFAULT 18,
          amount NUMERIC(15,2) DEFAULT 0
        )`,
        `CREATE TABLE IF NOT EXISTS crm_tasks (
          id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
          company_id UUID REFERENCES erp_companies(id) ON DELETE CASCADE,
          ref_type VARCHAR(30),
          ref_id UUID,
          title VARCHAR(300) NOT NULL,
          due_date DATE,
          priority VARCHAR(20) DEFAULT 'Medium',
          status VARCHAR(30) DEFAULT 'Open',
          assigned_to UUID REFERENCES erp_users(id),
          notes TEXT,
          created_at TIMESTAMPTZ DEFAULT NOW()
        )`,
        `CREATE TABLE IF NOT EXISTS crm_activities (
          id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
          company_id UUID REFERENCES erp_companies(id) ON DELETE CASCADE,
          ref_type VARCHAR(30),
          ref_id UUID,
          type VARCHAR(50),
          notes TEXT,
          date TIMESTAMPTZ DEFAULT NOW(),
          user_id UUID REFERENCES erp_users(id)
        )`,
      ];
      for (const sql of inv_migrations) {
        try { await db(sql); } catch(e3) { console.log('Inv/CRM migration:', e3.message.slice(0,60)); }
      }

      // Seed default warehouse if none
      const wh = await db('SELECT id FROM warehouses WHERE company_id=$1 LIMIT 1', [coId]);
      if (!wh.rows.length) {
        await db(`INSERT INTO warehouses (company_id,name,location,manager) VALUES ($1,$2,$3,$4)`,
          [coId, 'Main Warehouse', 'Coimbatore, Tamil Nadu', 'Ramesh Muthuvel']);
        await db(`INSERT INTO warehouses (company_id,name,location,manager) VALUES ($1,$2,$3,$4)`,
          [coId, 'Secondary Store', 'Coimbatore, Tamil Nadu', 'Store Manager']);
      }

      // Seed sample products if none
      const prd = await db('SELECT id FROM products WHERE company_id=$1 LIMIT 1', [coId]);
      if (!prd.rows.length) {
        const sampleProducts = [
          ['PayPe HRMS Software', 'SW-001', '998313', 'Software', 'License', 9999, 0, 999, 5],
          ['PayPe ERP Software', 'SW-002', '998313', 'Software', 'License', 14999, 0, 500, 5],
          ['Laptop - Dell', 'HW-001', '84713090', 'Hardware', 'Nos', 65000, 58000, 10, 2],
          ['Office Chair', 'FN-001', '94013000', 'Furniture', 'Nos', 8500, 6000, 15, 3],
          ['A4 Paper Ream', 'ST-001', '48023900', 'Stationery', 'Packet', 350, 280, 100, 20],
        ];
        for (const [name, sku, hsn, cat, unit, sale, cost, stock, reorder] of sampleProducts) {
          await db(`INSERT INTO products (company_id,name,sku,hsn,category,unit,sale_price,cost_price,stock,reorder_level)
            VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
            [coId, name, sku, hsn, cat, unit, sale, cost, stock, reorder]);
        }
      }

      // Seed sample leads if none
      const ld = await db('SELECT id FROM leads WHERE company_id=$1 LIMIT 1', [coId]);
      if (!ld.rows.length) {
        const sampleLeads = [
          ['Vijay Kumar', 'TechStart Pvt Ltd', 'vijay@techstart.in', '9876543210', 'Website', 'Qualified', 250000],
          ['Priya Sharma', 'Retail Solutions', 'priya@retail.in', '9123456789', 'Referral', 'New', 150000],
          ['Suresh Babu', 'Manufacturing Co', 'suresh@mfg.in', '9988776655', 'Cold Call', 'Contacted', 500000],
          ['Anita Rajan', 'Hospital Group', 'anita@hospital.in', '9345678901', 'Exhibition', 'Proposal', 750000],
        ];
        for (const [name, company, email, phone, source, status, value] of sampleLeads) {
          await db(`INSERT INTO leads (company_id,name,company_name,email,phone,source,status,value) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
            [coId, name, company, email, phone, source, status, value]);
        }
      }


      // ── PROCUREMENT TABLES ────────────────────────────
      const proc_migrations = [
        `CREATE TABLE IF NOT EXISTS vendors (
          id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
          company_id UUID REFERENCES erp_companies(id) ON DELETE CASCADE,
          party_id UUID REFERENCES parties(id),
          name VARCHAR(200) NOT NULL,
          category VARCHAR(100) DEFAULT 'General',
          payment_terms INTEGER DEFAULT 30,
          bank_name VARCHAR(100),
          account_no VARCHAR(50),
          ifsc VARCHAR(20),
          rating NUMERIC(3,1) DEFAULT 5.0,
          notes TEXT,
          is_active BOOLEAN DEFAULT true,
          created_at TIMESTAMPTZ DEFAULT NOW()
        )`,
        `CREATE TABLE IF NOT EXISTS rfq (
          id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
          company_id UUID REFERENCES erp_companies(id) ON DELETE CASCADE,
          rfq_no VARCHAR(50),
          title VARCHAR(300) NOT NULL,
          required_date DATE,
          status VARCHAR(30) DEFAULT 'Open',
          notes TEXT,
          created_by UUID REFERENCES erp_users(id),
          created_at TIMESTAMPTZ DEFAULT NOW()
        )`,
        `CREATE TABLE IF NOT EXISTS rfq_lines (
          id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
          rfq_id UUID REFERENCES rfq(id) ON DELETE CASCADE,
          description TEXT,
          qty NUMERIC(10,2) DEFAULT 1,
          unit VARCHAR(30) DEFAULT 'Nos',
          specifications TEXT
        )`,
        `CREATE TABLE IF NOT EXISTS rfq_vendors (
          id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
          rfq_id UUID REFERENCES rfq(id) ON DELETE CASCADE,
          vendor_id UUID REFERENCES vendors(id),
          status VARCHAR(30) DEFAULT 'Sent',
          quoted_amount NUMERIC(15,2),
          quoted_date DATE
        )`,
        `CREATE TABLE IF NOT EXISTS purchase_approvals (
          id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
          company_id UUID REFERENCES erp_companies(id) ON DELETE CASCADE,
          po_id UUID REFERENCES purchase_orders(id),
          amount NUMERIC(15,2) DEFAULT 0,
          justification TEXT,
          status VARCHAR(30) DEFAULT 'Pending',
          remarks TEXT,
          requested_by UUID REFERENCES erp_users(id),
          approved_by UUID REFERENCES erp_users(id),
          approved_at TIMESTAMPTZ,
          created_at TIMESTAMPTZ DEFAULT NOW()
        )`,
        `CREATE TABLE IF NOT EXISTS grn (
          id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
          company_id UUID REFERENCES erp_companies(id) ON DELETE CASCADE,
          grn_no VARCHAR(50),
          po_id UUID REFERENCES purchase_orders(id),
          received_date DATE,
          quality_status VARCHAR(30) DEFAULT 'Accepted',
          notes TEXT,
          created_by UUID REFERENCES erp_users(id),
          created_at TIMESTAMPTZ DEFAULT NOW()
        )`,
        `CREATE TABLE IF NOT EXISTS grn_lines (
          id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
          grn_id UUID REFERENCES grn(id) ON DELETE CASCADE,
          product_id UUID REFERENCES products(id),
          description TEXT,
          ordered_qty NUMERIC(10,2) DEFAULT 0,
          received_qty NUMERIC(10,2) DEFAULT 0,
          rejected_qty NUMERIC(10,2) DEFAULT 0
        )`,
        `CREATE TABLE IF NOT EXISTS vendor_payments (
          id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
          company_id UUID REFERENCES erp_companies(id) ON DELETE CASCADE,
          vendor_id UUID REFERENCES parties(id),
          amount NUMERIC(15,2) NOT NULL,
          payment_date DATE NOT NULL,
          mode VARCHAR(30) DEFAULT 'NEFT',
          reference VARCHAR(100),
          bill_id UUID REFERENCES invoices(id),
          notes TEXT,
          created_by UUID REFERENCES erp_users(id),
          created_at TIMESTAMPTZ DEFAULT NOW()
        )`,
      ];
      for (const sql of proc_migrations) {
        try { await db(sql); } catch(e4) { console.log('Proc migration:', e4.message.slice(0,60)); }
      }

      console.log('✅ Default company, user and data seeded!');
      }
    } catch(e) {
      dbStatus = 'error: ' + e.message;
      console.error('DB error:', e.message);
    }
  }
  res.json({ success: true, status: 'healthy', service: 'PayPe ERP API', version: '1.0.0', domain: 'erpapi.paype.co.in', db: dbStatus, time: new Date().toISOString() });
});

// ── AUTH ───────────────────────────────────────────────
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ success: false, message: 'Email and password required' });
    const r = await db('SELECT u.*, c.name AS company_name, c.gstin, c.financial_year FROM erp_users u LEFT JOIN erp_companies c ON c.id=u.company_id WHERE u.email=$1 AND u.is_active=true', [email.toLowerCase()]);
    if (!r.rows.length) return res.status(401).json({ success: false, message: 'Invalid credentials' });
    const user = r.rows[0];
    const valid = await bcrypt.compare(password, user.password);
    if (!valid) return res.status(401).json({ success: false, message: 'Invalid credentials' });
    const token = jwt.sign({ userId: user.id, companyId: user.company_id, role: user.role }, JWT, { expiresIn: '8h' });
    res.json({ success: true, token, user: { id: user.id, name: user.name, email: user.email, role: user.role, company: user.company_name, companyId: user.company_id, gstin: user.gstin, fy: user.financial_year }});
  } catch(e) { res.status(500).json({ success: false, message: e.message }); }
});

// ── DASHBOARD ──────────────────────────────────────────
app.get('/api/dashboard', auth, async (req, res) => {
  try {
    const cid = req.user.company_id;
    const [invStats, balances, recentInv] = await Promise.all([
      db(`SELECT 
        SUM(CASE WHEN type='sales' THEN total ELSE 0 END) AS total_revenue,
        SUM(CASE WHEN type='sales' AND status='Unpaid' THEN total ELSE 0 END) AS receivable,
        SUM(CASE WHEN type='purchase' AND status='Unpaid' THEN total ELSE 0 END) AS payable,
        COUNT(CASE WHEN type='sales' AND status='Unpaid' THEN 1 END) AS ar_count,
        COUNT(CASE WHEN type='purchase' AND status='Unpaid' THEN 1 END) AS ap_count
        FROM invoices WHERE company_id=$1`, [cid]),
      db(`SELECT type, SUM(current_balance) AS total FROM coa WHERE company_id=$1 GROUP BY type`, [cid]),
      db(`SELECT * FROM invoices WHERE company_id=$1 AND type='sales' ORDER BY created_at DESC LIMIT 5`, [cid]),
    ]);
    const balMap = {};
    balances.rows.forEach(function(b){ balMap[b.type] = parseFloat(b.total)||0; });
    res.json({ success: true, data: {
      revenue: parseFloat(invStats.rows[0].total_revenue)||0,
      receivable: parseFloat(invStats.rows[0].receivable)||0,
      payable: parseFloat(invStats.rows[0].payable)||0,
      ar_count: parseInt(invStats.rows[0].ar_count)||0,
      ap_count: parseInt(invStats.rows[0].ap_count)||0,
      balances: balMap,
      recentInvoices: recentInv.rows,
    }});
  } catch(e) { res.status(500).json({ success: false, message: e.message }); }
});

// ── CHART OF ACCOUNTS ──────────────────────────────────
app.get('/api/accounts', auth, async (req, res) => {
  try {
    const r = await db('SELECT * FROM coa WHERE company_id=$1 AND is_active=true ORDER BY code', [req.user.company_id]);
    res.json({ success: true, data: r.rows });
  } catch(e) { res.status(500).json({ success: false, message: e.message }); }
});

app.post('/api/accounts', auth, async (req, res) => {
  try {
    const { code, name, type, subtype, balanceType, openingBalance, description } = req.body;
    if (!code || !name || !type) return res.status(400).json({ success: false, message: 'Code, name and type required' });
    const ob = parseFloat(openingBalance)||0;
    const r = await db(`INSERT INTO coa (company_id,code,name,type,subtype,balance_type,opening_balance,current_balance,description)
      VALUES ($1,$2,$3,$4,$5,$6,$7,$7,$8) RETURNING *`,
      [req.user.company_id, code, name, type, subtype||null, balanceType||'Debit', ob, description||null]);
    res.status(201).json({ success: true, data: r.rows[0], message: 'Account created!' });
  } catch(e) { res.status(500).json({ success: false, message: e.message }); }
});

app.put('/api/accounts/:id', auth, async (req, res) => {
  try {
    const { name, subtype, description } = req.body;
    await db('UPDATE coa SET name=$1,subtype=$2,description=$3 WHERE id=$4 AND company_id=$5',
      [name, subtype, description, req.params.id, req.user.company_id]);
    res.json({ success: true, message: 'Account updated!' });
  } catch(e) { res.status(500).json({ success: false, message: e.message }); }
});

// ── PARTIES ────────────────────────────────────────────
app.get('/api/parties', auth, async (req, res) => {
  try {
    const { type } = req.query;
    let q = 'SELECT * FROM parties WHERE company_id=$1 AND is_active=true';
    const params = [req.user.company_id];
    if (type) { params.push(type); q += ' AND (type=$2 OR type=\'both\')'; }
    q += ' ORDER BY name';
    const r = await db(q, params);
    res.json({ success: true, data: r.rows });
  } catch(e) { res.status(500).json({ success: false, message: e.message }); }
});

app.post('/api/parties', auth, async (req, res) => {
  try {
    const { type, name, gstin, pan, email, mobile, address, state, openingBalance } = req.body;
    if (!type || !name) return res.status(400).json({ success: false, message: 'Type and name required' });
    const ob = parseFloat(openingBalance)||0;
    const r = await db(`INSERT INTO parties (company_id,type,name,gstin,pan,email,mobile,address,state,opening_balance,current_balance)
      VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$10) RETURNING *`,
      [req.user.company_id, type, name, gstin||null, pan||null, email||null, mobile||null, address||null, state||null, ob]);
    res.status(201).json({ success: true, data: r.rows[0], message: 'Party added!' });
  } catch(e) { res.status(500).json({ success: false, message: e.message }); }
});

// ── INVOICES ───────────────────────────────────────────
app.get('/api/invoices', auth, async (req, res) => {
  try {
    const { type, status, limit=50 } = req.query;
    let q = 'SELECT i.*, p.name AS party_name_full, p.gstin AS party_gstin FROM invoices i LEFT JOIN parties p ON p.id=i.party_id WHERE i.company_id=$1';
    const params = [req.user.company_id];
    if (type) { params.push(type); q += ' AND i.type=$' + params.length; }
    if (status) { params.push(status); q += ' AND i.status=$' + params.length; }
    params.push(parseInt(limit));
    q += ' ORDER BY i.created_at DESC LIMIT $' + params.length;
    const r = await db(q, params);
    res.json({ success: true, data: r.rows });
  } catch(e) { res.status(500).json({ success: false, message: e.message }); }
});

app.get('/api/invoices/:id', auth, async (req, res) => {
  try {
    const inv = await db('SELECT i.*, p.name AS party_name_full, p.gstin AS party_gstin, p.email AS party_email FROM invoices i LEFT JOIN parties p ON p.id=i.party_id WHERE i.id=$1 AND i.company_id=$2', [req.params.id, req.user.company_id]);
    if (!inv.rows.length) return res.status(404).json({ success: false, message: 'Not found' });
    const lines = await db('SELECT * FROM invoice_lines WHERE invoice_id=$1', [req.params.id]);
    res.json({ success: true, data: { ...inv.rows[0], lines: lines.rows }});
  } catch(e) { res.status(500).json({ success: false, message: e.message }); }
});

app.post('/api/invoices', auth, async (req, res) => {
  try {
    const { partyId, type, date, dueDate, lines, notes, status } = req.body;
    if (!partyId || !date || !lines || !lines.length) return res.status(400).json({ success: false, message: 'Party, date and lines required' });

    // Calculate totals
    let subtotal=0, totalGST=0;
    lines.forEach(function(l) {
      const amt = (parseFloat(l.qty)||1) * (parseFloat(l.rate)||0);
      const gst = amt * (parseFloat(l.gstRate)||18) / 100;
      subtotal += amt; totalGST += gst;
    });
    const cgst = totalGST/2, sgst = totalGST/2, total = subtotal+totalGST;

    // Generate invoice number
    const count = await db('SELECT COUNT(*) FROM invoices WHERE company_id=$1 AND type=$2', [req.user.company_id, type]);
    const no = type === 'sales'
      ? `PAYPE/2026-27/${String(parseInt(count.rows[0].count)+1).padStart(3,'0')}`
      : `BILL/2026-27/${String(parseInt(count.rows[0].count)+1).padStart(3,'0')}`;

    const party = await db('SELECT name FROM parties WHERE id=$1', [partyId]);
    const r = await db(`INSERT INTO invoices (company_id,invoice_no,type,party_id,party_name,date,due_date,subtotal,cgst,sgst,total,status,notes,created_by)
      VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14) RETURNING *`,
      [req.user.company_id, no, type, partyId, party.rows[0]?.name, date, dueDate||null, subtotal, cgst, sgst, total, status||'Unpaid', notes||null, req.user.id]);
    const inv = r.rows[0];

    // Insert lines
    for (const l of lines) {
      const amt = (parseFloat(l.qty)||1) * (parseFloat(l.rate)||0);
      const gstAmt = amt * (parseFloat(l.gstRate)||18) / 100;
      await db(`INSERT INTO invoice_lines (invoice_id,description,hsn_sac,qty,rate,amount,gst_rate,gst_amount,total) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
        [inv.id, l.description, l.hsnSac||null, parseFloat(l.qty)||1, parseFloat(l.rate)||0, amt, parseFloat(l.gstRate)||18, gstAmt, amt+gstAmt]);
    }
    res.status(201).json({ success: true, data: inv, message: 'Invoice ' + no + ' created!' });
  } catch(e) { res.status(500).json({ success: false, message: e.message }); }
});

app.put('/api/invoices/:id/status', auth, async (req, res) => {
  try {
    const { status, paid } = req.body;
    await db('UPDATE invoices SET status=$1, paid=COALESCE($2,paid) WHERE id=$3 AND company_id=$4',
      [status, paid||null, req.params.id, req.user.company_id]);
    res.json({ success: true, message: 'Invoice updated!' });
  } catch(e) { res.status(500).json({ success: false, message: e.message }); }
});

// ── JOURNAL ENTRIES ────────────────────────────────────
app.get('/api/journal', auth, async (req, res) => {
  try {
    const r = await db('SELECT j.*, u.name AS created_by_name FROM journal_entries j LEFT JOIN erp_users u ON u.id=j.created_by WHERE j.company_id=$1 ORDER BY j.date DESC, j.created_at DESC LIMIT 100', [req.user.company_id]);
    res.json({ success: true, data: r.rows });
  } catch(e) { res.status(500).json({ success: false, message: e.message }); }
});

app.post('/api/journal', auth, async (req, res) => {
  try {
    const { date, reference, description, type, lines } = req.body;
    if (!date || !description || !lines || lines.length < 2) return res.status(400).json({ success: false, message: 'Date, description and at least 2 lines required' });
    let totalDr=0, totalCr=0;
    lines.forEach(function(l){ totalDr+=parseFloat(l.debit)||0; totalCr+=parseFloat(l.credit)||0; });
    if (Math.abs(totalDr-totalCr) > 0.01) return res.status(400).json({ success: false, message: 'Entry not balanced! Debit must equal Credit' });
    const count = await db('SELECT COUNT(*) FROM journal_entries WHERE company_id=$1', [req.user.company_id]);
    const entryNo = 'JE-' + String(parseInt(count.rows[0].count)+1).padStart(4,'0');
    const r = await db(`INSERT INTO journal_entries (company_id,entry_no,date,reference,description,type,total_debit,total_credit,created_by)
      VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9) RETURNING *`,
      [req.user.company_id, entryNo, date, reference||null, description, type||'General', totalDr, totalCr, req.user.id]);
    const entry = r.rows[0];
    for (const l of lines) {
      if (!l.accountId) continue;
      await db('INSERT INTO journal_lines (entry_id,account_id,debit,credit,narration) VALUES ($1,$2,$3,$4,$5)',
        [entry.id, l.accountId, parseFloat(l.debit)||0, parseFloat(l.credit)||0, l.narration||null]);
      // Update account balance
      const dr = parseFloat(l.debit)||0, cr = parseFloat(l.credit)||0;
      await db('UPDATE coa SET current_balance = current_balance + $1 WHERE id=$2', [dr-cr, l.accountId]);
    }
    res.status(201).json({ success: true, data: entry, message: 'Journal entry ' + entryNo + ' posted!' });
  } catch(e) { res.status(500).json({ success: false, message: e.message }); }
});

// ── BANK ACCOUNTS ──────────────────────────────────────
app.get('/api/bank', auth, async (req, res) => {
  try {
    const r = await db('SELECT * FROM bank_accounts WHERE company_id=$1 AND is_active=true ORDER BY name', [req.user.company_id]);
    res.json({ success: true, data: r.rows });
  } catch(e) { res.status(500).json({ success: false, message: e.message }); }
});

app.post('/api/bank', auth, async (req, res) => {
  try {
    const { name, bankName, accountNo, ifsc, swift, branch, balance, type } = req.body;
    if (!name) return res.status(400).json({ success: false, message: 'Account name required' });
    const r = await db(`INSERT INTO bank_accounts (company_id,name,bank_name,account_no,ifsc,swift,branch,balance,type) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9) RETURNING *`,
      [req.user.company_id, name, bankName||null, accountNo||null, ifsc||null, swift||null, branch||null, parseFloat(balance)||0, type||'Current']);
    res.status(201).json({ success: true, data: r.rows[0], message: 'Bank account added!' });
  } catch(e) { res.status(500).json({ success: false, message: e.message }); }
});

app.get('/api/bank/:id/transactions', auth, async (req, res) => {
  try {
    const r = await db('SELECT * FROM bank_transactions WHERE bank_account_id=$1 ORDER BY date DESC LIMIT 100', [req.params.id]);
    res.json({ success: true, data: r.rows });
  } catch(e) { res.status(500).json({ success: false, message: e.message }); }
});

// ── GST ────────────────────────────────────────────────
app.get('/api/gst/summary', auth, async (req, res) => {
  try {
    const { month, year } = req.query;
    const m = parseInt(month) || new Date().getMonth()+1;
    const y = parseInt(year) || new Date().getFullYear();
    const r = await db(`SELECT
      SUM(CASE WHEN type='sales' THEN cgst+sgst+igst ELSE 0 END) AS output_tax,
      SUM(CASE WHEN type='purchase' THEN cgst+sgst+igst ELSE 0 END) AS input_tax,
      SUM(CASE WHEN type='sales' THEN subtotal ELSE 0 END) AS taxable_sales,
      SUM(CASE WHEN type='purchase' THEN subtotal ELSE 0 END) AS taxable_purchases
      FROM invoices WHERE company_id=$1 AND EXTRACT(MONTH FROM date)=$2 AND EXTRACT(YEAR FROM date)=$3`,
      [req.user.company_id, m, y]);
    const d = r.rows[0];
    const outputTax = parseFloat(d.output_tax)||0;
    const inputTax = parseFloat(d.input_tax)||0;
    res.json({ success: true, data: {
      month: m, year: y,
      outputTax, inputTax,
      netPayable: Math.max(0, outputTax-inputTax),
      taxableSales: parseFloat(d.taxable_sales)||0,
      taxablePurchases: parseFloat(d.taxable_purchases)||0,
    }});
  } catch(e) { res.status(500).json({ success: false, message: e.message }); }
});

app.get('/api/gst/gstr1', auth, async (req, res) => {
  try {
    const r = await db(`SELECT i.*, p.gstin AS party_gstin, p.state AS party_state FROM invoices i LEFT JOIN parties p ON p.id=i.party_id WHERE i.company_id=$1 AND i.type='sales' ORDER BY i.date DESC`, [req.user.company_id]);
    res.json({ success: true, data: r.rows });
  } catch(e) { res.status(500).json({ success: false, message: e.message }); }
});

// ── TDS ────────────────────────────────────────────────
app.get('/api/tds', auth, async (req, res) => {
  try {
    const r = await db('SELECT t.*, p.name AS party_name FROM tds_entries t LEFT JOIN parties p ON p.id=t.party_id WHERE t.company_id=$1 ORDER BY t.date DESC', [req.user.company_id]);
    res.json({ success: true, data: r.rows });
  } catch(e) { res.status(500).json({ success: false, message: e.message }); }
});

app.post('/api/tds', auth, async (req, res) => {
  try {
    const { partyId, section, paymentAmount, tdsRate, tdsAmount, date, description } = req.body;
    if (!partyId || !section || !paymentAmount) return res.status(400).json({ success: false, message: 'Party, section and amount required' });
    const r = await db(`INSERT INTO tds_entries (company_id,party_id,section,payment_amount,tds_rate,tds_amount,date,description) VALUES ($1,$2,$3,$4,$5,$6,$7,$8) RETURNING *`,
      [req.user.company_id, partyId, section, parseFloat(paymentAmount), parseFloat(tdsRate)||10, parseFloat(tdsAmount), date, description||null]);
    res.status(201).json({ success: true, data: r.rows[0], message: 'TDS recorded!' });
  } catch(e) { res.status(500).json({ success: false, message: e.message }); }
});

// ── FIXED ASSETS ───────────────────────────────────────
app.get('/api/assets', auth, async (req, res) => {
  try {
    const r = await db('SELECT * FROM fixed_assets WHERE company_id=$1 AND status!=\'Disposed\' ORDER BY name', [req.user.company_id]);
    res.json({ success: true, data: r.rows });
  } catch(e) { res.status(500).json({ success: false, message: e.message }); }
});

app.post('/api/assets', auth, async (req, res) => {
  try {
    const { name, category, purchaseDate, cost, depreciationRate, serialNo, location } = req.body;
    if (!name || !cost) return res.status(400).json({ success: false, message: 'Name and cost required' });
    const months = purchaseDate ? (new Date()-new Date(purchaseDate))/(1000*60*60*24*30.44) : 0;
    const depAmt = parseFloat(cost) * (parseFloat(depreciationRate)||33.33)/100 * months/12;
    const currentValue = Math.max(0, parseFloat(cost)-depAmt);
    const r = await db(`INSERT INTO fixed_assets (company_id,name,category,purchase_date,cost,depreciation_rate,current_value,serial_no,location) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9) RETURNING *`,
      [req.user.company_id, name, category||null, purchaseDate||null, parseFloat(cost), parseFloat(depreciationRate)||33.33, currentValue, serialNo||null, location||null]);
    res.status(201).json({ success: true, data: r.rows[0], message: 'Asset added!' });
  } catch(e) { res.status(500).json({ success: false, message: e.message }); }
});

// ── REPORTS ────────────────────────────────────────────
app.get('/api/reports/pl', auth, async (req, res) => {
  try {
    const r = await db('SELECT type, name, current_balance, balance_type FROM coa WHERE company_id=$1 AND type IN (\'Revenue\',\'Expense\') AND is_active=true ORDER BY type, code', [req.user.company_id]);
    const revenue = r.rows.filter(function(a){return a.type==='Revenue';});
    const expenses = r.rows.filter(function(a){return a.type==='Expense';});
    const totalRevenue = revenue.reduce(function(s,a){return s+parseFloat(a.current_balance);},0);
    const totalExpenses = expenses.reduce(function(s,a){return s+parseFloat(a.current_balance);},0);
    res.json({ success: true, data: { revenue, expenses, totalRevenue, totalExpenses, netProfit: totalRevenue-totalExpenses }});
  } catch(e) { res.status(500).json({ success: false, message: e.message }); }
});

app.get('/api/reports/bs', auth, async (req, res) => {
  try {
    const r = await db('SELECT type, subtype, name, current_balance, balance_type FROM coa WHERE company_id=$1 AND is_active=true ORDER BY type, code', [req.user.company_id]);
    const assets = r.rows.filter(function(a){return a.type==='Asset';});
    const liabilities = r.rows.filter(function(a){return a.type==='Liability';});
    const equity = r.rows.filter(function(a){return a.type==='Equity';});
    res.json({ success: true, data: { assets, liabilities, equity,
      totalAssets: assets.reduce(function(s,a){return s+parseFloat(a.current_balance);},0),
      totalLiabilities: liabilities.reduce(function(s,a){return s+parseFloat(a.current_balance);},0),
      totalEquity: equity.reduce(function(s,a){return s+parseFloat(a.current_balance);},0),
    }});
  } catch(e) { res.status(500).json({ success: false, message: e.message }); }
});

app.get('/api/reports/trial-balance', auth, async (req, res) => {
  try {
    const r = await db('SELECT code, name, type, balance_type, current_balance FROM coa WHERE company_id=$1 AND is_active=true ORDER BY code', [req.user.company_id]);
    res.json({ success: true, data: r.rows });
  } catch(e) { res.status(500).json({ success: false, message: e.message }); }
});

// ── AUDIT LOG ──────────────────────────────────────────
app.get('/api/audit', auth, async (req, res) => {
  try {
    const r = await db('SELECT a.*, u.name AS user_name FROM audit_log a LEFT JOIN erp_users u ON u.id=a.user_id WHERE a.company_id=$1 ORDER BY a.created_at DESC LIMIT 100', [req.user.company_id]);
    res.json({ success: true, data: r.rows });
  } catch(e) { res.status(500).json({ success: false, message: e.message }); }
});

app.post('/api/audit', auth, async (req, res) => {
  try {
    const { action, detail } = req.body;
    await db('INSERT INTO audit_log (company_id,user_id,action,detail) VALUES ($1,$2,$3,$4)',
      [req.user.company_id, req.user.id, action, detail]);
    res.json({ success: true });
  } catch(e) { res.status(500).json({ success: false, message: e.message }); }
});


// ── BANK TRANSACTIONS POST ─────────────────────────────
app.post('/api/bank/:id/transactions', auth, async (req, res) => {
  try {
    const { date, description, amount, type, reference, mode } = req.body;
    if (!date || !description || !amount) return res.status(400).json({ success: false, message: 'Date, description and amount required' });
    const debit  = type === 'debit'  ? parseFloat(amount) : 0;
    const credit = type === 'credit' ? parseFloat(amount) : 0;
    // Get current balance
    const bankRes = await db('SELECT balance FROM bank_accounts WHERE id=$1 AND company_id=$2', [req.params.id, req.user.company_id]);
    if (!bankRes.rows.length) return res.status(404).json({ success: false, message: 'Bank account not found' });
    const prevBal = parseFloat(bankRes.rows[0].balance);
    const newBal = prevBal + credit - debit;
    // Insert transaction
    const r = await db(`INSERT INTO bank_transactions (bank_account_id,date,description,debit,credit,balance,reference,mode)
      VALUES ($1,$2,$3,$4,$5,$6,$7,$8) RETURNING *`,
      [req.params.id, date, description, debit, credit, newBal, reference||null, mode||null]);
    // Update account balance
    await db('UPDATE bank_accounts SET balance=$1 WHERE id=$2', [newBal, req.params.id]);
    res.status(201).json({ success: true, data: r.rows[0], message: 'Transaction added!' });
  } catch(e) { res.status(500).json({ success: false, message: e.message }); }
});



// ── USER REGISTRATION (Admin only) ────────────────────
app.post('/api/auth/register', auth, async (req, res) => {
  try {
    if (req.user.role !== 'admin') return res.status(403).json({ success: false, message: 'Admin only' });
    const { name, email, password, role } = req.body;
    if (!name || !email || !password) return res.status(400).json({ success: false, message: 'Name, email and password required' });
    const hash = await bcrypt.hash(password, 10);
    const r = await db(
      'INSERT INTO erp_users (company_id,name,email,password,role) VALUES ($1,$2,$3,$4,$5) RETURNING id,name,email,role',
      [req.user.company_id, name, email.toLowerCase(), hash, role||'employee']
    );
    res.status(201).json({ success: true, data: r.rows[0], message: 'User created!' });
  } catch(e) {
    if (e.code === '23505') return res.status(400).json({ success: false, message: 'Email already exists' });
    res.status(500).json({ success: false, message: e.message });
  }
});

// ── GET ALL USERS ──────────────────────────────────────
app.get('/api/users', auth, async (req, res) => {
  try {
    if (req.user.role !== 'admin') return res.status(403).json({ success: false, message: 'Admin only' });
    const r = await db('SELECT id,name,email,role,is_active,created_at FROM erp_users WHERE company_id=$1 ORDER BY created_at', [req.user.company_id]);
    res.json({ success: true, data: r.rows });
  } catch(e) { res.status(500).json({ success: false, message: e.message }); }
});



// ── SETUP — Create missing default users ──────────────
app.get('/api/setup', async (req, res) => {
  try {
    const co = await db('SELECT id FROM erp_companies LIMIT 1');
    if (!co.rows.length) return res.json({ success: false, message: 'No company found' });
    const coId = co.rows[0].id;

    const users = [
      { name: 'Accounts Manager', email: 'accounts@paype.co.in', password: 'Manager@PayPe2026', role: 'manager' },
      { name: 'Employee', email: 'employee@paype.co.in', password: 'Employee@PayPe2026', role: 'employee' },
    ];

    const results = [];
    for (const u of users) {
      const existing = await db('SELECT id FROM erp_users WHERE email=$1', [u.email]);
      if (existing.rows.length) {
        results.push({ email: u.email, status: 'already exists' });
      } else {
        const hash = await bcrypt.hash(u.password, 10);
        await db('INSERT INTO erp_users (company_id,name,email,password,role) VALUES ($1,$2,$3,$4,$5)',
          [coId, u.name, u.email, hash, u.role]);
        results.push({ email: u.email, status: 'created ✅' });
      }
    }
    res.json({ success: true, results });
  } catch(e) { res.status(500).json({ success: false, message: e.message }); }
});



// ══════════════════════════════════════════════════════
// ── INVENTORY API ────────────────────────────────────
// ══════════════════════════════════════════════════════

// PRODUCTS
app.get('/api/inventory/products', auth, async (req, res) => {
  try {
    const r = await db('SELECT * FROM products WHERE company_id=$1 AND is_active=true ORDER BY name', [req.user.company_id]);
    res.json({ success: true, data: r.rows });
  } catch(e) { res.status(500).json({ success: false, message: e.message }); }
});

app.post('/api/inventory/products', auth, async (req, res) => {
  try {
    const { name, sku, hsn, category, unit, salePrice, costPrice, stock, reorderLevel, description, barcode } = req.body;
    if (!name) return res.status(400).json({ success: false, message: 'Product name required' });
    const r = await db(`INSERT INTO products (company_id,name,sku,hsn,category,unit,sale_price,cost_price,stock,reorder_level,description,barcode)
      VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12) RETURNING *`,
      [req.user.company_id, name, sku||null, hsn||null, category||null, unit||'Nos',
       parseFloat(salePrice)||0, parseFloat(costPrice)||0, parseFloat(stock)||0,
       parseFloat(reorderLevel)||10, description||null, barcode||null]);
    res.status(201).json({ success: true, data: r.rows[0], message: 'Product added!' });
  } catch(e) { res.status(500).json({ success: false, message: e.message }); }
});

app.put('/api/inventory/products/:id', auth, async (req, res) => {
  try {
    const { name, sku, hsn, category, unit, salePrice, costPrice, reorderLevel, description } = req.body;
    await db(`UPDATE products SET name=$1,sku=$2,hsn=$3,category=$4,unit=$5,sale_price=$6,cost_price=$7,reorder_level=$8,description=$9 WHERE id=$10 AND company_id=$11`,
      [name, sku, hsn, category, unit, parseFloat(salePrice)||0, parseFloat(costPrice)||0, parseFloat(reorderLevel)||10, description, req.params.id, req.user.company_id]);
    res.json({ success: true, message: 'Product updated!' });
  } catch(e) { res.status(500).json({ success: false, message: e.message }); }
});

// WAREHOUSES
app.get('/api/inventory/warehouses', auth, async (req, res) => {
  try {
    const r = await db('SELECT * FROM warehouses WHERE company_id=$1 AND is_active=true ORDER BY name', [req.user.company_id]);
    res.json({ success: true, data: r.rows });
  } catch(e) { res.status(500).json({ success: false, message: e.message }); }
});

app.post('/api/inventory/warehouses', auth, async (req, res) => {
  try {
    const { name, location, manager } = req.body;
    if (!name) return res.status(400).json({ success: false, message: 'Warehouse name required' });
    const r = await db(`INSERT INTO warehouses (company_id,name,location,manager) VALUES ($1,$2,$3,$4) RETURNING *`,
      [req.user.company_id, name, location||null, manager||null]);
    res.status(201).json({ success: true, data: r.rows[0], message: 'Warehouse added!' });
  } catch(e) { res.status(500).json({ success: false, message: e.message }); }
});

// STOCK MOVEMENTS
app.get('/api/inventory/stock-movements', auth, async (req, res) => {
  try {
    const r = await db(`SELECT sm.*, p.name AS product_name, p.sku, w.name AS warehouse_name
      FROM stock_movements sm
      LEFT JOIN products p ON p.id=sm.product_id
      LEFT JOIN warehouses w ON w.id=sm.warehouse_id
      WHERE sm.company_id=$1 ORDER BY sm.created_at DESC LIMIT 100`, [req.user.company_id]);
    res.json({ success: true, data: r.rows });
  } catch(e) { res.status(500).json({ success: false, message: e.message }); }
});

app.post('/api/inventory/stock-movements', auth, async (req, res) => {
  try {
    const { productId, warehouseId, type, qty, rate, reference, notes, date } = req.body;
    if (!productId || !type || !qty) return res.status(400).json({ success: false, message: 'Product, type and qty required' });
    const q = parseFloat(qty);
    const stockChange = ['stock-in','purchase-receive','transfer-in'].includes(type) ? q : -q;
    // Update product stock
    await db('UPDATE products SET stock = stock + $1 WHERE id=$2 AND company_id=$3', [stockChange, productId, req.user.company_id]);
    const r = await db(`INSERT INTO stock_movements (company_id,product_id,warehouse_id,type,qty,rate,reference,notes,date,created_by)
      VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) RETURNING *`,
      [req.user.company_id, productId, warehouseId||null, type, q, parseFloat(rate)||0, reference||null, notes||null, date||new Date().toISOString().split('T')[0], req.user.id]);
    res.status(201).json({ success: true, data: r.rows[0], message: 'Stock movement recorded!' });
  } catch(e) { res.status(500).json({ success: false, message: e.message }); }
});

// PURCHASE ORDERS
app.get('/api/inventory/purchase-orders', auth, async (req, res) => {
  try {
    const r = await db(`SELECT po.*, p.name AS vendor_name_full FROM purchase_orders po LEFT JOIN parties p ON p.id=po.vendor_id WHERE po.company_id=$1 ORDER BY po.created_at DESC`, [req.user.company_id]);
    res.json({ success: true, data: r.rows });
  } catch(e) { res.status(500).json({ success: false, message: e.message }); }
});

app.post('/api/inventory/purchase-orders', auth, async (req, res) => {
  try {
    const { vendorId, date, expectedDate, lines, notes } = req.body;
    if (!vendorId || !date || !lines || !lines.length) return res.status(400).json({ success: false, message: 'Vendor, date and lines required' });
    let sub=0, cgst=0, sgst=0;
    lines.forEach(function(l) { const amt=(parseFloat(l.qty)||1)*(parseFloat(l.rate)||0); const gst=amt*(parseFloat(l.gstRate)||18)/100; sub+=amt; cgst+=gst/2; sgst+=gst/2; });
    const count = await db('SELECT COUNT(*) FROM purchase_orders WHERE company_id=$1', [req.user.company_id]);
    const poNo = 'PO/2026-27/' + String(parseInt(count.rows[0].count)+1).padStart(4,'0');
    const vendor = await db('SELECT name FROM parties WHERE id=$1', [vendorId]);
    const r = await db(`INSERT INTO purchase_orders (company_id,po_no,vendor_id,vendor_name,date,expected_date,subtotal,cgst,sgst,total,notes,created_by)
      VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12) RETURNING *`,
      [req.user.company_id, poNo, vendorId, vendor.rows[0]?.name, date, expectedDate||null, sub, cgst, sgst, sub+cgst+sgst, notes||null, req.user.id]);
    const po = r.rows[0];
    for (const l of lines) {
      const amt=(parseFloat(l.qty)||1)*(parseFloat(l.rate)||0);
      await db(`INSERT INTO purchase_order_lines (po_id,product_id,description,qty,rate,gst_rate,amount) VALUES ($1,$2,$3,$4,$5,$6,$7)`,
        [po.id, l.productId||null, l.description||null, parseFloat(l.qty)||1, parseFloat(l.rate)||0, parseFloat(l.gstRate)||18, amt]);
    }
    res.status(201).json({ success: true, data: po, message: 'Purchase Order '+poNo+' created!' });
  } catch(e) { res.status(500).json({ success: false, message: e.message }); }
});

app.put('/api/inventory/purchase-orders/:id/status', auth, async (req, res) => {
  try {
    await db('UPDATE purchase_orders SET status=$1 WHERE id=$2 AND company_id=$3', [req.body.status, req.params.id, req.user.company_id]);
    res.json({ success: true, message: 'PO status updated!' });
  } catch(e) { res.status(500).json({ success: false, message: e.message }); }
});

// SALES ORDERS
app.get('/api/inventory/sales-orders', auth, async (req, res) => {
  try {
    const r = await db(`SELECT so.*, p.name AS customer_name_full FROM sales_orders so LEFT JOIN parties p ON p.id=so.customer_id WHERE so.company_id=$1 ORDER BY so.created_at DESC`, [req.user.company_id]);
    res.json({ success: true, data: r.rows });
  } catch(e) { res.status(500).json({ success: false, message: e.message }); }
});

app.post('/api/inventory/sales-orders', auth, async (req, res) => {
  try {
    const { customerId, date, deliveryDate, lines, notes } = req.body;
    if (!customerId || !date || !lines || !lines.length) return res.status(400).json({ success: false, message: 'Customer, date and lines required' });
    let sub=0, cgst=0, sgst=0;
    lines.forEach(function(l) { const amt=(parseFloat(l.qty)||1)*(parseFloat(l.rate)||0); const gst=amt*(parseFloat(l.gstRate)||18)/100; sub+=amt; cgst+=gst/2; sgst+=gst/2; });
    const count = await db('SELECT COUNT(*) FROM sales_orders WHERE company_id=$1', [req.user.company_id]);
    const soNo = 'SO/2026-27/' + String(parseInt(count.rows[0].count)+1).padStart(4,'0');
    const customer = await db('SELECT name FROM parties WHERE id=$1', [customerId]);
    const r = await db(`INSERT INTO sales_orders (company_id,so_no,customer_id,customer_name,date,delivery_date,subtotal,cgst,sgst,total,notes,created_by)
      VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12) RETURNING *`,
      [req.user.company_id, soNo, customerId, customer.rows[0]?.name, date, deliveryDate||null, sub, cgst, sgst, sub+cgst+sgst, notes||null, req.user.id]);
    const so = r.rows[0];
    for (const l of lines) {
      const amt=(parseFloat(l.qty)||1)*(parseFloat(l.rate)||0);
      await db(`INSERT INTO sales_order_lines (so_id,product_id,description,qty,rate,gst_rate,amount) VALUES ($1,$2,$3,$4,$5,$6,$7)`,
        [so.id, l.productId||null, l.description||null, parseFloat(l.qty)||1, parseFloat(l.rate)||0, parseFloat(l.gstRate)||18, amt]);
    }
    res.status(201).json({ success: true, data: so, message: 'Sales Order '+soNo+' created!' });
  } catch(e) { res.status(500).json({ success: false, message: e.message }); }
});

// INVENTORY REPORTS
app.get('/api/inventory/reports', auth, async (req, res) => {
  try {
    const [products, movements, lowStock] = await Promise.all([
      db('SELECT COUNT(*) AS total, SUM(stock*cost_price) AS stock_value FROM products WHERE company_id=$1 AND is_active=true', [req.user.company_id]),
      db("SELECT COUNT(*) AS total FROM stock_movements WHERE company_id=$1 AND date >= NOW()-INTERVAL '30 days'", [req.user.company_id]),
      db('SELECT * FROM products WHERE company_id=$1 AND stock <= reorder_level AND is_active=true ORDER BY stock ASC LIMIT 10', [req.user.company_id]),
    ]);
    res.json({ success: true, data: {
      totalProducts: parseInt(products.rows[0].total)||0,
      stockValue: parseFloat(products.rows[0].stock_value)||0,
      movementsThisMonth: parseInt(movements.rows[0].total)||0,
      lowStockProducts: lowStock.rows,
    }});
  } catch(e) { res.status(500).json({ success: false, message: e.message }); }
});

// ══════════════════════════════════════════════════════
// ── CRM API ──────────────────────────────────────────
// ══════════════════════════════════════════════════════

// LEADS
app.get('/api/crm/leads', auth, async (req, res) => {
  try {
    const { status } = req.query;
    let q = 'SELECT l.*, u.name AS assigned_name FROM leads l LEFT JOIN erp_users u ON u.id=l.assigned_to WHERE l.company_id=$1';
    const params = [req.user.company_id];
    if (status) { params.push(status); q += ' AND l.status=$' + params.length; }
    q += ' ORDER BY l.created_at DESC';
    const r = await db(q, params);
    res.json({ success: true, data: r.rows });
  } catch(e) { res.status(500).json({ success: false, message: e.message }); }
});

app.post('/api/crm/leads', auth, async (req, res) => {
  try {
    const { name, companyName, email, phone, source, status, value, notes } = req.body;
    if (!name) return res.status(400).json({ success: false, message: 'Lead name required' });
    const r = await db(`INSERT INTO leads (company_id,name,company_name,email,phone,source,status,value,assigned_to,notes)
      VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) RETURNING *`,
      [req.user.company_id, name, companyName||null, email||null, phone||null, source||'Website', status||'New', parseFloat(value)||0, req.user.id, notes||null]);
    res.status(201).json({ success: true, data: r.rows[0], message: 'Lead added!' });
  } catch(e) { res.status(500).json({ success: false, message: e.message }); }
});

app.put('/api/crm/leads/:id', auth, async (req, res) => {
  try {
    const { name, companyName, email, phone, source, status, value, notes } = req.body;
    await db(`UPDATE leads SET name=$1,company_name=$2,email=$3,phone=$4,source=$5,status=$6,value=$7,notes=$8 WHERE id=$9 AND company_id=$10`,
      [name, companyName, email, phone, source, status, parseFloat(value)||0, notes, req.params.id, req.user.company_id]);
    res.json({ success: true, message: 'Lead updated!' });
  } catch(e) { res.status(500).json({ success: false, message: e.message }); }
});

// OPPORTUNITIES
app.get('/api/crm/opportunities', auth, async (req, res) => {
  try {
    const r = await db(`SELECT o.*, l.name AS lead_name, l.company_name, u.name AS assigned_name
      FROM opportunities o LEFT JOIN leads l ON l.id=o.lead_id LEFT JOIN erp_users u ON u.id=o.assigned_to
      WHERE o.company_id=$1 ORDER BY o.created_at DESC`, [req.user.company_id]);
    res.json({ success: true, data: r.rows });
  } catch(e) { res.status(500).json({ success: false, message: e.message }); }
});

app.post('/api/crm/opportunities', auth, async (req, res) => {
  try {
    const { leadId, title, value, stage, probability, closeDate, notes } = req.body;
    if (!title) return res.status(400).json({ success: false, message: 'Title required' });
    const r = await db(`INSERT INTO opportunities (company_id,lead_id,title,value,stage,probability,close_date,assigned_to,notes)
      VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9) RETURNING *`,
      [req.user.company_id, leadId||null, title, parseFloat(value)||0, stage||'Prospect', parseFloat(probability)||10, closeDate||null, req.user.id, notes||null]);
    res.status(201).json({ success: true, data: r.rows[0], message: 'Opportunity added!' });
  } catch(e) { res.status(500).json({ success: false, message: e.message }); }
});

app.put('/api/crm/opportunities/:id', auth, async (req, res) => {
  try {
    const { title, value, stage, probability, closeDate, notes } = req.body;
    await db(`UPDATE opportunities SET title=$1,value=$2,stage=$3,probability=$4,close_date=$5,notes=$6 WHERE id=$7 AND company_id=$8`,
      [title, parseFloat(value)||0, stage, parseFloat(probability)||10, closeDate, notes, req.params.id, req.user.company_id]);
    res.json({ success: true, message: 'Opportunity updated!' });
  } catch(e) { res.status(500).json({ success: false, message: e.message }); }
});

// QUOTATIONS
app.get('/api/crm/quotations', auth, async (req, res) => {
  try {
    const r = await db(`SELECT q.*, l.name AS lead_name FROM quotations q LEFT JOIN leads l ON l.id=q.lead_id WHERE q.company_id=$1 ORDER BY q.created_at DESC`, [req.user.company_id]);
    res.json({ success: true, data: r.rows });
  } catch(e) { res.status(500).json({ success: false, message: e.message }); }
});

app.post('/api/crm/quotations', auth, async (req, res) => {
  try {
    const { leadId, customerId, customerName, date, validUntil, lines, notes } = req.body;
    if (!date || !lines || !lines.length) return res.status(400).json({ success: false, message: 'Date and lines required' });
    let sub=0, cgst=0, sgst=0;
    lines.forEach(function(l) { const amt=(parseFloat(l.qty)||1)*(parseFloat(l.rate)||0); const gst=amt*(parseFloat(l.gstRate)||18)/100; sub+=amt; cgst+=gst/2; sgst+=gst/2; });
    const count = await db('SELECT COUNT(*) FROM quotations WHERE company_id=$1', [req.user.company_id]);
    const qNo = 'QT/2026-27/' + String(parseInt(count.rows[0].count)+1).padStart(4,'0');
    const r = await db(`INSERT INTO quotations (company_id,quote_no,lead_id,customer_id,customer_name,date,valid_until,subtotal,cgst,sgst,total,notes,created_by)
      VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13) RETURNING *`,
      [req.user.company_id, qNo, leadId||null, customerId||null, customerName||null, date, validUntil||null, sub, cgst, sgst, sub+cgst+sgst, notes||null, req.user.id]);
    const qt = r.rows[0];
    for (const l of lines) {
      const amt=(parseFloat(l.qty)||1)*(parseFloat(l.rate)||0);
      await db(`INSERT INTO quotation_lines (quotation_id,product_id,description,qty,rate,gst_rate,amount) VALUES ($1,$2,$3,$4,$5,$6,$7)`,
        [qt.id, l.productId||null, l.description||null, parseFloat(l.qty)||1, parseFloat(l.rate)||0, parseFloat(l.gstRate)||18, amt]);
    }
    res.status(201).json({ success: true, data: qt, message: 'Quotation '+qNo+' created!' });
  } catch(e) { res.status(500).json({ success: false, message: e.message }); }
});

// TASKS
app.get('/api/crm/tasks', auth, async (req, res) => {
  try {
    const r = await db(`SELECT t.*, u.name AS assigned_name FROM crm_tasks t LEFT JOIN erp_users u ON u.id=t.assigned_to WHERE t.company_id=$1 ORDER BY t.due_date ASC NULLS LAST, t.created_at DESC`, [req.user.company_id]);
    res.json({ success: true, data: r.rows });
  } catch(e) { res.status(500).json({ success: false, message: e.message }); }
});

app.post('/api/crm/tasks', auth, async (req, res) => {
  try {
    const { title, refType, refId, dueDate, priority, notes } = req.body;
    if (!title) return res.status(400).json({ success: false, message: 'Title required' });
    const r = await db(`INSERT INTO crm_tasks (company_id,ref_type,ref_id,title,due_date,priority,assigned_to,notes)
      VALUES ($1,$2,$3,$4,$5,$6,$7,$8) RETURNING *`,
      [req.user.company_id, refType||'general', refId||null, title, dueDate||null, priority||'Medium', req.user.id, notes||null]);
    res.status(201).json({ success: true, data: r.rows[0], message: 'Task added!' });
  } catch(e) { res.status(500).json({ success: false, message: e.message }); }
});

app.put('/api/crm/tasks/:id/status', auth, async (req, res) => {
  try {
    await db('UPDATE crm_tasks SET status=$1 WHERE id=$2 AND company_id=$3', [req.body.status, req.params.id, req.user.company_id]);
    res.json({ success: true, message: 'Task updated!' });
  } catch(e) { res.status(500).json({ success: false, message: e.message }); }
});

// CRM PIPELINE
app.get('/api/crm/pipeline', auth, async (req, res) => {
  try {
    const stages = ['Prospect', 'Qualified', 'Proposal', 'Negotiation', 'Won', 'Lost'];
    const r = await db('SELECT stage, COUNT(*) AS count, SUM(value) AS total_value FROM opportunities WHERE company_id=$1 GROUP BY stage', [req.user.company_id]);
    const pipeline = stages.map(function(stage) {
      const found = r.rows.find(function(row) { return row.stage === stage; });
      return { stage, count: parseInt(found?.count||0), totalValue: parseFloat(found?.total_value||0) };
    });
    const allOpps = await db('SELECT o.*, l.name AS lead_name, l.company_name FROM opportunities o LEFT JOIN leads l ON l.id=o.lead_id WHERE o.company_id=$1 ORDER BY o.value DESC', [req.user.company_id]);
    res.json({ success: true, data: { pipeline, opportunities: allOpps.rows } });
  } catch(e) { res.status(500).json({ success: false, message: e.message }); }
});

// CRM REPORTS
app.get('/api/crm/reports', auth, async (req, res) => {
  try {
    const [leads, opps, quotes, tasks] = await Promise.all([
      db('SELECT status, COUNT(*) AS count, SUM(value) AS total FROM leads WHERE company_id=$1 GROUP BY status', [req.user.company_id]),
      db('SELECT stage, COUNT(*) AS count, SUM(value) AS total FROM opportunities WHERE company_id=$1 GROUP BY stage', [req.user.company_id]),
      db("SELECT COUNT(*) AS total, SUM(total) AS value FROM quotations WHERE company_id=$1 AND status!='Rejected'", [req.user.company_id]),
      db("SELECT status, COUNT(*) AS count FROM crm_tasks WHERE company_id=$1 GROUP BY status", [req.user.company_id]),
    ]);
    res.json({ success: true, data: {
      leads: leads.rows,
      opportunities: opps.rows,
      quotations: quotes.rows[0],
      tasks: tasks.rows,
    }});
  } catch(e) { res.status(500).json({ success: false, message: e.message }); }
});



// ══════════════════════════════════════════════════════
// ── MODULE 5: PROCUREMENT API ─────────────────────────
// ══════════════════════════════════════════════════════

// ── PROCUREMENT MIGRATIONS ────────────────────────────
// (Added in health check auto-migrate section)

// VENDORS
app.get('/api/procurement/vendors', auth, async (req, res) => {
  try {
    const r = await db(`SELECT v.*, 
      COUNT(DISTINCT po.id) AS po_count,
      COALESCE(SUM(po.total),0) AS total_business
      FROM vendors v
      LEFT JOIN purchase_orders po ON po.vendor_id = v.party_id
      WHERE v.company_id=$1
      GROUP BY v.id ORDER BY v.name`, [req.user.company_id]);
    res.json({ success: true, data: r.rows });
  } catch(e) { res.status(500).json({ success: false, message: e.message }); }
});

app.post('/api/procurement/vendors', auth, async (req, res) => {
  try {
    const { name, gstin, pan, email, mobile, address, category, paymentTerms, bankName, accountNo, ifsc, rating, notes } = req.body;
    if (!name) return res.status(400).json({ success: false, message: 'Vendor name required' });
    // Create party first
    const party = await db(`INSERT INTO parties (company_id,type,name,gstin,pan,email,mobile,address,state)
      VALUES ($1,'vendor',$2,$3,$4,$5,$6,$7,'TN') RETURNING id`,
      [req.user.company_id, name, gstin||null, pan||null, email||null, mobile||null, address||null]);
    const partyId = party.rows[0].id;
    const r = await db(`INSERT INTO vendors (company_id,party_id,name,category,payment_terms,bank_name,account_no,ifsc,rating,notes)
      VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) RETURNING *`,
      [req.user.company_id, partyId, name, category||'General', paymentTerms||30, bankName||null, accountNo||null, ifsc||null, parseFloat(rating)||5, notes||null]);
    res.status(201).json({ success: true, data: r.rows[0], message: 'Vendor added!' });
  } catch(e) { res.status(500).json({ success: false, message: e.message }); }
});

app.put('/api/procurement/vendors/:id', auth, async (req, res) => {
  try {
    const { category, paymentTerms, bankName, accountNo, ifsc, rating, notes, isActive } = req.body;
    await db(`UPDATE vendors SET category=$1,payment_terms=$2,bank_name=$3,account_no=$4,ifsc=$5,rating=$6,notes=$7,is_active=$8 WHERE id=$9 AND company_id=$10`,
      [category, paymentTerms, bankName, accountNo, ifsc, parseFloat(rating)||5, notes, isActive!==false, req.params.id, req.user.company_id]);
    res.json({ success: true, message: 'Vendor updated!' });
  } catch(e) { res.status(500).json({ success: false, message: e.message }); }
});

// RFQ
app.get('/api/procurement/rfq', auth, async (req, res) => {
  try {
    const r = await db(`SELECT r.*, u.name AS created_by_name FROM rfq r
      LEFT JOIN erp_users u ON u.id=r.created_by
      WHERE r.company_id=$1 ORDER BY r.created_at DESC`, [req.user.company_id]);
    res.json({ success: true, data: r.rows });
  } catch(e) { res.status(500).json({ success: false, message: e.message }); }
});

app.post('/api/procurement/rfq', auth, async (req, res) => {
  try {
    const { title, requiredDate, lines, vendorIds, notes } = req.body;
    if (!title || !lines || !lines.length) return res.status(400).json({ success: false, message: 'Title and items required' });
    const count = await db('SELECT COUNT(*) FROM rfq WHERE company_id=$1', [req.user.company_id]);
    const rfqNo = 'RFQ/2026-27/' + String(parseInt(count.rows[0].count)+1).padStart(4,'0');
    const r = await db(`INSERT INTO rfq (company_id,rfq_no,title,required_date,status,notes,created_by)
      VALUES ($1,$2,$3,$4,'Open',$5,$6) RETURNING *`,
      [req.user.company_id, rfqNo, title, requiredDate||null, notes||null, req.user.id]);
    const rfq = r.rows[0];
    for (const l of lines) {
      await db(`INSERT INTO rfq_lines (rfq_id,description,qty,unit,specifications) VALUES ($1,$2,$3,$4,$5)`,
        [rfq.id, l.description, parseFloat(l.qty)||1, l.unit||'Nos', l.specifications||null]);
    }
    if (vendorIds && vendorIds.length) {
      for (const vid of vendorIds) {
        await db(`INSERT INTO rfq_vendors (rfq_id,vendor_id,status) VALUES ($1,$2,'Sent')`, [rfq.id, vid]);
      }
    }
    res.status(201).json({ success: true, data: rfq, message: 'RFQ '+rfqNo+' created!' });
  } catch(e) { res.status(500).json({ success: false, message: e.message }); }
});

// PURCHASE APPROVALS
app.get('/api/procurement/approvals', auth, async (req, res) => {
  try {
    const r = await db(`SELECT pa.*, po.po_no, po.total, po.vendor_name, u.name AS requested_by_name
      FROM purchase_approvals pa
      LEFT JOIN purchase_orders po ON po.id=pa.po_id
      LEFT JOIN erp_users u ON u.id=pa.requested_by
      WHERE pa.company_id=$1 ORDER BY pa.created_at DESC`, [req.user.company_id]);
    res.json({ success: true, data: r.rows });
  } catch(e) { res.status(500).json({ success: false, message: e.message }); }
});

app.post('/api/procurement/approvals', auth, async (req, res) => {
  try {
    const { poId, amount, justification } = req.body;
    if (!poId) return res.status(400).json({ success: false, message: 'PO required' });
    const r = await db(`INSERT INTO purchase_approvals (company_id,po_id,amount,justification,status,requested_by)
      VALUES ($1,$2,$3,$4,'Pending',$5) RETURNING *`,
      [req.user.company_id, poId, parseFloat(amount)||0, justification||null, req.user.id]);
    res.status(201).json({ success: true, data: r.rows[0], message: 'Approval request submitted!' });
  } catch(e) { res.status(500).json({ success: false, message: e.message }); }
});

app.put('/api/procurement/approvals/:id', auth, async (req, res) => {
  try {
    if (!['admin','manager'].includes(req.user.role)) return res.status(403).json({ success: false, message: 'Manager or Admin required' });
    const { status, remarks } = req.body;
    await db(`UPDATE purchase_approvals SET status=$1,remarks=$2,approved_by=$3,approved_at=NOW() WHERE id=$4 AND company_id=$5`,
      [status, remarks||null, req.user.id, req.params.id, req.user.company_id]);
    if (status === 'Approved') {
      const ap = await db('SELECT po_id FROM purchase_approvals WHERE id=$1', [req.params.id]);
      if (ap.rows[0]) await db("UPDATE purchase_orders SET status='Approved' WHERE id=$1", [ap.rows[0].po_id]);
    }
    res.json({ success: true, message: 'Approval '+status+'!' });
  } catch(e) { res.status(500).json({ success: false, message: e.message }); }
});

// GRN
app.get('/api/procurement/grn', auth, async (req, res) => {
  try {
    const r = await db(`SELECT g.*, po.po_no, po.vendor_name FROM grn g
      LEFT JOIN purchase_orders po ON po.id=g.po_id
      WHERE g.company_id=$1 ORDER BY g.created_at DESC`, [req.user.company_id]);
    res.json({ success: true, data: r.rows });
  } catch(e) { res.status(500).json({ success: false, message: e.message }); }
});

app.post('/api/procurement/grn', auth, async (req, res) => {
  try {
    const { poId, receivedDate, lines, qualityStatus, notes } = req.body;
    if (!poId) return res.status(400).json({ success: false, message: 'PO required' });
    const count = await db('SELECT COUNT(*) FROM grn WHERE company_id=$1', [req.user.company_id]);
    const grnNo = 'GRN/2026-27/' + String(parseInt(count.rows[0].count)+1).padStart(4,'0');
    const r = await db(`INSERT INTO grn (company_id,grn_no,po_id,received_date,quality_status,notes,created_by)
      VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING *`,
      [req.user.company_id, grnNo, poId, receivedDate||new Date().toISOString().split('T')[0], qualityStatus||'Accepted', notes||null, req.user.id]);
    const grn = r.rows[0];
    if (lines && lines.length) {
      for (const l of lines) {
        await db(`INSERT INTO grn_lines (grn_id,product_id,description,ordered_qty,received_qty,rejected_qty) VALUES ($1,$2,$3,$4,$5,$6)`,
          [grn.id, l.productId||null, l.description||null, parseFloat(l.orderedQty)||0, parseFloat(l.receivedQty)||0, parseFloat(l.rejectedQty)||0]);
        // Update stock if accepted
        if (l.productId && qualityStatus !== 'Rejected') {
          await db('UPDATE products SET stock=stock+$1 WHERE id=$2 AND company_id=$3',
            [parseFloat(l.receivedQty)||0, l.productId, req.user.company_id]);
        }
      }
    }
    await db("UPDATE purchase_orders SET status='Received' WHERE id=$1", [poId]);
    res.status(201).json({ success: true, data: grn, message: 'GRN '+grnNo+' created!' });
  } catch(e) { res.status(500).json({ success: false, message: e.message }); }
});

// VENDOR PAYMENTS
app.get('/api/procurement/payments', auth, async (req, res) => {
  try {
    const r = await db(`SELECT vp.*, p.name AS vendor_name FROM vendor_payments vp
      LEFT JOIN parties p ON p.id=vp.vendor_id
      WHERE vp.company_id=$1 ORDER BY vp.payment_date DESC`, [req.user.company_id]);
    res.json({ success: true, data: r.rows });
  } catch(e) { res.status(500).json({ success: false, message: e.message }); }
});

app.post('/api/procurement/payments', auth, async (req, res) => {
  try {
    const { vendorId, amount, paymentDate, mode, reference, billId, notes } = req.body;
    if (!vendorId || !amount) return res.status(400).json({ success: false, message: 'Vendor and amount required' });
    const r = await db(`INSERT INTO vendor_payments (company_id,vendor_id,amount,payment_date,mode,reference,bill_id,notes,created_by)
      VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9) RETURNING *`,
      [req.user.company_id, vendorId, parseFloat(amount), paymentDate||new Date().toISOString().split('T')[0],
       mode||'NEFT', reference||null, billId||null, notes||null, req.user.id]);
    if (billId) await db("UPDATE invoices SET status='Paid' WHERE id=$1", [billId]);
    res.status(201).json({ success: true, data: r.rows[0], message: 'Payment recorded!' });
  } catch(e) { res.status(500).json({ success: false, message: e.message }); }
});

// PROCUREMENT DASHBOARD
app.get('/api/procurement/dashboard', auth, async (req, res) => {
  try {
    const [vendors, rfqs, approvals, grns, payments] = await Promise.all([
      db('SELECT COUNT(*) AS total, COUNT(*) FILTER(WHERE is_active=true) AS active FROM vendors WHERE company_id=$1', [req.user.company_id]),
      db("SELECT COUNT(*) AS total, COUNT(*) FILTER(WHERE status='Open') AS open FROM rfq WHERE company_id=$1", [req.user.company_id]),
      db("SELECT COUNT(*) AS total, COUNT(*) FILTER(WHERE status='Pending') AS pending FROM purchase_approvals WHERE company_id=$1", [req.user.company_id]),
      db('SELECT COUNT(*) AS total FROM grn WHERE company_id=$1', [req.user.company_id]),
      db('SELECT COALESCE(SUM(amount),0) AS total FROM vendor_payments WHERE company_id=$1', [req.user.company_id]),
    ]);
    res.json({ success: true, data: {
      vendors: vendors.rows[0],
      rfqs: rfqs.rows[0],
      approvals: approvals.rows[0],
      grns: grns.rows[0],
      totalPayments: parseFloat(payments.rows[0].total)||0,
    }});
  } catch(e) { res.status(500).json({ success: false, message: e.message }); }
});


// ── 404 & ERROR ────────────────────────────────────────
app.use(function(req, res) { res.status(404).json({ success: false, message: 'Endpoint not found' }); });
app.use(function(err, req, res, next) { res.status(500).json({ success: false, message: err.message }); });

app.listen(PORT, function() { console.log('PayPe ERP API running on port ' + PORT); });
module.exports = app;
