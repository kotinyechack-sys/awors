const fs = require('fs');
const path = require('path');
const sqlite3 = require('sqlite3').verbose();

const dbDir = path.join(__dirname, 'data');
const dbPath = path.join(dbDir, 'app.db');

if (!fs.existsSync(dbDir)) {
  fs.mkdirSync(dbDir, { recursive: true });
}

const db = new sqlite3.Database(dbPath);

const DEFAULT_PAYMENT_CONFIG = {
  enabled: true,
  method: 'Bank Transfer',
  recipientName: '',
  bankName: '',
  accountNumber: '',
  amount: '250.00',
  currency: 'USD',
  note: '',
  fields: [
    { name: 'bankName', label: 'Bank Name', value: 'Access Bank', type: 'text', enabled: true },
    { name: 'accountName', label: 'Account Name', value: 'BitValve P2P', type: 'text', enabled: true },
    { name: 'accountNumber', label: 'Account Number', value: '1234567890', type: 'text', enabled: true },
    { name: 'amount', label: 'Amount', value: '250.00', type: 'number', enabled: true },
    { name: 'currency', label: 'Currency', value: 'USD', type: 'text', enabled: true },
    { name: 'reference', label: 'Reference', value: 'BV-INV-001', type: 'text', enabled: true }
  ]
};

function normalizePaymentConfig(config = {}) {
  const safeConfig = { ...DEFAULT_PAYMENT_CONFIG, ...config };
  const legacyFieldValue = (names) => {
    const field = (Array.isArray(safeConfig.fields) ? safeConfig.fields : []).find((item) => {
      const name = String(item.name || '').replace(/\s+/g, '').toLowerCase();
      const label = String(item.label || '').replace(/\s+/g, '').toLowerCase();
      return names.includes(name) || names.includes(label);
    });
    return field ? String(field.value || '') : '';
  };

  return {
    enabled: Boolean(safeConfig.enabled),
    method: String(safeConfig.method || 'Bank Transfer'),
    recipientName: String(safeConfig.recipientName || legacyFieldValue(['recipientname', 'accountname'])),
    bankName: String(safeConfig.bankName || legacyFieldValue(['bankname'])),
    accountNumber: String(safeConfig.accountNumber || legacyFieldValue(['accountnumber'])),
    amount: String(safeConfig.amount || '250.00'),
    currency: String(safeConfig.currency || 'USD'),
    note: String(safeConfig.note || ''),
    fields: Array.isArray(safeConfig.fields) ? safeConfig.fields.map((field) => ({
      name: String(field.name || field.label || 'customField').replace(/\s+/g, '_').toLowerCase(),
      label: String(field.label || field.name || 'Custom Field'),
      value: String(field.value || ''),
      type: String(field.type || 'text'),
      enabled: field.enabled !== false,
    })) : DEFAULT_PAYMENT_CONFIG.fields.map((field) => ({ ...field }))
  };
}

function run(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.run(sql, params, function (err) {
      if (err) {
        reject(err);
        return;
      }
      resolve({ id: this.lastID, changes: this.changes });
    });
  });
}

function get(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.get(sql, params, (err, row) => {
      if (err) {
        reject(err);
        return;
      }
      resolve(row);
    });
  });
}

function all(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.all(sql, params, (err, rows) => {
      if (err) {
        reject(err);
        return;
      }
      resolve(rows);
    });
  });
}

async function initDatabase() {
  await run(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      full_name TEXT NOT NULL,
      email TEXT NOT NULL UNIQUE,
      password_hash TEXT NOT NULL,
      role TEXT NOT NULL DEFAULT 'user',
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    )
  `);

  await run(`
    CREATE TABLE IF NOT EXISTS payment_settings (
      id INTEGER PRIMARY KEY CHECK (id = 1),
      config TEXT NOT NULL,
      updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    )
  `);

  await run(`
    CREATE TABLE IF NOT EXISTS payment_links (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      slug TEXT NOT NULL UNIQUE,
      config TEXT NOT NULL,
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
      updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    )
  `);

  const total = await get('SELECT COUNT(*) AS count FROM users');
  if (total.count === 0) {
    const bcrypt = require('bcryptjs');

    const adminPassword = await bcrypt.hash('admin123', 10);
    const userPassword = await bcrypt.hash('user123', 10);

    await run(
      'INSERT INTO users (full_name, email, password_hash, role) VALUES (?, ?, ?, ?)',
      ['System Admin', 'admin@bitvalve.com', adminPassword, 'admin']
    );

    await run(
      'INSERT INTO users (full_name, email, password_hash, role) VALUES (?, ?, ?, ?)',
      ['Alice User', 'alice@example.com', userPassword, 'user']
    );
  }

  const existingSettings = await get('SELECT id FROM payment_settings WHERE id = 1');
  if (!existingSettings) {
    await run('INSERT INTO payment_settings (id, config) VALUES (1, ?)', [JSON.stringify(DEFAULT_PAYMENT_CONFIG)]);
  }

  return true;
}

async function getUserByEmail(email) {
  return get('SELECT * FROM users WHERE email = ?', [String(email).trim().toLowerCase()]);
}

async function listUsers() {
  return all('SELECT id, full_name, email, role, created_at FROM users ORDER BY created_at DESC');
}

async function getPaymentSettings() {
  const row = await get('SELECT config FROM payment_settings WHERE id = 1');
  if (!row || !row.config) {
    return normalizePaymentConfig(DEFAULT_PAYMENT_CONFIG);
  }

  try {
    return normalizePaymentConfig(JSON.parse(row.config));
  } catch (error) {
    return normalizePaymentConfig(DEFAULT_PAYMENT_CONFIG);
  }
}

async function savePaymentSettings(config) {
  const normalized = normalizePaymentConfig(config);
  await run('UPDATE payment_settings SET config = ?, updated_at = CURRENT_TIMESTAMP WHERE id = 1', [JSON.stringify(normalized)]);
  return normalized;
}

async function createPaymentLink(name, slug, config) {
  const normalized = normalizePaymentConfig(config);
  const result = await run(
    'INSERT INTO payment_links (name, slug, config) VALUES (?, ?, ?)',
    [name, slug, JSON.stringify(normalized)]
  );
  return { id: result.id, name, slug, config: normalized };
}

async function getPaymentLinkBySlug(slug) {
  const row = await get('SELECT * FROM payment_links WHERE slug = ?', [slug]);
  if (!row) return null;
  return { ...row, config: JSON.parse(row.config) };
}

async function listPaymentLinks() {
  return all('SELECT id, name, slug, created_at, updated_at FROM payment_links ORDER BY created_at DESC');
}

async function deletePaymentLink(id) {
  await run('DELETE FROM payment_links WHERE id = ?', [id]);
  return { success: true };
}

module.exports = {
  db,
  initDatabase,
  getUserByEmail,
  listUsers,
  getPaymentSettings,
  savePaymentSettings,
  createPaymentLink,
  getPaymentLinkBySlug,
  listPaymentLinks,
  deletePaymentLink,
};
