const Database = require('better-sqlite3');
const bcrypt = require('bcryptjs');
const path = require('path');

const DB_PATH = path.join(__dirname, '..', 'data', 'idp.db');

let db;

function getDb() {
  if (!db) {
    const fs = require('fs');
    const dir = path.dirname(DB_PATH);
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });

    db = new Database(DB_PATH);
    db.pragma('journal_mode = WAL');
    db.pragma('foreign_keys = ON');
    initTables();
  }
  return db;
}

function initTables() {
  db.exec(`
    CREATE TABLE IF NOT EXISTS admins (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      email TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL,
      first_name TEXT DEFAULT '',
      last_name TEXT DEFAULT '',
      display_name TEXT DEFAULT '',
      immutable_id TEXT DEFAULT '',
      enabled INTEGER DEFAULT 1,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS service_providers (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      type TEXT NOT NULL DEFAULT 'custom',
      entity_id TEXT NOT NULL,
      acs_url TEXT NOT NULL,
      name_id_format TEXT DEFAULT 'email',
      enabled INTEGER DEFAULT 1,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS login_logs (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_email TEXT,
      sp_name TEXT,
      success INTEGER,
      ip_address TEXT,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );
  `);
}

// Admin operations
const adminOps = {
  create(username, password) {
    const hash = bcrypt.hashSync(password, 10);
    return getDb().prepare('INSERT INTO admins (username, password) VALUES (?, ?)').run(username, hash);
  },
  verify(username, password) {
    const admin = getDb().prepare('SELECT * FROM admins WHERE username = ?').get(username);
    if (!admin) return null;
    return bcrypt.compareSync(password, admin.password) ? admin : null;
  },
  count() {
    return getDb().prepare('SELECT COUNT(*) as cnt FROM admins').get().cnt;
  },
  changePassword(id, newPassword) {
    const hash = bcrypt.hashSync(newPassword, 10);
    return getDb().prepare('UPDATE admins SET password = ? WHERE id = ?').run(hash, id);
  }
};

// User operations
const userOps = {
  list() {
    return getDb().prepare('SELECT id, email, first_name, last_name, display_name, immutable_id, enabled, created_at FROM users ORDER BY created_at DESC').all();
  },
  getByEmail(email) {
    return getDb().prepare('SELECT * FROM users WHERE email = ? AND enabled = 1').get(email);
  },
  getById(id) {
    return getDb().prepare('SELECT * FROM users WHERE id = ?').get(id);
  },
  create({ email, password, first_name, last_name, display_name, immutable_id }) {
    const hash = bcrypt.hashSync(password, 10);
    return getDb().prepare(
      'INSERT INTO users (email, password, first_name, last_name, display_name, immutable_id) VALUES (?, ?, ?, ?, ?, ?)'
    ).run(email, hash, first_name || '', last_name || '', display_name || '', immutable_id || '');
  },
  update(id, { email, first_name, last_name, display_name, immutable_id, enabled }) {
    return getDb().prepare(
      'UPDATE users SET email=?, first_name=?, last_name=?, display_name=?, immutable_id=?, enabled=?, updated_at=CURRENT_TIMESTAMP WHERE id=?'
    ).run(email, first_name || '', last_name || '', display_name || '', immutable_id || '', enabled ? 1 : 0, id);
  },
  updatePassword(id, password) {
    const hash = bcrypt.hashSync(password, 10);
    return getDb().prepare('UPDATE users SET password = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?').run(hash, id);
  },
  delete(id) {
    return getDb().prepare('DELETE FROM users WHERE id = ?').run(id);
  },
  verify(email, password) {
    const user = getDb().prepare('SELECT * FROM users WHERE email = ? AND enabled = 1').get(email);
    if (!user) return null;
    return bcrypt.compareSync(password, user.password) ? user : null;
  },
  count() {
    return getDb().prepare('SELECT COUNT(*) as cnt FROM users').get().cnt;
  }
};

// Service Provider operations
const spOps = {
  list() {
    return getDb().prepare('SELECT * FROM service_providers ORDER BY created_at DESC').all();
  },
  getById(id) {
    return getDb().prepare('SELECT * FROM service_providers WHERE id = ?').get(id);
  },
  getByEntityId(entityId) {
    return getDb().prepare('SELECT * FROM service_providers WHERE entity_id = ? AND enabled = 1').get(entityId);
  },
  create({ name, type, entity_id, acs_url, name_id_format }) {
    return getDb().prepare(
      'INSERT INTO service_providers (name, type, entity_id, acs_url, name_id_format) VALUES (?, ?, ?, ?, ?)'
    ).run(name, type || 'custom', entity_id, acs_url, name_id_format || 'email');
  },
  update(id, { name, type, entity_id, acs_url, name_id_format, enabled }) {
    return getDb().prepare(
      'UPDATE service_providers SET name=?, type=?, entity_id=?, acs_url=?, name_id_format=?, enabled=? WHERE id=?'
    ).run(name, type, entity_id, acs_url, name_id_format || 'email', enabled ? 1 : 0, id);
  },
  delete(id) {
    return getDb().prepare('DELETE FROM service_providers WHERE id = ?').run(id);
  },
  count() {
    return getDb().prepare('SELECT COUNT(*) as cnt FROM service_providers').get().cnt;
  }
};

// Login log operations
const logOps = {
  add(user_email, sp_name, success, ip_address) {
    return getDb().prepare(
      'INSERT INTO login_logs (user_email, sp_name, success, ip_address) VALUES (?, ?, ?, ?)'
    ).run(user_email, sp_name, success ? 1 : 0, ip_address);
  },
  recent(limit = 50) {
    return getDb().prepare('SELECT * FROM login_logs ORDER BY created_at DESC LIMIT ?').all(limit);
  },
  countToday() {
    return getDb().prepare("SELECT COUNT(*) as cnt FROM login_logs WHERE date(created_at) = date('now')").get().cnt;
  },
  countTodaySuccess() {
    return getDb().prepare("SELECT COUNT(*) as cnt FROM login_logs WHERE date(created_at) = date('now') AND success = 1").get().cnt;
  }
};

module.exports = { getDb, adminOps, userOps, spOps, logOps };
