// db.js — SQLite schema, seed data, and small query helpers.
// This is a direct port of the original Flask backend's DB layer
// (same schema, same seed logic, same single-admin rule) using
// better-sqlite3, which — like Python's sqlite3 — is synchronous,
// so the query/execute helpers below map 1:1 onto the old
// query()/execute() helpers from app.py.

const path = require("path");
const Database = require("better-sqlite3");
const bcrypt = require("bcryptjs");

const DB_PATH = path.join(__dirname, "railreserve.db");
const db = new Database(DB_PATH);
db.pragma("foreign_keys = ON");

const SCHEMA = `
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL CHECK(role IN ('admin','passenger')),
    phone TEXT DEFAULT '',
    preferred_seat TEXT DEFAULT '',
    tier TEXT DEFAULT 'Standard',
    region TEXT DEFAULT '',
    status TEXT DEFAULT 'active',
    pref_email_confirm INTEGER DEFAULT 1,
    pref_sms_reminder INTEGER DEFAULT 0,
    pref_share_data INTEGER DEFAULT 1,
    created_at TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS stations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT UNIQUE NOT NULL,
    code TEXT DEFAULT ''
);

CREATE TABLE IF NOT EXISTS routes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    stations TEXT NOT NULL,
    origin_station_id INTEGER REFERENCES stations(id),
    destination_station_id INTEGER REFERENCES stations(id),
    distance_km INTEGER DEFAULT 0,
    duration TEXT DEFAULT '',
    category TEXT DEFAULT '',
    status TEXT DEFAULT 'ACTIVE'
);

CREATE TABLE IF NOT EXISTS trains (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    number TEXT NOT NULL,
    route_id INTEGER REFERENCES routes(id),
    origin TEXT NOT NULL,
    destination TEXT NOT NULL,
    departure_time TEXT NOT NULL,
    arrival_time TEXT DEFAULT '—',
    duration TEXT DEFAULT '—',
    region TEXT DEFAULT '',
    status TEXT DEFAULT 'ON TIME',
    total_seats INTEGER DEFAULT 24
);

CREATE TABLE IF NOT EXISTS fares (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    train_id INTEGER REFERENCES trains(id),
    class_name TEXT NOT NULL,
    price REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS seats (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    train_id INTEGER REFERENCES trains(id),
    seat_number TEXT NOT NULL,
    seat_class TEXT DEFAULT 'Standard',
    is_window INTEGER DEFAULT 0,
    is_booked INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS bookings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    pnr TEXT NOT NULL,
    user_id INTEGER REFERENCES users(id),
    train_id INTEGER REFERENCES trains(id),
    seat_id INTEGER REFERENCES seats(id),
    journey_date TEXT NOT NULL,
    class_name TEXT NOT NULL,
    price REAL NOT NULL,
    status TEXT DEFAULT 'CONFIRMED',
    passenger_name TEXT DEFAULT '',
    passenger_email TEXT DEFAULT '',
    passenger_phone TEXT DEFAULT '',
    payment_id TEXT DEFAULT '',
    payment_status TEXT DEFAULT '',
    created_at TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS payment_orders (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    order_id TEXT UNIQUE NOT NULL,
    razorpay_payment_id TEXT DEFAULT '',
    user_id INTEGER REFERENCES users(id),
    train_id INTEGER REFERENCES trains(id),
    seat_ids TEXT NOT NULL,
    class_name TEXT NOT NULL,
    journey_date TEXT NOT NULL,
    passenger_name TEXT DEFAULT '',
    passenger_email TEXT DEFAULT '',
    passenger_phone TEXT DEFAULT '',
    amount REAL NOT NULL,
    currency TEXT DEFAULT 'USD',
    status TEXT DEFAULT 'created',
    created_at TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS notifications (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER REFERENCES users(id),
    title TEXT NOT NULL,
    body TEXT NOT NULL,
    is_read INTEGER DEFAULT 0,
    created_at TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value TEXT
);

CREATE TABLE IF NOT EXISTS audit_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    actor TEXT NOT NULL,
    action TEXT NOT NULL,
    created_at TEXT DEFAULT (datetime('now'))
);
`;

const DEFAULT_SETTINGS = {
  maintenance_mode: "0",
  two_factor_admins: "1",
  email_notifications: "1",
  default_currency: "USD",
  default_timezone: "UTC",
  min_occupancy_alert: "75%",
  cancellation_fee: "$15",
  dynamic_pricing_cap: "3%",
  auto_release_unpaid: "1",
};

// ---- small helpers mirroring the old Python query()/execute() ----
function query(sql, args = []) {
  return db.prepare(sql).all(...args);
}
function queryOne(sql, args = []) {
  const row = db.prepare(sql).get(...args);
  return row === undefined ? null : row;
}
function execute(sql, args = []) {
  const info = db.prepare(sql).run(...args);
  return info.lastInsertRowid;
}
function nowiso() {
  const d = new Date();
  const pad = (n) => String(n).padStart(2, "0");
  return `${d.getUTCFullYear()}-${pad(d.getUTCMonth() + 1)}-${pad(d.getUTCDate())} ${pad(d.getUTCHours())}:${pad(d.getUTCMinutes())}`;
}
function logAudit(actor, action) {
  execute("INSERT INTO audit_logs (actor, action, created_at) VALUES (?,?,?)", [actor, action, nowiso()]);
}

function seedIfEmpty(adminEmail, adminPassword) {
  db.exec(SCHEMA);

  const admin = queryOne("SELECT id FROM users WHERE email=?", [adminEmail]);
  if (!admin) {
    execute(
      "INSERT INTO users (name,email,password_hash,role,tier,region,status) VALUES (?,?,?,?,?,?,?)",
      ["Admin", adminEmail, bcrypt.hashSync(adminPassword, 10), "admin", "Admin", "Global", "active"]
    );
    logAudit(adminEmail, "System initialized — admin account ready");
  }

  const settingsCount = queryOne("SELECT COUNT(*) c FROM settings").c;
  if (settingsCount === 0) {
    for (const [k, v] of Object.entries(DEFAULT_SETTINGS)) {
      execute("INSERT INTO settings (key,value) VALUES (?,?)", [k, v]);
    }
  }
}

module.exports = { db, query, queryOne, execute, nowiso, logAudit, seedIfEmpty };
