// server.js — Rail.Reserve API (Node.js/Express)
//
// This is a faithful port of the original Flask/Python backend: same
// routes, same request/response shapes, same validation rules, same
// business logic (single admin account, stations -> routes -> trains,
// group bookings sharing one PNR, payment-gated booking creation,
// real Razorpay order creation + signature verification). Nothing was
// added or removed — only the runtime changed from Python to Node.

require("dotenv").config();

const crypto = require("crypto");
const express = require("express");
const cookieSession = require("cookie-session");
const cors = require("cors");
const bcrypt = require("bcryptjs");

const { query, queryOne, execute, logAudit, seedIfEmpty } = require("./db");

// ------------------------------------------------------------------
// Configuration — the single admin account, and payment gateway keys.
// All secrets come from environment variables, never hardcoded, and
// never sent to the frontend (only RAZORPAY_KEY_ID, which Razorpay's
// own docs say is safe client-side).
//
// There are no hardcoded fallback values for admin credentials or the
// session secret: if they're missing from .env, the server refuses to
// start rather than silently booting with a known/default identity.
// ------------------------------------------------------------------
const REQUIRED_ENV_VARS = ["RAILRESERVE_ADMIN_EMAIL", "RAILRESERVE_ADMIN_PASSWORD", "RAILRESERVE_SECRET"];
const missingEnvVars = REQUIRED_ENV_VARS.filter((name) => !process.env[name]);
if (missingEnvVars.length > 0) {
  console.error(
    `Missing required environment variable(s): ${missingEnvVars.join(", ")}. ` +
      "Copy backend/.env.example to backend/.env and set real values before starting the server."
  );
  process.exit(1);
}

const ADMIN_EMAIL = process.env.RAILRESERVE_ADMIN_EMAIL.trim().toLowerCase();
const ADMIN_PASSWORD = process.env.RAILRESERVE_ADMIN_PASSWORD;
const SESSION_SECRET = process.env.RAILRESERVE_SECRET;
const PORT = process.env.PORT || 5000;

// FRONTEND_ORIGIN may be a single origin or a comma-separated list
// (e.g. "http://localhost:3000,http://127.0.0.1:3000"). Whatever is
// configured, we also automatically allow the localhost/127.0.0.1
// equivalent of each entry, since browsers treat those as different
// origins even though they're the same machine — a very common source
// of otherwise-confusing CORS failures in local development.
const FRONTEND_ORIGIN = process.env.FRONTEND_ORIGIN || "http://localhost:3000";
const ALLOWED_ORIGINS = (() => {
  const set = new Set();
  FRONTEND_ORIGIN.split(",").map((o) => o.trim()).filter(Boolean).forEach((origin) => {
    set.add(origin);
    if (origin.includes("localhost")) set.add(origin.replace("localhost", "127.0.0.1"));
    if (origin.includes("127.0.0.1")) set.add(origin.replace("127.0.0.1", "localhost"));
  });
  return Array.from(set);
})();

const RAZORPAY_KEY_ID = process.env.RAZORPAY_KEY_ID || "";
const RAZORPAY_KEY_SECRET = process.env.RAZORPAY_KEY_SECRET || "";
const RAZORPAY_ENABLED = Boolean(RAZORPAY_KEY_ID && RAZORPAY_KEY_SECRET);

let razorpayClient = null;
if (RAZORPAY_ENABLED) {
  try {
    const Razorpay = require("razorpay");
    razorpayClient = new Razorpay({ key_id: RAZORPAY_KEY_ID, key_secret: RAZORPAY_KEY_SECRET });
  } catch (e) {
    console.warn("razorpay package not available — falling back to test-mode payments.");
  }
}

seedIfEmpty(ADMIN_EMAIL, ADMIN_PASSWORD);

const app = express();
app.set("trust proxy", 1);
app.use(express.json());
app.use(
  cors({
    origin(origin, callback) {
      // Same-origin tools (curl, server-to-server, Postman) send no
      // Origin header at all — always allow those.
      if (!origin || ALLOWED_ORIGINS.includes(origin)) {
        callback(null, true);
      } else {
        console.warn(`CORS: blocked request from origin "${origin}" — allowed origins: ${ALLOWED_ORIGINS.join(", ")}`);
        callback(null, false);
      }
    },
    credentials: true,
  })
);
app.use(
  cookieSession({
    name: "railreserve_session",
    keys: [SESSION_SECRET],
    httpOnly: true,
    sameSite: "lax",
    secure: false, // set true when serving over HTTPS in production
    maxAge: 1000 * 60 * 60 * 24 * 7,
  })
);

// ------------------------------------------------------------------
// Small helpers
// ------------------------------------------------------------------
function genPnr() {
  let s = "";
  for (let i = 0; i < 10; i++) s += Math.floor(Math.random() * 10);
  return s;
}

function hashPassword(password) {
  return bcrypt.hashSync(password, 10);
}
function checkPassword(hash, password) {
  return bcrypt.compareSync(password, hash);
}

function currentUser(req) {
  const uid = req.session.userId;
  if (!uid) return null;
  return queryOne("SELECT * FROM users WHERE id=?", [uid]);
}

function requireAuth(roles) {
  return (req, res, next) => {
    const u = currentUser(req);
    if (!u) return res.status(401).json({ error: "Not authenticated" });
    if (roles && !roles.includes(u.role)) return res.status(403).json({ error: "Not authorized" });
    req.currentUser = u;
    next();
  };
}

function publicUser(u) {
  if (!u) return null;
  const { password_hash, ...rest } = u;
  return rest;
}

function trainPublic(t) {
  const fares = query("SELECT class_name, price FROM fares WHERE train_id=?", [t.id]);
  const total = queryOne("SELECT COUNT(*) c FROM seats WHERE train_id=?", [t.id]).c;
  const booked = queryOne("SELECT COUNT(*) c FROM seats WHERE train_id=? AND is_booked=1", [t.id]).c;
  const minFare = fares.length ? Math.min(...fares.map((f) => f.price)) : 0;
  return {
    ...t,
    fares,
    min_fare: minFare,
    total_seats: total,
    booked_seats: booked,
    available_seats: total - booked,
    occupancy_pct: total ? Math.round((booked / total) * 100) : 0,
  };
}

function trainAdmin(t) {
  const total = queryOne("SELECT COUNT(*) c FROM seats WHERE train_id=?", [t.id]).c;
  const booked = queryOne("SELECT COUNT(*) c FROM seats WHERE train_id=? AND is_booked=1", [t.id]).c;
  return {
    ...t,
    occupancy_pct: total ? Math.round((booked / total) * 100) : 0,
    total_seats: total,
  };
}

function bookingPublic(b) {
  const t = queryOne("SELECT * FROM trains WHERE id=?", [b.train_id]);
  const s = queryOne("SELECT * FROM seats WHERE id=?", [b.seat_id]);
  const usr = queryOne("SELECT name,email FROM users WHERE id=?", [b.user_id]);
  const d = { ...b };
  d.train_name = t ? `${t.name} #${t.number}` : "(train removed)";
  d.origin = t ? t.origin : "";
  d.destination = t ? t.destination : "";
  d.departure_time = t ? t.departure_time : "";
  d.arrival_time = t ? t.arrival_time : "";
  d.seat_number = s ? s.seat_number : "";
  d.seat_type = s && s.is_window ? "Window" : "Aisle";
  if (!d.passenger_name) d.passenger_name = usr ? usr.name : "";
  if (!d.passenger_email) d.passenger_email = usr ? usr.email : "";
  return d;
}

function makeSeatsForTrain(trainId) {
  for (let row = 1; row <= 4; row++) {
    for (const col of ["A", "B", "C", "D", "E", "F"]) {
      execute(
        "INSERT INTO seats (train_id,seat_number,seat_class,is_window,is_booked) VALUES (?,?,?,?,0)",
        [trainId, `${row}${col}`, "Standard", col === "A" || col === "F" ? 1 : 0]
      );
    }
  }
}

function localNowDateTimeStr() {
  const d = new Date();
  const pad = (n) => String(n).padStart(2, "0");
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(d.getMinutes())}`;
}

// ------------------------------------------------------------------
// Auth API
// ------------------------------------------------------------------
app.post("/api/register", (req, res) => {
  const data = req.body || {};
  const name = (data.name || "").trim();
  const email = (data.email || "").trim().toLowerCase();
  const password = data.password || "";
  if (!name || !email || !password) return res.status(400).json({ error: "Name, email and password are required" });
  if (email === ADMIN_EMAIL) return res.status(409).json({ error: "This email is reserved" });
  if (queryOne("SELECT id FROM users WHERE email=?", [email])) {
    return res.status(409).json({ error: "An account with that email already exists" });
  }
  const uid = execute(
    "INSERT INTO users (name,email,password_hash,role,tier,region,status) VALUES (?,?,?,?,?,?,?)",
    [name, email, hashPassword(password), "passenger", "Standard", "", "active"]
  );
  execute("INSERT INTO notifications (user_id,title,body) VALUES (?,?,?)", [
    uid,
    "Welcome to Rail.Reserve",
    "Your account is ready. Search for a train to book your first trip.",
  ]);
  req.session.userId = uid;
  logAudit(email, "New passenger account registered");
  res.json({ user: publicUser(queryOne("SELECT * FROM users WHERE id=?", [uid])) });
});

function checkPasswordHashSafe(email, password) {
  const u = queryOne("SELECT password_hash FROM users WHERE email=?", [email]);
  if (!u) return false;
  return checkPassword(u.password_hash, password);
}

app.post("/api/login", (req, res) => {
  const data = req.body || {};
  const email = (data.email || "").trim().toLowerCase();
  const password = data.password || "";
  const tab = data.role || "passenger";

  if (tab === "admin") {
    if (email !== ADMIN_EMAIL || !checkPasswordHashSafe(ADMIN_EMAIL, password)) {
      return res.status(401).json({ error: "Invalid admin email or password." });
    }
    const admin = queryOne("SELECT * FROM users WHERE email=?", [ADMIN_EMAIL]);
    req.session.userId = admin.id;
    logAudit(admin.email, "Signed in");
    return res.json({ user: publicUser(admin) });
  }

  const u = queryOne("SELECT * FROM users WHERE email=? AND role='passenger'", [email]);
  if (!u || !checkPassword(u.password_hash, password)) {
    return res.status(401).json({ error: "Invalid email or password" });
  }
  if (u.status === "locked" || u.status === "suspended") {
    return res.status(403).json({ error: `This account is ${u.status}. Contact the admin.` });
  }
  req.session.userId = u.id;
  logAudit(email, "Signed in");
  res.json({ user: publicUser(u) });
});

app.post("/api/logout", (req, res) => {
  const u = currentUser(req);
  if (u) logAudit(u.email, "Signed out");
  req.session = null;
  res.json({ ok: true });
});

app.get("/api/me", (req, res) => {
  const u = currentUser(req);
  res.json({ user: u ? publicUser(u) : null });
});

// ------------------------------------------------------------------
// Profile
// ------------------------------------------------------------------
app.put("/api/profile", requireAuth(), (req, res) => {
  const u = req.currentUser;
  const data = req.body || {};
  const name = data.name || u.name;
  const phone = data.phone !== undefined ? data.phone : u.phone;
  const preferredSeat = data.preferred_seat !== undefined ? data.preferred_seat : u.preferred_seat;
  execute("UPDATE users SET name=?, phone=?, preferred_seat=? WHERE id=?", [name, phone, preferredSeat, u.id]);
  logAudit(u.email, "Updated profile details");
  res.json({ user: publicUser(queryOne("SELECT * FROM users WHERE id=?", [u.id])) });
});

app.put("/api/profile/preferences", requireAuth(), (req, res) => {
  const u = req.currentUser;
  const data = req.body || {};
  execute(
    "UPDATE users SET pref_email_confirm=?, pref_sms_reminder=?, pref_share_data=? WHERE id=?",
    [data.pref_email_confirm ? 1 : 0, data.pref_sms_reminder ? 1 : 0, data.pref_share_data ? 1 : 0, u.id]
  );
  res.json({ ok: true });
});

// ------------------------------------------------------------------
// Stations
// ------------------------------------------------------------------
app.get("/api/stations", (req, res) => {
  res.json({ stations: query("SELECT * FROM stations ORDER BY name") });
});

app.post("/api/admin/stations", requireAuth(["admin"]), (req, res) => {
  const u = req.currentUser;
  const data = req.body || {};
  const name = (data.name || "").trim();
  if (!name) return res.status(400).json({ error: "Station name is required" });
  if (queryOne("SELECT id FROM stations WHERE lower(name)=?", [name.toLowerCase()])) {
    return res.status(409).json({ error: "That station already exists" });
  }
  const sid = execute("INSERT INTO stations (name,code) VALUES (?,?)", [name, (data.code || "").trim().toUpperCase()]);
  logAudit(u.email, `Added station ${name}`);
  res.json({ station: queryOne("SELECT * FROM stations WHERE id=?", [sid]) });
});

app.put("/api/admin/stations/:sid", requireAuth(["admin"]), (req, res) => {
  const u = req.currentUser;
  const sid = parseInt(req.params.sid, 10);
  const st = queryOne("SELECT * FROM stations WHERE id=?", [sid]);
  if (!st) return res.status(404).json({ error: "Station not found" });
  const data = req.body || {};
  const name = data.name || st.name;
  const code = data.code !== undefined ? data.code : st.code;
  execute("UPDATE stations SET name=?, code=? WHERE id=?", [name, (code || "").toUpperCase(), sid]);
  logAudit(u.email, `Edited station ${name}`);
  res.json({ station: queryOne("SELECT * FROM stations WHERE id=?", [sid]) });
});

app.delete("/api/admin/stations/:sid", requireAuth(["admin"]), (req, res) => {
  const u = req.currentUser;
  const sid = parseInt(req.params.sid, 10);
  const st = queryOne("SELECT * FROM stations WHERE id=?", [sid]);
  if (!st) return res.status(404).json({ error: "Station not found" });
  const inUse = queryOne("SELECT id FROM routes WHERE origin_station_id=? OR destination_station_id=?", [sid, sid]);
  if (inUse) return res.status(409).json({ error: "This station is used by an existing route — remove or edit that route first" });
  execute("DELETE FROM stations WHERE id=?", [sid]);
  logAudit(u.email, `Removed station ${st.name}`);
  res.json({ ok: true });
});

// ------------------------------------------------------------------
// Routes
// ------------------------------------------------------------------
app.get("/api/routes", (req, res) => {
  const routes = query("SELECT * FROM routes ORDER BY name");
  for (const r of routes) {
    const fares = queryOne(
      `SELECT MIN(f.price) m FROM fares f JOIN trains t ON t.id=f.train_id WHERE t.route_id=?`,
      [r.id]
    );
    r.from_price = fares && fares.m !== null ? fares.m : 0;
    r.stops = r.stations.split("·").filter((s) => s.trim()).length;
  }
  res.json({ routes });
});

app.post("/api/routes", requireAuth(["admin"]), (req, res) => {
  const u = req.currentUser;
  const data = req.body || {};
  const name = (data.name || "").trim();
  if (!name) return res.status(400).json({ error: "Route name is required" });
  const originId = parseInt(data.origin_station_id, 10);
  const destId = parseInt(data.destination_station_id, 10);
  if (Number.isNaN(originId) || Number.isNaN(destId)) {
    return res.status(400).json({ error: "Please choose a real origin and destination station" });
  }
  const origin = queryOne("SELECT * FROM stations WHERE id=?", [originId]);
  const dest = queryOne("SELECT * FROM stations WHERE id=?", [destId]);
  if (!origin || !dest) return res.status(400).json({ error: "Please choose a real origin and destination station" });
  if (originId === destId) return res.status(400).json({ error: "Origin and destination must be different stations" });
  const via = (data.via || "").trim();
  const stationsDisplay = origin.name + (via ? ` · ${via}` : "") + " · " + dest.name;
  const rid = execute(
    `INSERT INTO routes (name,stations,origin_station_id,destination_station_id,distance_km,duration,category,status)
     VALUES (?,?,?,?,?,?,?,?)`,
    [name, stationsDisplay, originId, destId, parseInt(data.distance_km, 10) || 0,
      data.duration || "", data.category || "", data.status || "ACTIVE"]
  );
  logAudit(u.email, `Added route ${name}`);
  res.json({ route: queryOne("SELECT * FROM routes WHERE id=?", [rid]) });
});

app.delete("/api/routes/:routeId", requireAuth(["admin"]), (req, res) => {
  const u = req.currentUser;
  const routeId = parseInt(req.params.routeId, 10);
  const r = queryOne("SELECT * FROM routes WHERE id=?", [routeId]);
  if (!r) return res.status(404).json({ error: "Route not found" });
  const inUse = queryOne("SELECT id FROM trains WHERE route_id=?", [routeId]);
  if (inUse) return res.status(409).json({ error: "This route is used by an existing train — remove or reassign that train first" });
  execute("DELETE FROM routes WHERE id=?", [routeId]);
  logAudit(u.email, `Removed route ${r.name}`);
  res.json({ ok: true });
});

// ------------------------------------------------------------------
// Trains
// ------------------------------------------------------------------
app.get("/api/trains", (req, res) => {
  const origin = (req.query.from || "").toString().trim().toLowerCase();
  const dest = (req.query.to || "").toString().trim().toLowerCase();
  const searchDate = (req.query.date || "").toString().trim();
  let minSeats = parseInt(req.query.passengers, 10);
  if (Number.isNaN(minSeats)) minSeats = 1;

  const nowStr = localNowDateTimeStr();
  const trains = query("SELECT * FROM trains ORDER BY departure_time");
  const results = [];
  for (const t of trains) {
    if (origin && !t.origin.toLowerCase().includes(origin)) continue;
    if (dest && !t.destination.toLowerCase().includes(dest)) continue;
    // A train that has already departed is never searchable/bookable.
    if (t.departure_time && t.departure_time < nowStr) continue;
    // When a passenger searches with a specific date, only trains
    // actually scheduled to board on that exact date are shown.
    if (searchDate && t.departure_time.slice(0, 10) !== searchDate) continue;
    const tp = trainPublic(t);
    if (tp.available_seats < minSeats) continue;
    results.push(tp);
  }
  res.json({ trains: results });
});

app.get("/api/trains/:trainId", (req, res) => {
  const t = queryOne("SELECT * FROM trains WHERE id=?", [req.params.trainId]);
  if (!t) return res.status(404).json({ error: "Train not found" });
  res.json({ train: trainPublic(t) });
});

app.get("/api/trains/:trainId/seats", (req, res) => {
  const seats = query(
    "SELECT id, seat_number, seat_class, is_window, is_booked FROM seats WHERE train_id=? ORDER BY id",
    [req.params.trainId]
  );
  res.json({ seats });
});

app.get("/api/admin/trains", requireAuth(["admin"]), (req, res) => {
  res.json({ trains: query("SELECT * FROM trains ORDER BY id").map(trainAdmin) });
});

app.post("/api/admin/trains", requireAuth(["admin"]), (req, res) => {
  const u = req.currentUser;
  const data = req.body || {};
  const name = (data.name || "").trim();
  const number = (data.number || "").trim();
  const routeId = data.route_id;
  const departureTime = data.departure_time || "";
  if (!name || !number || !routeId) return res.status(400).json({ error: "Name, number and a route are required" });
  if (!departureTime) return res.status(400).json({ error: "Boarding date and time are required" });
  const route = queryOne("SELECT * FROM routes WHERE id=?", [routeId]);
  if (!route) return res.status(400).json({ error: "Please choose a valid route" });
  const originStation = queryOne("SELECT * FROM stations WHERE id=?", [route.origin_station_id]);
  const destStation = queryOne("SELECT * FROM stations WHERE id=?", [route.destination_station_id]);
  if (!originStation || !destStation) return res.status(400).json({ error: "That route is missing its station data" });

  const tid = execute(
    `INSERT INTO trains (name,number,route_id,origin,destination,departure_time,arrival_time,duration,region,status,total_seats)
     VALUES (?,?,?,?,?,?,?,?,?,?,24)`,
    [name, number, routeId, originStation.name, destStation.name, departureTime,
      data.arrival_time || "—", data.duration || route.duration || "—",
      data.region || "", data.status || "ON TIME"]
  );
  makeSeatsForTrain(tid);
  execute("INSERT INTO fares (train_id,class_name,price) VALUES (?,?,?)", [tid, "Standard", parseFloat(data.price) || 0]);
  logAudit(u.email, `Added new train ${name} #${number}`);
  res.json({ train: trainAdmin(queryOne("SELECT * FROM trains WHERE id=?", [tid])) });
});

app.put("/api/admin/trains/:trainId", requireAuth(["admin"]), (req, res) => {
  const u = req.currentUser;
  const trainId = req.params.trainId;
  const t = queryOne("SELECT * FROM trains WHERE id=?", [trainId]);
  if (!t) return res.status(404).json({ error: "Train not found" });
  const data = req.body || {};
  const fields = ["name", "number", "origin", "destination", "departure_time", "arrival_time", "duration", "status", "region"];
  const updates = {};
  for (const f of fields) {
    updates[f] = data[f] !== undefined && data[f] !== "" ? data[f] : t[f];
  }
  execute(
    `UPDATE trains SET name=?,number=?,origin=?,destination=?,departure_time=?,arrival_time=?,duration=?,status=?,region=? WHERE id=?`,
    [...fields.map((f) => updates[f]), trainId]
  );
  logAudit(u.email, `Edited train ${updates.name} #${updates.number}`);
  res.json({ train: trainAdmin(queryOne("SELECT * FROM trains WHERE id=?", [trainId])) });
});

app.delete("/api/admin/trains/:trainId", requireAuth(["admin"]), (req, res) => {
  const u = req.currentUser;
  const trainId = req.params.trainId;
  const t = queryOne("SELECT * FROM trains WHERE id=?", [trainId]);
  if (!t) return res.status(404).json({ error: "Train not found" });
  execute("DELETE FROM bookings WHERE train_id=?", [trainId]);
  execute("DELETE FROM seats WHERE train_id=?", [trainId]);
  execute("DELETE FROM fares WHERE train_id=?", [trainId]);
  execute("DELETE FROM trains WHERE id=?", [trainId]);
  logAudit(u.email, `Removed train ${t.name} #${t.number}`);
  res.json({ ok: true });
});

app.get("/api/admin/fares", requireAuth(["admin"]), (req, res) => {
  const rows = query(
    `SELECT f.id, f.class_name, f.price, f.train_id, t.name, t.number, t.departure_time, t.arrival_time
     FROM fares f JOIN trains t ON t.id = f.train_id ORDER BY f.id`
  );
  res.json({ fares: rows.map((r) => ({ ...r, train_label: `${r.name} #${r.number}` })) });
});

app.post("/api/admin/fares", requireAuth(["admin"]), (req, res) => {
  const u = req.currentUser;
  const data = req.body || {};
  if (!data.train_id || !data.class_name) return res.status(400).json({ error: "Train and class name are required" });
  const fid = execute("INSERT INTO fares (train_id,class_name,price) VALUES (?,?,?)", [
    data.train_id,
    data.class_name,
    parseFloat(data.price) || 0,
  ]);
  logAudit(u.email, `Added fare class ${data.class_name}`);
  res.json({ id: fid });
});

// ------------------------------------------------------------------
// Bookings (group booking: one shared PNR across N seats)
// ------------------------------------------------------------------
app.post("/api/bookings/group", requireAuth(), (req, res) => {
  const u = req.currentUser;
  const data = req.body || {};
  const trainId = data.train_id;
  const className = data.class_name;
  const journeyDate = data.journey_date;
  const seatIds = data.seat_ids || [];
  const pname = (data.passenger_name || "").trim();
  const pemail = (data.passenger_email || "").trim();
  const pphone = (data.passenger_phone || "").trim();
  const paymentId = (data.payment_id || "").trim();
  const paymentStatus = (data.payment_status || "").trim();

  if (!journeyDate) return res.status(400).json({ error: "Please choose a journey date" });
  if (!pname || !pemail) return res.status(400).json({ error: "Passenger name and email are required" });
  if (!seatIds.length) return res.status(400).json({ error: "Please select at least one seat" });
  if (paymentStatus !== "PAID" || !paymentId) {
    return res.status(402).json({ error: "Payment was not confirmed — booking cannot be created" });
  }
  if (queryOne("SELECT id FROM bookings WHERE payment_id=?", [paymentId])) {
    return res.status(409).json({ error: "This payment has already been used for a booking (duplicate payment ignored)" });
  }

  const t = queryOne("SELECT * FROM trains WHERE id=?", [trainId]);
  if (!t) return res.status(404).json({ error: "Train not found" });
  const fare = queryOne("SELECT * FROM fares WHERE train_id=? AND class_name=?", [trainId, className]);
  if (!fare) return res.status(400).json({ error: "That fare class is not available on this train" });

  const seatRows = [];
  for (const sid of seatIds) {
    const seat = queryOne("SELECT * FROM seats WHERE id=? AND train_id=?", [sid, trainId]);
    if (!seat) return res.status(404).json({ error: "One of the selected seats no longer exists" });
    if (seat.is_booked) return res.status(409).json({ error: `Seat ${seat.seat_number} was just taken — please pick another` });
    seatRows.push(seat);
  }

  const pnr = genPnr();
  const createdIds = [];
  for (const seat of seatRows) {
    execute("UPDATE seats SET is_booked=1 WHERE id=?", [seat.id]);
    const bid = execute(
      `INSERT INTO bookings (pnr,user_id,train_id,seat_id,journey_date,class_name,price,status,
       passenger_name,passenger_email,passenger_phone,payment_id,payment_status)
       VALUES (?,?,?,?,?,?,?, 'CONFIRMED', ?,?,?,?,?)`,
      [pnr, u.id, trainId, seat.id, journeyDate, className, fare.price, pname, pemail, pphone, paymentId, paymentStatus]
    );
    createdIds.push(bid);
  }

  execute("INSERT INTO notifications (user_id,title,body) VALUES (?,?,?)", [
    u.id,
    "Booking confirmed",
    `PNR ${pnr} — ${seatRows.length} seat(s) on ${t.name} #${t.number} (${t.origin} → ${t.destination}) for ${journeyDate}.`,
  ]);
  logAudit(u.email, `Booked ${seatRows.length} seat(s) on ${t.name} #${t.number} (PNR ${pnr})`);

  const created = createdIds.map((bid) => bookingPublic(queryOne("SELECT * FROM bookings WHERE id=?", [bid])));
  res.json({ pnr, bookings: created });
});

app.get("/api/bookings/mine", requireAuth(), (req, res) => {
  const u = req.currentUser;
  const rows = query("SELECT * FROM bookings WHERE user_id=? ORDER BY created_at DESC", [u.id]);
  res.json({ bookings: rows.map(bookingPublic) });
});

app.post("/api/bookings/:bookingId/cancel", requireAuth(), (req, res) => {
  const u = req.currentUser;
  const bookingId = req.params.bookingId;
  const b = queryOne("SELECT * FROM bookings WHERE id=?", [bookingId]);
  if (!b || (b.user_id !== u.id && u.role !== "admin")) return res.status(404).json({ error: "Booking not found" });
  if (b.status === "CANCELLED") return res.status(400).json({ error: "Booking already cancelled" });
  execute("UPDATE bookings SET status='CANCELLED' WHERE id=?", [bookingId]);
  execute("UPDATE seats SET is_booked=0 WHERE id=?", [b.seat_id]);
  execute("INSERT INTO notifications (user_id,title,body) VALUES (?,?,?)", [
    b.user_id,
    "Booking cancelled",
    `Your booking (PNR ${b.pnr}) has been cancelled.`,
  ]);
  logAudit(u.email, `Cancelled booking PNR ${b.pnr}`);
  res.json({ ok: true });
});

app.get("/api/pnr/:pnr", (req, res) => {
  const matches = query("SELECT * FROM bookings WHERE pnr=?", [req.params.pnr]);
  if (!matches.length) return res.status(404).json({ error: "No booking found for that PNR" });
  res.json({ booking: bookingPublic(matches[0]), bookings: matches.map(bookingPublic) });
});

// ------------------------------------------------------------------
// Notifications
// ------------------------------------------------------------------
app.get("/api/notifications", requireAuth(), (req, res) => {
  const u = req.currentUser;
  res.json({ notifications: query("SELECT * FROM notifications WHERE user_id=? ORDER BY created_at DESC", [u.id]) });
});

app.post("/api/notifications/read-all", requireAuth(), (req, res) => {
  const u = req.currentUser;
  execute("UPDATE notifications SET is_read=1 WHERE user_id=?", [u.id]);
  res.json({ ok: true });
});

// ------------------------------------------------------------------
// Admin: passengers, bookings, reports, settings, revenue, audit
// ------------------------------------------------------------------
app.get("/api/admin/passengers", requireAuth(["admin"]), (req, res) => {
  const rows = query("SELECT * FROM users WHERE role='passenger' ORDER BY name");
  const out = rows.map((r) => {
    const trips = queryOne("SELECT COUNT(*) c FROM bookings WHERE user_id=?", [r.id]).c;
    return { ...publicUser(r), total_trips: trips };
  });
  res.json({ passengers: out });
});

app.post("/api/admin/passengers/:pid/toggle-suspend", requireAuth(["admin"]), (req, res) => {
  const u = req.currentUser;
  const pid = req.params.pid;
  const p = queryOne("SELECT * FROM users WHERE id=?", [pid]);
  if (!p) return res.status(404).json({ error: "Passenger not found" });
  const newStatus = p.status === "suspended" ? "active" : "suspended";
  execute("UPDATE users SET status=? WHERE id=?", [newStatus, pid]);
  logAudit(u.email, `Set ${p.email} status to ${newStatus}`);
  res.json({ status: newStatus });
});

app.get("/api/admin/bookings", requireAuth(["admin"]), (req, res) => {
  const status = req.query.status;
  let sql = "SELECT * FROM bookings";
  let args = [];
  if (status && status.toString().toLowerCase() !== "all") {
    sql += " WHERE status=?";
    args = [status.toString().toUpperCase()];
  }
  sql += " ORDER BY created_at DESC";
  res.json({ bookings: query(sql, args).map(bookingPublic) });
});

app.get("/api/admin/reports/summary", requireAuth(["admin"]), (req, res) => {
  const revenue = queryOne("SELECT COALESCE(SUM(price),0) s FROM bookings WHERE status!='CANCELLED'").s;
  const active = queryOne("SELECT COUNT(*) c FROM bookings WHERE status='CONFIRMED'").c;
  const completed = queryOne("SELECT COUNT(*) c FROM bookings WHERE status='COMPLETED'").c;
  const cancelled = queryOne("SELECT COUNT(*) c FROM bookings WHERE status='CANCELLED'").c;
  const totalSeats = queryOne("SELECT COUNT(*) c FROM seats").c;
  const bookedSeats = queryOne("SELECT COUNT(*) c FROM seats WHERE is_booked=1").c;
  const occ = totalSeats ? Math.round((bookedSeats / totalSeats) * 100) : 0;
  res.json({
    revenue: Math.round(revenue * 100) / 100,
    active_bookings: active,
    completed_bookings: completed,
    cancelled_bookings: cancelled,
    occupancy_pct: occ,
  });
});

app.get("/api/admin/settings", requireAuth(["admin"]), (req, res) => {
  const rows = query("SELECT key,value FROM settings");
  const settings = {};
  for (const r of rows) settings[r.key] = r.value;
  res.json({ settings });
});

app.put("/api/admin/settings", requireAuth(["admin"]), (req, res) => {
  const u = req.currentUser;
  const data = req.body || {};
  for (const [k, v] of Object.entries(data)) {
    execute(
      "INSERT INTO settings (key,value) VALUES (?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
      [k, String(v)]
    );
  }
  logAudit(u.email, "Updated system settings");
  res.json({ ok: true });
});

app.get("/api/admin/revenue", requireAuth(["admin"]), (req, res) => {
  const total = queryOne("SELECT COALESCE(SUM(price),0) s FROM bookings WHERE status!='CANCELLED'").s;
  const byRoute = query(`
    SELECT r.name, COALESCE(SUM(b.price),0) revenue
    FROM routes r
    LEFT JOIN trains t ON t.route_id = r.id
    LEFT JOIN bookings b ON b.train_id = t.id AND b.status != 'CANCELLED'
    GROUP BY r.id ORDER BY revenue DESC
  `);
  const passengers = queryOne("SELECT COUNT(*) c FROM users WHERE role='passenger'").c;
  const totalTrains = queryOne("SELECT COUNT(*) c FROM trains").c;
  res.json({
    total_revenue: Math.round(total * 100) / 100,
    by_route: byRoute,
    total_passengers: passengers,
    total_trains: totalTrains,
  });
});

app.get("/api/admin/audit", requireAuth(["admin"]), (req, res) => {
  res.json({ logs: query("SELECT * FROM audit_logs ORDER BY id DESC LIMIT 100") });
});

// ------------------------------------------------------------------
// Payments — real Razorpay when RAZORPAY_KEY_ID/SECRET are configured
// (order creation + HMAC signature verification happen server-side,
// where the secret key actually stays secret). If not configured, the
// frontend falls back to a clearly-labeled sandbox test flow so the
// app still runs without requiring a Razorpay account.
// ------------------------------------------------------------------
app.get("/api/payments/config", (req, res) => {
  res.json({ configured: RAZORPAY_ENABLED, key_id: RAZORPAY_ENABLED ? RAZORPAY_KEY_ID : null });
});

app.post("/api/payments/create-order", requireAuth(), async (req, res) => {
  if (!RAZORPAY_ENABLED) return res.status(503).json({ error: "Payment gateway is not configured on this server" });
  const u = req.currentUser;
  const data = req.body || {};
  const trainId = data.train_id;
  const seatIds = data.seat_ids || [];
  const className = data.class_name;
  const journeyDate = data.journey_date;
  const pname = (data.passenger_name || "").trim();
  const pemail = (data.passenger_email || "").trim();
  const pphone = (data.passenger_phone || "").trim();

  if (!seatIds.length || !journeyDate || !pname || !pemail) return res.status(400).json({ error: "Missing booking details" });
  const t = queryOne("SELECT * FROM trains WHERE id=?", [trainId]);
  const fare = queryOne("SELECT * FROM fares WHERE train_id=? AND class_name=?", [trainId, className]);
  if (!t || !fare) return res.status(400).json({ error: "Invalid train or fare class" });
  for (const sid of seatIds) {
    const seat = queryOne("SELECT * FROM seats WHERE id=? AND train_id=?", [sid, trainId]);
    if (!seat || seat.is_booked) return res.status(409).json({ error: "One or more selected seats are no longer available" });
  }

  const amount = fare.price * seatIds.length;
  const currency = "INR";
  let rpOrder;
  try {
    rpOrder = await razorpayClient.orders.create({
      amount: Math.round(amount * 100),
      currency,
      payment_capture: 1,
    });
  } catch (e) {
    return res.status(502).json({ error: `Could not create payment order: ${e.message || e}` });
  }

  execute(
    `INSERT INTO payment_orders (order_id,user_id,train_id,seat_ids,class_name,journey_date,
     passenger_name,passenger_email,passenger_phone,amount,currency,status)
     VALUES (?,?,?,?,?,?,?,?,?,?,?, 'created')`,
    [rpOrder.id, u.id, trainId, seatIds.join(","), className, journeyDate, pname, pemail, pphone, amount, currency]
  );
  res.json({ order_id: rpOrder.id, amount, currency, key_id: RAZORPAY_KEY_ID });
});

app.post("/api/payments/verify", requireAuth(), (req, res) => {
  if (!RAZORPAY_ENABLED) return res.status(503).json({ error: "Payment gateway is not configured on this server" });
  const u = req.currentUser;
  const data = req.body || {};
  const orderId = data.razorpay_order_id;
  const paymentId = data.razorpay_payment_id;
  const signature = data.razorpay_signature;
  if (!orderId || !paymentId || !signature) return res.status(400).json({ error: "Missing payment verification fields" });

  const order = queryOne("SELECT * FROM payment_orders WHERE order_id=?", [orderId]);
  if (!order) return res.status(404).json({ error: "Unknown payment order" });
  if (order.status === "paid") {
    return res.status(409).json({ error: "This order has already been used for a booking (duplicate payment ignored)" });
  }

  // Real HMAC-SHA256 signature verification, exactly as Razorpay documents:
  // expected = HMAC_SHA256(order_id + "|" + payment_id, key_secret)
  const payload = `${orderId}|${paymentId}`;
  const expectedSig = crypto.createHmac("sha256", RAZORPAY_KEY_SECRET).update(payload).digest("hex");
  const sigBuf = Buffer.from(signature, "utf8");
  const expBuf = Buffer.from(expectedSig, "utf8");
  const validSig = sigBuf.length === expBuf.length && crypto.timingSafeEqual(sigBuf, expBuf);
  if (!validSig) {
    execute("UPDATE payment_orders SET status='failed' WHERE order_id=?", [orderId]);
    return res.status(402).json({ error: "Payment verification failed — signature mismatch" });
  }

  execute("UPDATE payment_orders SET status='paid', razorpay_payment_id=? WHERE order_id=?", [paymentId, orderId]);

  const seatIds = order.seat_ids.split(",").filter(Boolean).map((s) => parseInt(s, 10));
  const t = queryOne("SELECT * FROM trains WHERE id=?", [order.train_id]);
  const fare = queryOne("SELECT * FROM fares WHERE train_id=? AND class_name=?", [order.train_id, order.class_name]);
  if (!t || !fare) return res.status(404).json({ error: "Train or fare no longer exists" });

  const seatRows = [];
  for (const sid of seatIds) {
    const seat = queryOne("SELECT * FROM seats WHERE id=? AND train_id=?", [sid, order.train_id]);
    if (!seat || seat.is_booked) {
      return res.status(409).json({ error: "A selected seat was taken by someone else — contact support, your payment was captured" });
    }
    seatRows.push(seat);
  }

  const pnr = genPnr();
  const createdIds = [];
  for (const seat of seatRows) {
    execute("UPDATE seats SET is_booked=1 WHERE id=?", [seat.id]);
    const bid = execute(
      `INSERT INTO bookings (pnr,user_id,train_id,seat_id,journey_date,class_name,price,status,
       passenger_name,passenger_email,passenger_phone,payment_id,payment_status)
       VALUES (?,?,?,?,?,?,?, 'CONFIRMED', ?,?,?,?, 'PAID')`,
      [pnr, u.id, order.train_id, seat.id, order.journey_date, order.class_name, fare.price,
        order.passenger_name, order.passenger_email, order.passenger_phone, paymentId]
    );
    createdIds.push(bid);
  }

  execute("INSERT INTO notifications (user_id,title,body) VALUES (?,?,?)", [
    u.id,
    "Booking confirmed",
    `PNR ${pnr} — payment verified, ${seatRows.length} seat(s) booked.`,
  ]);
  logAudit(u.email, `Paid booking on ${t.name} #${t.number} (PNR ${pnr}, Razorpay payment ${paymentId})`);

  const created = createdIds.map((bid) => bookingPublic(queryOne("SELECT * FROM bookings WHERE id=?", [bid])));
  res.json({ pnr, bookings: created });
});

// A generic Express error handler as a last line of defense — if any
// route handler throws synchronously (or passes an error to next()),
// this returns a clean JSON error instead of the request hanging or
// the process crashing.
app.use((err, req, res, next) => {
  console.error("Unhandled request error:", err);
  if (res.headersSent) return next(err);
  const status = err.statusCode || err.status || 500;
  const message = status < 500 ? (err.message || "Bad request") : "Internal server error";
  res.status(status).json({ error: message });
});

// Keep the process running on unexpected errors rather than exiting —
// this is a long-running local/dev API server, and one bad request
// should never take the whole thing down.
process.on("uncaughtException", (err) => {
  console.error("Uncaught exception (server is still running):", err);
});
process.on("unhandledRejection", (err) => {
  console.error("Unhandled promise rejection (server is still running):", err);
});

const server = app.listen(PORT, () => {
  console.log(`Rail.Reserve API listening on http://localhost:${PORT}`);
  console.log(`Accepting requests from frontend origin(s): ${ALLOWED_ORIGINS.join(", ")}`);
  if (!RAZORPAY_ENABLED) {
    console.log("Razorpay not configured (RAZORPAY_KEY_ID/RAZORPAY_KEY_SECRET unset) — payments run in sandbox test mode.");
  }
});

server.on("error", (err) => {
  if (err.code === "EADDRINUSE") {
    console.error(
      `Port ${PORT} is already in use. Stop whatever else is using it, or set a different PORT in backend/.env, then restart.`
    );
    process.exit(1);
  } else {
    console.error("Server failed to start:", err);
    process.exit(1);
  }
});
