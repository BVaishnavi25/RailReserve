import os
from dotenv import load_dotenv
import sqlite3
import random
import string
import hmac
import hashlib
from datetime import datetime
from functools import wraps

from flask import Flask, request, jsonify, session, render_template, g

load_dotenv()

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "railreserve.db")

app = Flask(__name__)
app.secret_key = os.environ["RAILRESERVE_SECRET"]
app.config["JSON_SORT_KEYS"] = False

ADMIN_EMAIL = os.environ["RAILRESERVE_ADMIN_EMAIL"]
ADMIN_PASSWORD = os.environ["RAILRESERVE_ADMIN_PASSWORD"]

RAZORPAY_KEY_ID = os.environ.get("RAZORPAY_KEY_ID", "")
RAZORPAY_KEY_SECRET = os.environ.get("RAZORPAY_KEY_SECRET", "")
RAZORPAY_ENABLED = bool(RAZORPAY_KEY_ID and RAZORPAY_KEY_SECRET)

_razorpay_client = None
if RAZORPAY_ENABLED:
    try:
        import razorpay
        _razorpay_client = razorpay.Client(auth=(RAZORPAY_KEY_ID, RAZORPAY_KEY_SECRET))
    except ImportError:
        RAZORPAY_ENABLED = False
        print("razorpay package not installed (pip install razorpay) — falling back to test-mode payments.")

def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
    return g.db

@app.teardown_appcontext
def close_db(exc):
    db = g.pop("db", None)
    if db is not None:
        db.close()

def query(sql, args=(), one=False):
    cur = get_db().execute(sql, args)
    rows = cur.fetchall()
    cur.close()
    return (rows[0] if rows else None) if one else rows

def execute(sql, args=()):
    db = get_db()
    cur = db.execute(sql, args)
    db.commit()
    lastid = cur.lastrowid
    cur.close()
    return lastid

def row_to_dict(row):
    return dict(row) if row is not None else None

def rows_to_list(rows):
    return [dict(r) for r in rows]

def nowiso():
    return datetime.utcnow().strftime("%Y-%m-%d %H:%M")

def gen_pnr():
    return "".join(random.choices(string.digits, k=10))

def hash_password(password):
    from werkzeug.security import generate_password_hash
    return generate_password_hash(password)

def check_password(pw_hash, password):
    from werkzeug.security import check_password_hash
    return check_password_hash(pw_hash, password)

def log_audit(actor, action):
    execute("INSERT INTO audit_logs (actor, action, created_at) VALUES (?,?,?)", (actor, action, nowiso()))
# ------------------------------------------------------------------
# Schema — single admin, stations -> routes -> trains, group bookings
# ------------------------------------------------------------------
SCHEMA = """
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
"""

DEFAULT_SETTINGS = {
    "maintenance_mode": "0",
    "two_factor_admins": "1",
    "email_notifications": "1",
    "default_currency": "USD",
    "default_timezone": "UTC",
    "min_occupancy_alert": "75%",
    "cancellation_fee": "$15",
    "dynamic_pricing_cap": "3%",
    "auto_release_unpaid": "1",
}


def seed_if_empty():
    db = get_db()
    db.executescript(SCHEMA)
    db.commit()

    admin = query("SELECT id FROM users WHERE email=?", (ADMIN_EMAIL,), one=True)
    if not admin:
        execute(
            "INSERT INTO users (name,email,password_hash,role,tier,region,status) VALUES (?,?,?,?,?,?,?)",
            ("Admin", ADMIN_EMAIL, hash_password(ADMIN_PASSWORD), "admin", "Admin", "Global", "active"),
        )
        log_audit(ADMIN_EMAIL, "System initialized — admin account ready")

    if query("SELECT COUNT(*) c FROM settings", one=True)["c"] == 0:
        for k, v in DEFAULT_SETTINGS.items():
            execute("INSERT INTO settings (key,value) VALUES (?,?)", (k, v))

    db.commit()


with app.app_context():
    seed_if_empty()


# ------------------------------------------------------------------
# Auth helpers
# ------------------------------------------------------------------
def current_user():
    uid = session.get("user_id")
    if not uid:
        return None
    return query("SELECT * FROM users WHERE id=?", (uid,), one=True)


def login_required(roles=None):
    def deco(fn):
        @wraps(fn)
        def wrapper(*a, **kw):
            u = current_user()
            if not u:
                return jsonify(error="Not authenticated"), 401
            if roles and u["role"] not in roles:
                return jsonify(error="Not authorized"), 403
            return fn(u, *a, **kw)
        return wrapper
    return deco


def public_user(u):
    d = row_to_dict(u)
    if d:
        d.pop("password_hash", None)
    return d


# ------------------------------------------------------------------
# Page
# ------------------------------------------------------------------
@app.route("/")
def index():
    return render_template("index.html")


# ------------------------------------------------------------------
# Auth API
# ------------------------------------------------------------------
@app.post("/api/register")
def register():
    data = request.get_json(force=True)
    name = (data.get("name") or "").strip()
    email = (data.get("email") or "").strip().lower()
    password = data.get("password") or ""
    if not name or not email or not password:
        return jsonify(error="Name, email and password are required"), 400
    if email == ADMIN_EMAIL:
        return jsonify(error="This email is reserved"), 409
    if query("SELECT id FROM users WHERE email=?", (email,), one=True):
        return jsonify(error="An account with that email already exists"), 409
    uid = execute(
        "INSERT INTO users (name,email,password_hash,role,tier,region,status) VALUES (?,?,?,?,?,?,?)",
        (name, email, hash_password(password), "passenger", "Standard", "", "active"),
    )
    execute("INSERT INTO notifications (user_id,title,body) VALUES (?,?,?)",
            (uid, "Welcome to Rail.Reserve", "Your account is ready. Search for a train to book your first trip."))
    session["user_id"] = uid
    log_audit(email, "New passenger account registered")
    return jsonify(user=public_user(query("SELECT * FROM users WHERE id=?", (uid,), one=True)))


def check_password_hash_safe(email, password):
    u = query("SELECT password_hash FROM users WHERE email=?", (email,), one=True)
    if not u:
        return False
    return check_password(u["password_hash"], password)


@app.post("/api/login")
def login():
    data = request.get_json(force=True)
    email = (data.get("email") or "").strip().lower()
    password = data.get("password") or ""
    tab = data.get("role") or "passenger"

    if tab == "admin":
        if email != ADMIN_EMAIL or not check_password_hash_safe(ADMIN_EMAIL, password):
            return jsonify(error="Invalid admin email or password."), 401
        admin = query("SELECT * FROM users WHERE email=?", (ADMIN_EMAIL,), one=True)
        session["user_id"] = admin["id"]
        log_audit(admin["email"], "Signed in")
        return jsonify(user=public_user(admin))

    u = query("SELECT * FROM users WHERE email=? AND role='passenger'", (email,), one=True)
    if not u or not check_password(u["password_hash"], password):
        return jsonify(error="Invalid email or password"), 401
    if u["status"] in ("locked", "suspended"):
        return jsonify(error=f"This account is {u['status']}. Contact the admin."), 403
    session["user_id"] = u["id"]
    log_audit(email, "Signed in")
    return jsonify(user=public_user(u))


@app.post("/api/logout")
def logout():
    u = current_user()
    if u:
        log_audit(u["email"], "Signed out")
    session.clear()
    return jsonify(ok=True)


@app.get("/api/me")
def me():
    u = current_user()
    return jsonify(user=public_user(u) if u else None)


# ------------------------------------------------------------------
# Profile
# ------------------------------------------------------------------
@app.put("/api/profile")
@login_required()
def update_profile(u):
    data = request.get_json(force=True)
    name = data.get("name") or u["name"]
    phone = data.get("phone", u["phone"])
    preferred_seat = data.get("preferred_seat", u["preferred_seat"])
    execute("UPDATE users SET name=?, phone=?, preferred_seat=? WHERE id=?", (name, phone, preferred_seat, u["id"]))
    log_audit(u["email"], "Updated profile details")
    return jsonify(user=public_user(query("SELECT * FROM users WHERE id=?", (u["id"],), one=True)))


@app.put("/api/profile/preferences")
@login_required()
def update_preferences(u):
    data = request.get_json(force=True)
    execute(
        "UPDATE users SET pref_email_confirm=?, pref_sms_reminder=?, pref_share_data=? WHERE id=?",
        (int(bool(data.get("pref_email_confirm"))), int(bool(data.get("pref_sms_reminder"))),
         int(bool(data.get("pref_share_data"))), u["id"]),
    )
    return jsonify(ok=True)


# ------------------------------------------------------------------
# Stations
# ------------------------------------------------------------------
@app.get("/api/stations")
def list_stations():
    return jsonify(stations=rows_to_list(query("SELECT * FROM stations ORDER BY name")))


@app.post("/api/admin/stations")
@login_required(roles=["admin"])
def add_station(u):
    data = request.get_json(force=True)
    name = (data.get("name") or "").strip()
    if not name:
        return jsonify(error="Station name is required"), 400
    if query("SELECT id FROM stations WHERE lower(name)=?", (name.lower(),), one=True):
        return jsonify(error="That station already exists"), 409
    sid = execute("INSERT INTO stations (name,code) VALUES (?,?)", (name, (data.get("code") or "").strip().upper()))
    log_audit(u["email"], f"Added station {name}")
    return jsonify(station=row_to_dict(query("SELECT * FROM stations WHERE id=?", (sid,), one=True)))


@app.put("/api/admin/stations/<int:sid>")
@login_required(roles=["admin"])
def edit_station(u, sid):
    st = query("SELECT * FROM stations WHERE id=?", (sid,), one=True)
    if not st:
        return jsonify(error="Station not found"), 404
    data = request.get_json(force=True)
    name = data.get("name") or st["name"]
    code = data.get("code", st["code"])
    execute("UPDATE stations SET name=?, code=? WHERE id=?", (name, (code or "").upper(), sid))
    log_audit(u["email"], f"Edited station {name}")
    return jsonify(station=row_to_dict(query("SELECT * FROM stations WHERE id=?", (sid,), one=True)))


@app.delete("/api/admin/stations/<int:sid>")
@login_required(roles=["admin"])
def delete_station(u, sid):
    st = query("SELECT * FROM stations WHERE id=?", (sid,), one=True)
    if not st:
        return jsonify(error="Station not found"), 404
    in_use = query("SELECT id FROM routes WHERE origin_station_id=? OR destination_station_id=?", (sid, sid), one=True)
    if in_use:
        return jsonify(error="This station is used by an existing route — remove or edit that route first"), 409
    execute("DELETE FROM stations WHERE id=?", (sid,))
    log_audit(u["email"], f"Removed station {st['name']}")
    return jsonify(ok=True)


# ------------------------------------------------------------------
# Routes
# ------------------------------------------------------------------
@app.get("/api/routes")
def list_routes():
    routes = rows_to_list(query("SELECT * FROM routes ORDER BY name"))
    for r in routes:
        fares = query("""SELECT MIN(f.price) m FROM fares f JOIN trains t ON t.id=f.train_id
                          WHERE t.route_id=?""", (r["id"],), one=True)
        r["from_price"] = fares["m"] if fares and fares["m"] is not None else 0
        r["stops"] = len([s for s in r["stations"].split("·") if s.strip()])
    return jsonify(routes=routes)


@app.post("/api/routes")
@login_required(roles=["admin"])
def add_route(u):
    data = request.get_json(force=True)
    name = (data.get("name") or "").strip()
    if not name:
        return jsonify(error="Route name is required"), 400
    try:
        origin_id = int(data.get("origin_station_id"))
        dest_id = int(data.get("destination_station_id"))
    except (TypeError, ValueError):
        return jsonify(error="Please choose a real origin and destination station"), 400
    origin = query("SELECT * FROM stations WHERE id=?", (origin_id,), one=True)
    dest = query("SELECT * FROM stations WHERE id=?", (dest_id,), one=True)
    if not origin or not dest:
        return jsonify(error="Please choose a real origin and destination station"), 400
    if origin_id == dest_id:
        return jsonify(error="Origin and destination must be different stations"), 400
    via = (data.get("via") or "").strip()
    stations_display = origin["name"] + (f" · {via}" if via else "") + " · " + dest["name"]
    rid = execute(
        """INSERT INTO routes (name,stations,origin_station_id,destination_station_id,distance_km,duration,category,status)
           VALUES (?,?,?,?,?,?,?,?)""",
        (name, stations_display, origin_id, dest_id, int(data.get("distance_km") or 0),
         data.get("duration") or "", data.get("category") or "", data.get("status") or "ACTIVE"),
    )
    log_audit(u["email"], f"Added route {name}")
    return jsonify(route=row_to_dict(query("SELECT * FROM routes WHERE id=?", (rid,), one=True)))


@app.delete("/api/routes/<int:route_id>")
@login_required(roles=["admin"])
def delete_route(u, route_id):
    r = query("SELECT * FROM routes WHERE id=?", (route_id,), one=True)
    if not r:
        return jsonify(error="Route not found"), 404
    in_use = query("SELECT id FROM trains WHERE route_id=?", (route_id,), one=True)
    if in_use:
        return jsonify(error="This route is used by an existing train — remove or reassign that train first"), 409
    execute("DELETE FROM routes WHERE id=?", (route_id,))
    log_audit(u["email"], f"Removed route {r['name']}")
    return jsonify(ok=True)


# ------------------------------------------------------------------
# Trains
# ------------------------------------------------------------------
def train_public(t):
    d = row_to_dict(t)
    fares = rows_to_list(query("SELECT class_name, price FROM fares WHERE train_id=?", (t["id"],)))
    total = query("SELECT COUNT(*) c FROM seats WHERE train_id=?", (t["id"],), one=True)["c"]
    booked = query("SELECT COUNT(*) c FROM seats WHERE train_id=? AND is_booked=1", (t["id"],), one=True)["c"]
    d["fares"] = fares
    d["min_fare"] = min([f["price"] for f in fares], default=0)
    d["total_seats"] = total
    d["booked_seats"] = booked
    d["available_seats"] = total - booked
    d["occupancy_pct"] = round((booked / total) * 100) if total else 0
    return d


def train_admin(t):
    d = row_to_dict(t)
    total = query("SELECT COUNT(*) c FROM seats WHERE train_id=?", (t["id"],), one=True)["c"]
    booked = query("SELECT COUNT(*) c FROM seats WHERE train_id=? AND is_booked=1", (t["id"],), one=True)["c"]
    d["occupancy_pct"] = round((booked / total) * 100) if total else 0
    d["total_seats"] = total
    return d


@app.get("/api/trains")
def list_trains():
    origin = (request.args.get("from") or "").strip().lower()
    dest = (request.args.get("to") or "").strip().lower()
    search_date = (request.args.get("date") or "").strip()
    try:
        min_seats = int(request.args.get("passengers") or 1)
    except ValueError:
        min_seats = 1
    now_str = datetime.now().strftime("%Y-%m-%dT%H:%M")
    trains = query("SELECT * FROM trains ORDER BY departure_time")
    results = []
    for t in trains:
        if origin and origin not in t["origin"].lower():
            continue
        if dest and dest not in t["destination"].lower():
            continue
        # A train that has already departed is never searchable/bookable.
        if t["departure_time"] and t["departure_time"] < now_str:
            continue
        # When a passenger searches with a specific date, only trains
        # actually scheduled to board on that exact date are shown.
        if search_date and t["departure_time"][:10] != search_date:
            continue
        tp = train_public(t)
        if tp["available_seats"] < min_seats:
            continue
        results.append(tp)
    return jsonify(trains=results)


@app.get("/api/trains/<int:train_id>")
def get_train(train_id):
    t = query("SELECT * FROM trains WHERE id=?", (train_id,), one=True)
    if not t:
        return jsonify(error="Train not found"), 404
    return jsonify(train=train_public(t))


@app.get("/api/trains/<int:train_id>/seats")
def train_seats(train_id):
    seats = rows_to_list(query(
        "SELECT id, seat_number, seat_class, is_window, is_booked FROM seats WHERE train_id=? ORDER BY id", (train_id,)))
    return jsonify(seats=seats)


def make_seats_for_train(train_id):
    for row in range(1, 5):
        for col in "ABCDEF":
            execute("INSERT INTO seats (train_id,seat_number,seat_class,is_window,is_booked) VALUES (?,?,?,?,0)",
                    (train_id, f"{row}{col}", "Standard", 1 if col in ("A", "F") else 0))


@app.get("/api/admin/trains")
@login_required(roles=["admin"])
def admin_trains(u):
    return jsonify(trains=[train_admin(t) for t in query("SELECT * FROM trains ORDER BY id")])


@app.post("/api/admin/trains")
@login_required(roles=["admin"])
def admin_add_train(u):
    data = request.get_json(force=True)
    name = (data.get("name") or "").strip()
    number = (data.get("number") or "").strip()
    route_id = data.get("route_id")
    departure_time = data.get("departure_time") or ""
    if not name or not number or not route_id:
        return jsonify(error="Name, number and a route are required"), 400
    if not departure_time:
        return jsonify(error="Boarding date and time are required"), 400
    route = query("SELECT * FROM routes WHERE id=?", (route_id,), one=True)
    if not route:
        return jsonify(error="Please choose a valid route"), 400
    origin_station = query("SELECT * FROM stations WHERE id=?", (route["origin_station_id"],), one=True)
    dest_station = query("SELECT * FROM stations WHERE id=?", (route["destination_station_id"],), one=True)
    if not origin_station or not dest_station:
        return jsonify(error="That route is missing its station data"), 400
    tid = execute(
        """INSERT INTO trains (name,number,route_id,origin,destination,departure_time,arrival_time,duration,region,status,total_seats)
           VALUES (?,?,?,?,?,?,?,?,?,?,24)""",
        (name, number, route_id, origin_station["name"], dest_station["name"], departure_time,
         data.get("arrival_time") or "—", data.get("duration") or route["duration"] or "—",
         data.get("region") or "", data.get("status") or "ON TIME"),
    )
    make_seats_for_train(tid)
    execute("INSERT INTO fares (train_id,class_name,price) VALUES (?,?,?)",
            (tid, "Standard", float(data.get("price") or 0)))
    log_audit(u["email"], f"Added new train {name} #{number}")
    return jsonify(train=train_admin(query("SELECT * FROM trains WHERE id=?", (tid,), one=True)))


@app.put("/api/admin/trains/<int:train_id>")
@login_required(roles=["admin"])
def admin_edit_train(u, train_id):
    t = query("SELECT * FROM trains WHERE id=?", (train_id,), one=True)
    if not t:
        return jsonify(error="Train not found"), 404
    data = request.get_json(force=True)
    fields = ["name", "number", "origin", "destination", "departure_time", "arrival_time", "duration", "status", "region"]
    updates = {f: data.get(f) if data.get(f) not in (None, "") else t[f] for f in fields}
    execute(
        """UPDATE trains SET name=?,number=?,origin=?,destination=?,departure_time=?,arrival_time=?,duration=?,status=?,region=?
           WHERE id=?""",
        (*[updates[f] for f in fields], train_id),
    )
    log_audit(u["email"], f"Edited train {updates['name']} #{updates['number']}")
    return jsonify(train=train_admin(query("SELECT * FROM trains WHERE id=?", (train_id,), one=True)))


@app.delete("/api/admin/trains/<int:train_id>")
@login_required(roles=["admin"])
def admin_delete_train(u, train_id):
    t = query("SELECT * FROM trains WHERE id=?", (train_id,), one=True)
    if not t:
        return jsonify(error="Train not found"), 404
    execute("DELETE FROM bookings WHERE train_id=?", (train_id,))
    execute("DELETE FROM seats WHERE train_id=?", (train_id,))
    execute("DELETE FROM fares WHERE train_id=?", (train_id,))
    execute("DELETE FROM trains WHERE id=?", (train_id,))
    log_audit(u["email"], f"Removed train {t['name']} #{t['number']}")
    return jsonify(ok=True)


@app.get("/api/admin/fares")
@login_required(roles=["admin"])
def admin_fares(u):
    rows = query("""SELECT f.id, f.class_name, f.price, f.train_id, t.name, t.number, t.departure_time, t.arrival_time
                     FROM fares f JOIN trains t ON t.id = f.train_id ORDER BY f.id""")
    return jsonify(fares=[dict(r) | {"train_label": f"{r['name']} #{r['number']}"} for r in rows])


@app.post("/api/admin/fares")
@login_required(roles=["admin"])
def admin_add_fare(u):
    data = request.get_json(force=True)
    if not data.get("train_id") or not data.get("class_name"):
        return jsonify(error="Train and class name are required"), 400
    fid = execute("INSERT INTO fares (train_id,class_name,price) VALUES (?,?,?)",
                  (data.get("train_id"), data.get("class_name"), float(data.get("price") or 0)))
    log_audit(u["email"], f"Added fare class {data.get('class_name')}")
    return jsonify(id=fid)


# ------------------------------------------------------------------
# Bookings (group booking: one shared PNR across N seats)
# ------------------------------------------------------------------
def booking_public(b):
    d = row_to_dict(b)
    t = query("SELECT * FROM trains WHERE id=?", (b["train_id"],), one=True)
    s = query("SELECT * FROM seats WHERE id=?", (b["seat_id"],), one=True)
    usr = query("SELECT name,email FROM users WHERE id=?", (b["user_id"],), one=True)
    d["train_name"] = f"{t['name']} #{t['number']}" if t else "(train removed)"
    d["origin"] = t["origin"] if t else ""
    d["destination"] = t["destination"] if t else ""
    d["departure_time"] = t["departure_time"] if t else ""
    d["arrival_time"] = t["arrival_time"] if t else ""
    d["seat_number"] = s["seat_number"] if s else ""
    d["seat_type"] = "Window" if (s and s["is_window"]) else "Aisle"
    if not d.get("passenger_name"):
        d["passenger_name"] = usr["name"] if usr else ""
    if not d.get("passenger_email"):
        d["passenger_email"] = usr["email"] if usr else ""
    return d


@app.post("/api/bookings/group")
@login_required()
def create_group_booking(u):
    data = request.get_json(force=True)
    train_id = data.get("train_id")
    class_name = data.get("class_name")
    journey_date = data.get("journey_date")
    seat_ids = data.get("seat_ids") or []
    pname = (data.get("passenger_name") or "").strip()
    pemail = (data.get("passenger_email") or "").strip()
    pphone = (data.get("passenger_phone") or "").strip()
    payment_id = (data.get("payment_id") or "").strip()
    payment_status = (data.get("payment_status") or "").strip()

    if not journey_date:
        return jsonify(error="Please choose a journey date"), 400
    if not pname or not pemail:
        return jsonify(error="Passenger name and email are required"), 400
    if not seat_ids:
        return jsonify(error="Please select at least one seat"), 400
    if payment_status != "PAID" or not payment_id:
        return jsonify(error="Payment was not confirmed — booking cannot be created"), 402
    if query("SELECT id FROM bookings WHERE payment_id=?", (payment_id,), one=True):
        return jsonify(error="This payment has already been used for a booking (duplicate payment ignored)"), 409

    t = query("SELECT * FROM trains WHERE id=?", (train_id,), one=True)
    if not t:
        return jsonify(error="Train not found"), 404
    fare = query("SELECT * FROM fares WHERE train_id=? AND class_name=?", (train_id, class_name), one=True)
    if not fare:
        return jsonify(error="That fare class is not available on this train"), 400

    seat_rows = []
    for sid in seat_ids:
        seat = query("SELECT * FROM seats WHERE id=? AND train_id=?", (sid, train_id), one=True)
        if not seat:
            return jsonify(error="One of the selected seats no longer exists"), 404
        if seat["is_booked"]:
            return jsonify(error=f"Seat {seat['seat_number']} was just taken — please pick another"), 409
        seat_rows.append(seat)

    pnr = gen_pnr()
    created_ids = []
    for seat in seat_rows:
        execute("UPDATE seats SET is_booked=1 WHERE id=?", (seat["id"],))
        bid = execute(
            """INSERT INTO bookings (pnr,user_id,train_id,seat_id,journey_date,class_name,price,status,
               passenger_name,passenger_email,passenger_phone,payment_id,payment_status)
               VALUES (?,?,?,?,?,?,?, 'CONFIRMED', ?,?,?,?,?)""",
            (pnr, u["id"], train_id, seat["id"], journey_date, class_name, fare["price"],
             pname, pemail, pphone, payment_id, payment_status),
        )
        created_ids.append(bid)

    execute("INSERT INTO notifications (user_id,title,body) VALUES (?,?,?)",
            (u["id"], "Booking confirmed",
             f"PNR {pnr} — {len(seat_rows)} seat(s) on {t['name']} #{t['number']} ({t['origin']} → {t['destination']}) for {journey_date}."))
    log_audit(u["email"], f"Booked {len(seat_rows)} seat(s) on {t['name']} #{t['number']} (PNR {pnr})")

    created = [booking_public(query("SELECT * FROM bookings WHERE id=?", (bid,), one=True)) for bid in created_ids]
    return jsonify(pnr=pnr, bookings=created)


@app.get("/api/bookings/mine")
@login_required()
def my_bookings(u):
    rows = query("SELECT * FROM bookings WHERE user_id=? ORDER BY created_at DESC", (u["id"],))
    return jsonify(bookings=[booking_public(b) for b in rows])


@app.post("/api/bookings/<int:booking_id>/cancel")
@login_required()
def cancel_booking(u, booking_id):
    b = query("SELECT * FROM bookings WHERE id=?", (booking_id,), one=True)
    if not b or (b["user_id"] != u["id"] and u["role"] != "admin"):
        return jsonify(error="Booking not found"), 404
    if b["status"] == "CANCELLED":
        return jsonify(error="Booking already cancelled"), 400
    execute("UPDATE bookings SET status='CANCELLED' WHERE id=?", (booking_id,))
    execute("UPDATE seats SET is_booked=0 WHERE id=?", (b["seat_id"],))
    execute("INSERT INTO notifications (user_id,title,body) VALUES (?,?,?)",
            (b["user_id"], "Booking cancelled", f"Your booking (PNR {b['pnr']}) has been cancelled."))
    log_audit(u["email"], f"Cancelled booking PNR {b['pnr']}")
    return jsonify(ok=True)


@app.get("/api/pnr/<pnr>")
def check_pnr(pnr):
    matches = query("SELECT * FROM bookings WHERE pnr=?", (pnr,))
    if not matches:
        return jsonify(error="No booking found for that PNR"), 404
    return jsonify(booking=booking_public(matches[0]), bookings=[booking_public(b) for b in matches])


# ------------------------------------------------------------------
# Notifications
# ------------------------------------------------------------------
@app.get("/api/notifications")
@login_required()
def list_notifications(u):
    return jsonify(notifications=rows_to_list(
        query("SELECT * FROM notifications WHERE user_id=? ORDER BY created_at DESC", (u["id"],))))


@app.post("/api/notifications/read-all")
@login_required()
def mark_all_read(u):
    execute("UPDATE notifications SET is_read=1 WHERE user_id=?", (u["id"],))
    return jsonify(ok=True)


# ------------------------------------------------------------------
# Admin: passengers, bookings, reports, settings, revenue, audit
# ------------------------------------------------------------------
@app.get("/api/admin/passengers")
@login_required(roles=["admin"])
def admin_passengers(u):
    rows = query("SELECT * FROM users WHERE role='passenger' ORDER BY name")
    out = []
    for r in rows:
        trips = query("SELECT COUNT(*) c FROM bookings WHERE user_id=?", (r["id"],), one=True)["c"]
        out.append(public_user(r) | {"total_trips": trips})
    return jsonify(passengers=out)


@app.post("/api/admin/passengers/<int:pid>/toggle-suspend")
@login_required(roles=["admin"])
def admin_toggle_suspend(u, pid):
    p = query("SELECT * FROM users WHERE id=?", (pid,), one=True)
    if not p:
        return jsonify(error="Passenger not found"), 404
    new_status = "active" if p["status"] == "suspended" else "suspended"
    execute("UPDATE users SET status=? WHERE id=?", (new_status, pid))
    log_audit(u["email"], f"Set {p['email']} status to {new_status}")
    return jsonify(status=new_status)


@app.get("/api/admin/bookings")
@login_required(roles=["admin"])
def admin_bookings(u):
    status = request.args.get("status")
    sql = "SELECT * FROM bookings"
    args = ()
    if status and status.lower() != "all":
        sql += " WHERE status=?"
        args = (status.upper(),)
    sql += " ORDER BY created_at DESC"
    return jsonify(bookings=[booking_public(b) for b in query(sql, args)])


@app.get("/api/admin/reports/summary")
@login_required(roles=["admin"])
def admin_reports_summary(u):
    revenue = query("SELECT COALESCE(SUM(price),0) s FROM bookings WHERE status!='CANCELLED'", one=True)["s"]
    active = query("SELECT COUNT(*) c FROM bookings WHERE status='CONFIRMED'", one=True)["c"]
    completed = query("SELECT COUNT(*) c FROM bookings WHERE status='COMPLETED'", one=True)["c"]
    cancelled = query("SELECT COUNT(*) c FROM bookings WHERE status='CANCELLED'", one=True)["c"]
    total_seats = query("SELECT COUNT(*) c FROM seats", one=True)["c"]
    booked_seats = query("SELECT COUNT(*) c FROM seats WHERE is_booked=1", one=True)["c"]
    occ = round((booked_seats / total_seats) * 100) if total_seats else 0
    return jsonify(revenue=round(revenue, 2), active_bookings=active, completed_bookings=completed,
                    cancelled_bookings=cancelled, occupancy_pct=occ)


@app.get("/api/admin/settings")
@login_required(roles=["admin"])
def admin_get_settings(u):
    rows = query("SELECT key,value FROM settings")
    return jsonify(settings={r["key"]: r["value"] for r in rows})


@app.put("/api/admin/settings")
@login_required(roles=["admin"])
def admin_update_settings(u):
    data = request.get_json(force=True)
    for k, v in data.items():
        execute("INSERT INTO settings (key,value) VALUES (?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                (k, str(v)))
    log_audit(u["email"], "Updated system settings")
    return jsonify(ok=True)


@app.get("/api/admin/revenue")
@login_required(roles=["admin"])
def admin_revenue(u):
    total = query("SELECT COALESCE(SUM(price),0) s FROM bookings WHERE status!='CANCELLED'", one=True)["s"]
    by_route = query("""
        SELECT r.name, COALESCE(SUM(b.price),0) revenue
        FROM routes r
        LEFT JOIN trains t ON t.route_id = r.id
        LEFT JOIN bookings b ON b.train_id = t.id AND b.status != 'CANCELLED'
        GROUP BY r.id ORDER BY revenue DESC
    """)
    passengers = query("SELECT COUNT(*) c FROM users WHERE role='passenger'", one=True)["c"]
    total_trains = query("SELECT COUNT(*) c FROM trains", one=True)["c"]
    return jsonify(total_revenue=round(total, 2), by_route=rows_to_list(by_route),
                    total_passengers=passengers, total_trains=total_trains)


@app.get("/api/admin/audit")
@login_required(roles=["admin"])
def admin_audit(u):
    return jsonify(logs=rows_to_list(query("SELECT * FROM audit_logs ORDER BY id DESC LIMIT 100")))


# ------------------------------------------------------------------
# Payments — real Razorpay when RAZORPAY_KEY_ID/SECRET are configured
# (order creation + HMAC signature verification happen server-side,
# where the secret key actually stays secret). If not configured, the
# frontend falls back to a clearly-labeled sandbox test flow so the
# app still runs without requiring a Razorpay account.
# ------------------------------------------------------------------
@app.get("/api/payments/config")
def payments_config():
    return jsonify(configured=RAZORPAY_ENABLED, key_id=RAZORPAY_KEY_ID if RAZORPAY_ENABLED else None)


@app.post("/api/payments/create-order")
@login_required()
def create_payment_order(u):
    if not RAZORPAY_ENABLED:
        return jsonify(error="Payment gateway is not configured on this server"), 503
    data = request.get_json(force=True)
    train_id = data.get("train_id")
    seat_ids = data.get("seat_ids") or []
    class_name = data.get("class_name")
    journey_date = data.get("journey_date")
    pname = (data.get("passenger_name") or "").strip()
    pemail = (data.get("passenger_email") or "").strip()
    pphone = (data.get("passenger_phone") or "").strip()

    if not seat_ids or not journey_date or not pname or not pemail:
        return jsonify(error="Missing booking details"), 400
    t = query("SELECT * FROM trains WHERE id=?", (train_id,), one=True)
    fare = query("SELECT * FROM fares WHERE train_id=? AND class_name=?", (train_id, class_name), one=True)
    if not t or not fare:
        return jsonify(error="Invalid train or fare class"), 400
    for sid in seat_ids:
        seat = query("SELECT * FROM seats WHERE id=? AND train_id=?", (sid, train_id), one=True)
        if not seat or seat["is_booked"]:
            return jsonify(error="One or more selected seats are no longer available"), 409

    amount = fare["price"] * len(seat_ids)
    currency = "INR"
    try:
        rp_order = _razorpay_client.order.create({
            "amount": int(round(amount * 100)),
            "currency": currency,
            "payment_capture": 1,
        })
    except Exception as e:
        return jsonify(error=f"Could not create payment order: {e}"), 502

    execute(
        """INSERT INTO payment_orders (order_id,user_id,train_id,seat_ids,class_name,journey_date,
           passenger_name,passenger_email,passenger_phone,amount,currency,status)
           VALUES (?,?,?,?,?,?,?,?,?,?,?, 'created')""",
        (rp_order["id"], u["id"], train_id, ",".join(str(s) for s in seat_ids), class_name, journey_date,
         pname, pemail, pphone, amount, currency),
    )
    return jsonify(order_id=rp_order["id"], amount=amount, currency=currency, key_id=RAZORPAY_KEY_ID)


@app.post("/api/payments/verify")
@login_required()
def verify_payment(u):
    if not RAZORPAY_ENABLED:
        return jsonify(error="Payment gateway is not configured on this server"), 503
    data = request.get_json(force=True)
    order_id = data.get("razorpay_order_id")
    payment_id = data.get("razorpay_payment_id")
    signature = data.get("razorpay_signature")
    if not order_id or not payment_id or not signature:
        return jsonify(error="Missing payment verification fields"), 400

    order = query("SELECT * FROM payment_orders WHERE order_id=?", (order_id,), one=True)
    if not order:
        return jsonify(error="Unknown payment order"), 404
    if order["status"] == "paid":
        return jsonify(error="This order has already been used for a booking (duplicate payment ignored)"), 409

    payload = f"{order_id}|{payment_id}"
    expected_sig = hmac.new(RAZORPAY_KEY_SECRET.encode(), payload.encode(), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected_sig, signature):
        execute("UPDATE payment_orders SET status='failed' WHERE order_id=?", (order_id,))
        return jsonify(error="Payment verification failed — signature mismatch"), 402

    execute("UPDATE payment_orders SET status='paid', razorpay_payment_id=? WHERE order_id=?", (payment_id, order_id))

    seat_ids = [int(s) for s in order["seat_ids"].split(",") if s]
    t = query("SELECT * FROM trains WHERE id=?", (order["train_id"],), one=True)
    fare = query("SELECT * FROM fares WHERE train_id=? AND class_name=?", (order["train_id"], order["class_name"]), one=True)
    if not t or not fare:
        return jsonify(error="Train or fare no longer exists"), 404

    seat_rows = []
    for sid in seat_ids:
        seat = query("SELECT * FROM seats WHERE id=? AND train_id=?", (sid, order["train_id"]), one=True)
        if not seat or seat["is_booked"]:
            return jsonify(error="A selected seat was taken by someone else — contact support, your payment was captured"), 409
        seat_rows.append(seat)

    pnr = gen_pnr()
    created_ids = []
    for seat in seat_rows:
        execute("UPDATE seats SET is_booked=1 WHERE id=?", (seat["id"],))
        bid = execute(
            """INSERT INTO bookings (pnr,user_id,train_id,seat_id,journey_date,class_name,price,status,
               passenger_name,passenger_email,passenger_phone,payment_id,payment_status)
               VALUES (?,?,?,?,?,?,?, 'CONFIRMED', ?,?,?,?, 'PAID')""",
            (pnr, u["id"], order["train_id"], seat["id"], order["journey_date"], order["class_name"], fare["price"],
             order["passenger_name"], order["passenger_email"], order["passenger_phone"], payment_id),
        )
        created_ids.append(bid)

    execute("INSERT INTO notifications (user_id,title,body) VALUES (?,?,?)",
            (u["id"], "Booking confirmed", f"PNR {pnr} — payment verified, {len(seat_rows)} seat(s) booked."))
    log_audit(u["email"], f"Paid booking on {t['name']} #{t['number']} (PNR {pnr}, Razorpay payment {payment_id})")

    created = [booking_public(query("SELECT * FROM bookings WHERE id=?", (bid,), one=True)) for bid in created_ids]
    return jsonify(pnr=pnr, bookings=created)


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=True, use_reloader=False)
