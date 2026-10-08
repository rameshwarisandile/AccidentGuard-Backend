"""AccidentResponse backend  (Flask + SQLite)
Run:  python app.py      ->  http://0.0.0.0:5000
"""
import os, re, sqlite3, secrets, hashlib, random
import datetime as dt
import jwt
from flask import Flask, request, jsonify, g
from werkzeug.security import generate_password_hash, check_password_hash

BASE = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.environ.get("DB_PATH", os.path.join(BASE, "accident.db"))
JWT_SECRET = os.environ.get("JWT_SECRET", "dev-secret-change-me")
DEMO_LAT = float(os.environ.get("DEMO_LAT", "20.5937"))
DEMO_LNG = float(os.environ.get("DEMO_LNG", "78.9629"))

RELATIONSHIPS = ["Family", "Friend", "Brother", "Sister", "Mother", "Father", "Husband", "Other"]
STATUS_BY_TYPE = {
    "Possible Accident": "Warning",
    "Confirmed Accident": "Danger",
    "Obstacle Detected": "Warning",
    "System Check": "Normal",
    "System Warning": "Warning",
    "Confirmed Emergency": "Danger",
}
ALERT_TYPES = ("Confirmed Accident", "Confirmed Emergency")
ONLINE_SECONDS = 120

app = Flask(__name__)

SCHEMA = """
CREATE TABLE IF NOT EXISTS users(
  id INTEGER PRIMARY KEY AUTOINCREMENT, full_name TEXT NOT NULL, email TEXT UNIQUE NOT NULL,
  phone TEXT, password_hash TEXT NOT NULL, role TEXT DEFAULT 'Vehicle Owner',
  emergency_alerts INTEGER DEFAULT 1, notifications INTEGER DEFAULT 1, created_at TEXT);
CREATE TABLE IF NOT EXISTS devices(
  id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL, name TEXT DEFAULT 'ESP32 Safety Unit',
  key_hash TEXT UNIQUE NOT NULL, last_seen_at TEXT, last_lat REAL, last_lng REAL, last_location_at TEXT);
CREATE TABLE IF NOT EXISTS contacts(
  id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL, name TEXT NOT NULL, phone TEXT NOT NULL,
  relationship TEXT NOT NULL, is_primary INTEGER DEFAULT 0, created_at TEXT);
CREATE TABLE IF NOT EXISTS events(
  id INTEGER PRIMARY KEY AUTOINCREMENT, incident_id TEXT UNIQUE, user_id INTEGER NOT NULL, device_id INTEGER,
  event_type TEXT NOT NULL, status TEXT NOT NULL, description TEXT, latitude REAL, longitude REAL,
  location_text TEXT, occurred_at TEXT NOT NULL, resolved_at TEXT);
CREATE TABLE IF NOT EXISTS notification_log(
  id INTEGER PRIMARY KEY AUTOINCREMENT, event_id INTEGER, contact_id INTEGER, channel TEXT,
  status TEXT, message TEXT, created_at TEXT);
"""


def init_db():
    con = sqlite3.connect(DB_PATH)
    con.executescript(SCHEMA)
    con.commit()
    con.close()


def db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(_exc):
    d = g.pop("db", None)
    if d is not None:
        d.close()


def now_iso():
    return dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_iso(s):
    if not s:
        return None
    return dt.datetime.strptime(s, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=dt.timezone.utc)


def is_recent(s):
    t = parse_iso(s)
    return bool(t) and (dt.datetime.now(dt.timezone.utc) - t).total_seconds() <= ONLINE_SECONDS


def err(code, message, status=400):
    return jsonify({"error": {"code": code, "message": message}}), status


def hash_key(k):
    return hashlib.sha256(k.encode()).hexdigest()


def make_token(uid):
    exp = dt.datetime.now(dt.timezone.utc) + dt.timedelta(days=7)
    return jwt.encode({"sub": str(uid), "exp": exp}, JWT_SECRET, algorithm="HS256")


def auth_required(fn):
    from functools import wraps

    @wraps(fn)
    def wrapper(*a, **kw):
        h = request.headers.get("Authorization", "")
        if not h.startswith("Bearer "):
            return err("unauthorized", "Please sign in.", 401)
        try:
            uid = int(jwt.decode(h[7:], JWT_SECRET, algorithms=["HS256"])["sub"])
        except Exception:
            return err("unauthorized", "Session expired. Please sign in again.", 401)
        u = db().execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()
        if not u:
            return err("unauthorized", "Account not found.", 401)
        g.user = u
        return fn(*a, **kw)
    return wrapper


def device_required(fn):
    from functools import wraps

    @wraps(fn)
    def wrapper(*a, **kw):
        key = request.headers.get("X-Device-Key", "")
        d = db().execute("SELECT * FROM devices WHERE key_hash=?", (hash_key(key),)).fetchone() if key else None
        if not d:
            return err("invalid_device_key", "Invalid or missing X-Device-Key.", 401)
        g.device = d
        return fn(*a, **kw)
    return wrapper


def user_json(u):
    return {"id": u["id"], "full_name": u["full_name"], "email": u["email"], "phone": u["phone"] or "",
            "role": u["role"], "emergency_alerts_enabled": bool(u["emergency_alerts"]),
            "notifications_enabled": bool(u["notifications"])}


def contact_json(c):
    return {"id": c["id"], "name": c["name"], "phone": c["phone"], "relationship": c["relationship"],
            "is_primary": bool(c["is_primary"])}


def event_json(e):
    return {"incident_id": e["incident_id"], "event_type": e["event_type"], "status": e["status"],
            "description": e["description"] or "", "latitude": e["latitude"], "longitude": e["longitude"],
            "location_text": e["location_text"] or "Unknown", "occurred_at": e["occurred_at"],
            "resolved_at": e["resolved_at"]}


def device_json(d):
    connected = is_recent(d["last_seen_at"])
    return {"id": d["id"], "name": d["name"], "status": "Connected" if connected else "Disconnected",
            "last_seen_at": d["last_seen_at"]}


def body():
    return request.get_json(silent=True) or {}


# ------------------------------------------------------------------ auth
@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/api/v1/auth/register")
def register():
    b = body()
    name = (b.get("full_name") or "").strip()
    email = (b.get("email") or "").strip().lower()
    phone = (b.get("phone") or "").strip()
    pw = b.get("password") or ""
    if not name:
        return err("validation", "Name is required")
    if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email):
        return err("validation", "Please enter a valid email address")
    if phone and not re.fullmatch(r"\d{10}", phone):
        return err("validation", "Please enter a valid 10-digit phone number")
    if len(pw) < 6:
        return err("validation", "Password must be at least 6 characters")
    con = db()
    if con.execute("SELECT 1 FROM users WHERE email=?", (email,)).fetchone():
        return err("email_taken", "This email is already registered.", 409)
    cur = con.execute("INSERT INTO users(full_name,email,phone,password_hash,created_at) VALUES(?,?,?,?,?)",
                      (name, email, phone, generate_password_hash(pw), now_iso()))
    uid = cur.lastrowid
    key = "dev_" + secrets.token_urlsafe(24)
    con.execute("INSERT INTO devices(user_id,key_hash) VALUES(?,?)", (uid, hash_key(key)))
    con.commit()
    u = con.execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()
    return jsonify({"access_token": make_token(uid), "user": user_json(u), "device_key": key}), 201


@app.post("/api/v1/auth/login")
def login():
    b = body()
    email = (b.get("email") or "").strip().lower()
    u = db().execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
    if not u or not check_password_hash(u["password_hash"], b.get("password") or ""):
        return err("invalid_credentials", "Invalid email or password", 401)
    return jsonify({"access_token": make_token(u["id"]), "user": user_json(u)})


@app.post("/api/v1/auth/forgot-password")
def forgot():
    return jsonify({"message": "If this email is registered, password reset instructions will be sent to that email address."})


@app.get("/api/v1/auth/me")
@auth_required
def me():
    return jsonify({"user": user_json(g.user)})


# --------------------------------------------------------------- profile
@app.put("/api/v1/profile")
@auth_required
def update_profile():
    b = body()
    name = (b.get("full_name") or g.user["full_name"]).strip()
    phone = (b.get("phone") if b.get("phone") is not None else g.user["phone"] or "").strip()
    if not name:
        return err("validation", "Name is required")
    if phone and not re.fullmatch(r"\d{10}", phone):
        return err("validation", "Please enter a valid 10-digit phone number")
    db().execute("UPDATE users SET full_name=?, phone=? WHERE id=?", (name, phone, g.user["id"]))
    db().commit()
    u = db().execute("SELECT * FROM users WHERE id=?", (g.user["id"],)).fetchone()
    return jsonify({"user": user_json(u)})


@app.put("/api/v1/profile/settings")
@auth_required
def update_settings():
    b = body()
    a = int(bool(b.get("emergency_alerts_enabled", bool(g.user["emergency_alerts"]))))
    n = int(bool(b.get("notifications_enabled", bool(g.user["notifications"]))))
    db().execute("UPDATE users SET emergency_alerts=?, notifications=? WHERE id=?", (a, n, g.user["id"]))
    db().commit()
    u = db().execute("SELECT * FROM users WHERE id=?", (g.user["id"],)).fetchone()
    return jsonify({"user": user_json(u)})


# -------------------------------------------------------------- contacts
def ensure_primary(uid):
    con = db()
    if con.execute("SELECT 1 FROM contacts WHERE user_id=? AND is_primary=1", (uid,)).fetchone():
        return
    first = con.execute("SELECT id FROM contacts WHERE user_id=? ORDER BY id LIMIT 1", (uid,)).fetchone()
    if first:
        con.execute("UPDATE contacts SET is_primary=1 WHERE id=?", (first["id"],))


def validate_contact(b):
    name = (b.get("name") or "").strip()
    phone = (b.get("phone") or "").strip()
    rel = (b.get("relationship") or "").strip()
    if not name:
        return None, "Name is required"
    if not re.fullmatch(r"\d{10}", phone):
        return None, "Please enter a valid 10-digit phone number"
    if rel not in RELATIONSHIPS:
        return None, "Please choose a relationship"
    return (name, phone, rel), None


@app.get("/api/v1/contacts")
@auth_required
def list_contacts():
    rows = db().execute("SELECT * FROM contacts WHERE user_id=? ORDER BY is_primary DESC, id ASC",
                        (g.user["id"],)).fetchall()
    return jsonify({"items": [contact_json(r) for r in rows]})


@app.post("/api/v1/contacts")
@auth_required
def add_contact():
    b = body()
    vals, e = validate_contact(b)
    if e:
        return err("validation", e)
    con, uid = db(), g.user["id"]
    has_any = con.execute("SELECT 1 FROM contacts WHERE user_id=?", (uid,)).fetchone()
    make_primary = bool(b.get("is_primary")) or not has_any
    if make_primary:
        con.execute("UPDATE contacts SET is_primary=0 WHERE user_id=?", (uid,))
    cur = con.execute("INSERT INTO contacts(user_id,name,phone,relationship,is_primary,created_at) VALUES(?,?,?,?,?,?)",
                      (uid, *vals, int(make_primary), now_iso()))
    con.commit()
    row = con.execute("SELECT * FROM contacts WHERE id=?", (cur.lastrowid,)).fetchone()
    return jsonify({"contact": contact_json(row)}), 201


def own_contact(cid):
    return db().execute("SELECT * FROM contacts WHERE id=? AND user_id=?", (cid, g.user["id"])).fetchone()


@app.put("/api/v1/contacts/<int:cid>")
@auth_required
def edit_contact(cid):
    if not own_contact(cid):
        return err("not_found", "Contact not found", 404)
    b = body()
    vals, e = validate_contact(b)
    if e:
        return err("validation", e)
    con, uid = db(), g.user["id"]
    if b.get("is_primary"):
        con.execute("UPDATE contacts SET is_primary=0 WHERE user_id=?", (uid,))
        con.execute("UPDATE contacts SET is_primary=1 WHERE id=?", (cid,))
    con.execute("UPDATE contacts SET name=?, phone=?, relationship=? WHERE id=?", (*vals, cid))
    ensure_primary(uid)
    con.commit()
    return jsonify({"contact": contact_json(own_contact(cid))})


@app.delete("/api/v1/contacts/<int:cid>")
@auth_required
def delete_contact(cid):
    if not own_contact(cid):
        return err("not_found", "Contact not found", 404)
    db().execute("DELETE FROM contacts WHERE id=?", (cid,))
    ensure_primary(g.user["id"])
    db().commit()
    return jsonify({"deleted": True})


@app.post("/api/v1/contacts/<int:cid>/set-primary")
@auth_required
def set_primary(cid):
    if not own_contact(cid):
        return err("not_found", "Contact not found", 404)
    db().execute("UPDATE contacts SET is_primary=0 WHERE user_id=?", (g.user["id"],))
    db().execute("UPDATE contacts SET is_primary=1 WHERE id=?", (cid,))
    db().commit()
    return jsonify({"contact": contact_json(own_contact(cid))})


# ---------------------------------------------------------------- events
def notify_contacts(con, user, event_row):
    """Console provider: logs the SMS text. Swap this for Twilio/MSG91 later."""
    if not user["emergency_alerts"]:
        return 0
    contacts = con.execute("SELECT * FROM contacts WHERE user_id=? ORDER BY is_primary DESC, id", (user["id"],)).fetchall()
    link = f"https://maps.google.com/?q={event_row['latitude']},{event_row['longitude']}"
    msg = f"EMERGENCY: {user['full_name']}'s vehicle reported a {event_row['event_type']} ({event_row['incident_id']}). Location: {link}"
    for c in contacts:
        con.execute("INSERT INTO notification_log(event_id,contact_id,channel,status,message,created_at) VALUES(?,?,?,?,?,?)",
                    (event_row["id"], c["id"], "console", "logged", msg, now_iso()))
        print(f"[NOTIFY] -> {c['name']} ({c['phone']}): {msg}", flush=True)
    return len(contacts)


def create_event(con, user, device_id, etype, description, lat, lng, occurred_at=None):
    status = STATUS_BY_TYPE[etype]
    loc = f"{lat:.5f}, {lng:.5f}" if lat is not None and lng is not None else "Unknown"
    cur = con.execute("INSERT INTO events(user_id,device_id,event_type,status,description,latitude,longitude,location_text,occurred_at) VALUES(?,?,?,?,?,?,?,?,?)",
                      (user["id"], device_id, etype, status, description, lat, lng, loc, occurred_at or now_iso()))
    eid = cur.lastrowid
    con.execute("UPDATE events SET incident_id=? WHERE id=?", (f"INC-{eid:06d}", eid))
    row = con.execute("SELECT * FROM events WHERE id=?", (eid,)).fetchone()
    if etype in ALERT_TYPES:
        notify_contacts(con, user, row)
    con.commit()
    return row


@app.get("/api/v1/events/summary")
@auth_required
def events_summary():
    con, uid = db(), g.user["id"]
    total = con.execute("SELECT COUNT(*) c FROM events WHERE user_id=?", (uid,)).fetchone()["c"]
    latest = con.execute("SELECT * FROM events WHERE user_id=? ORDER BY occurred_at DESC, id DESC LIMIT 1", (uid,)).fetchone()
    sysstat = latest["status"] if latest and latest["status"] in ("Danger", "Warning") else "Normal"
    dev = con.execute("SELECT * FROM devices WHERE user_id=? ORDER BY id LIMIT 1", (uid,)).fetchone()
    return jsonify({"total": total, "latest_event": event_json(latest) if latest else None,
                    "system_status": sysstat, "device": device_json(dev) if dev else None})


@app.get("/api/v1/safety/insights")
@auth_required
def safety_insights():
    con, uid = db(), g.user["id"]
    latest = con.execute("SELECT * FROM events WHERE user_id=? ORDER BY occurred_at DESC, id DESC LIMIT 1", (uid,)).fetchone()
    recent = con.execute("SELECT COUNT(*) c FROM events WHERE user_id=? AND occurred_at >= datetime('now', '-24 hours')", (uid,)).fetchone()["c"]
    dev = con.execute("SELECT * FROM devices WHERE user_id=? ORDER BY id LIMIT 1", (uid,)).fetchone()
    score = 8 + min(recent * 7, 28)
    if latest:
        score += {"Danger":55,"Warning":25,"Normal":0,"Resolved":5}.get(latest["status"],10)
    if not dev or not is_recent(dev["last_seen_at"]): score += 12
    score = min(score, 100)
    if score >= 75:
        priority, assessment = "CRITICAL", "Immediate human review recommended. A recent danger event or unhealthy device signal increases response risk."
    elif score >= 45:
        priority, assessment = "HIGH", "Attention recommended. Recent safety activity indicates elevated operational risk."
    elif score >= 25:
        priority, assessment = "MODERATE", "System is mostly stable, but continued monitoring is recommended."
    else:
        priority, assessment = "LOW", "No significant risk signal is visible from the latest available telemetry."
    actions = "Open live map | Check latest event | Call emergency services if an accident is confirmed | Notify primary contact | Review event history"
    return jsonify({"risk_score": score, "priority": priority, "assessment": assessment, "actions": actions, "latest_event": event_json(latest) if latest else None})


@app.get("/api/v1/events")
@auth_required
def list_events():
    limit = min(max(request.args.get("limit", 50, type=int), 1), 200)
    offset = max(request.args.get("offset", 0, type=int), 0)
    status = request.args.get("status")
    sql, args = "FROM events WHERE user_id=?", [g.user["id"]]
    if status:
        sql += " AND status=?"
        args.append(status)
    total = db().execute("SELECT COUNT(*) c " + sql, args).fetchone()["c"]
    rows = db().execute("SELECT * " + sql + " ORDER BY occurred_at DESC, id DESC LIMIT ? OFFSET ?", args + [limit, offset]).fetchall()
    return jsonify({"items": [event_json(r) for r in rows], "total": total})


def own_event(iid):
    return db().execute("SELECT * FROM events WHERE incident_id=? AND user_id=?", (iid, g.user["id"])).fetchone()


@app.get("/api/v1/events/<iid>")
@auth_required
def get_event(iid):
    e = own_event(iid)
    return jsonify({"event": event_json(e)}) if e else err("not_found", "Event not found", 404)


@app.post("/api/v1/events/<iid>/resolve")
@auth_required
def resolve_event(iid):
    e = own_event(iid)
    if not e:
        return err("not_found", "Event not found", 404)
    db().execute("UPDATE events SET status='Resolved', resolved_at=? WHERE id=?", (now_iso(), e["id"]))
    db().commit()
    return jsonify({"event": event_json(own_event(iid))})


# -------------------------------------------------------------- location
@app.get("/api/v1/location/latest")
@auth_required
def latest_location():
    d = db().execute("SELECT * FROM devices WHERE user_id=? ORDER BY id LIMIT 1", (g.user["id"],)).fetchone()
    if not d or d["last_lat"] is None:
        return jsonify({"lat": None, "lng": None, "status": "No data", "last_updated": None})
    return jsonify({"lat": d["last_lat"], "lng": d["last_lng"],
                    "status": "Live" if is_recent(d["last_location_at"]) else "Last known",
                    "last_updated": d["last_location_at"]})


# --------------------------------------------------------------- devices
@app.get("/api/v1/devices")
@auth_required
def list_devices():
    rows = db().execute("SELECT * FROM devices WHERE user_id=?", (g.user["id"],)).fetchall()
    return jsonify({"items": [device_json(r) for r in rows]})


@app.post("/api/v1/devices/rotate-key")
@auth_required
def rotate_key():
    d = db().execute("SELECT * FROM devices WHERE user_id=? ORDER BY id LIMIT 1", (g.user["id"],)).fetchone()
    key = "dev_" + secrets.token_urlsafe(24)
    if d:
        db().execute("UPDATE devices SET key_hash=? WHERE id=?", (hash_key(key), d["id"]))
    else:
        db().execute("INSERT INTO devices(user_id,key_hash) VALUES(?,?)", (g.user["id"], hash_key(key)))
    db().commit()
    return jsonify({"device_key": key})


@app.post("/api/v1/device/location")
@device_required
def device_location():
    b = body()
    try:
        lat, lng = float(b["lat"]), float(b["lng"])
    except Exception:
        return err("validation", "lat and lng are required numbers")
    t = now_iso()
    db().execute("UPDATE devices SET last_lat=?, last_lng=?, last_location_at=?, last_seen_at=? WHERE id=?",
                 (lat, lng, t, t, g.device["id"]))
    db().commit()
    return jsonify({"ok": True})


@app.post("/api/v1/device/events")
@device_required
def device_event():
    b = body()
    etype = b.get("event_type")
    if etype not in STATUS_BY_TYPE:
        return err("validation", "event_type must be one of: " + ", ".join(STATUS_BY_TYPE))
    lat, lng = b.get("lat"), b.get("lng")
    try:
        lat = float(lat) if lat is not None else None
        lng = float(lng) if lng is not None else None
    except Exception:
        return err("validation", "lat/lng must be numbers")
    con = db()
    user = con.execute("SELECT * FROM users WHERE id=?", (g.device["user_id"],)).fetchone()
    t = now_iso()
    if lat is not None and lng is not None:
        con.execute("UPDATE devices SET last_lat=?, last_lng=?, last_location_at=? WHERE id=?", (lat, lng, t, g.device["id"]))
    con.execute("UPDATE devices SET last_seen_at=? WHERE id=?", (t, g.device["id"]))
    row = create_event(con, user, g.device["id"], etype, b.get("description") or "", lat, lng)
    return jsonify({"event": event_json(row)}), 201


@app.post("/api/v1/demo/simulate")
@auth_required
def demo_simulate():
    """Pretend to be the ESP32 (for demos without hardware)."""
    etype = body().get("event_type", "Confirmed Accident")
    if etype not in STATUS_BY_TYPE:
        return err("validation", "Unknown event_type")
    con = db()
    d = con.execute("SELECT * FROM devices WHERE user_id=? ORDER BY id LIMIT 1", (g.user["id"],)).fetchone()
    lat = DEMO_LAT + random.uniform(-0.01, 0.01)
    lng = DEMO_LNG + random.uniform(-0.01, 0.01)
    t = now_iso()
    con.execute("UPDATE devices SET last_lat=?, last_lng=?, last_location_at=?, last_seen_at=? WHERE id=?", (lat, lng, t, t, d["id"]))
    desc = {"Confirmed Accident": "Crash detected by accelerometer. Impact above threshold.",
            "Possible Accident": "Sudden deceleration detected. Awaiting confirmation.",
            "Obstacle Detected": "Obstacle detected ahead by ultrasonic sensor.",
            "System Warning": "Sensor reading out of range.",
            "System Check": "Routine system check passed.",
            "Confirmed Emergency": "Driver triggered emergency."}[etype]
    row = create_event(con, g.user, d["id"], etype, desc, lat, lng)
    return jsonify({"event": event_json(row)}), 201


init_db()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)), debug=False)
