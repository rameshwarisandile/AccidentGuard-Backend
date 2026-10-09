
"""AccidentGuard backend: Flask + PostgreSQL on Render, SQLite for local tests."""
import os
import re
import sqlite3
import secrets
import hashlib
import random
import datetime as dt

import jwt
import psycopg
from psycopg.rows import dict_row
from flask import Flask, request, jsonify, g
from werkzeug.security import generate_password_hash, check_password_hash

BASE = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.environ.get("DB_PATH", os.path.join(BASE, "accident.db"))
DATABASE_URL = os.environ.get("DATABASE_URL")
USE_POSTGRES = bool(DATABASE_URL) and "DB_PATH" not in os.environ

JWT_SECRET = os.environ.get("JWT_SECRET", "dev-secret-change-me")
DEMO_LAT = float(os.environ.get("DEMO_LAT", "20.5937"))
DEMO_LNG = float(os.environ.get("DEMO_LNG", "78.9629"))

RELATIONSHIPS = [
    "Family", "Friend", "Brother", "Sister",
    "Mother", "Father", "Husband", "Other"
]

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
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  full_name TEXT NOT NULL,
  email TEXT UNIQUE NOT NULL,
  phone TEXT,
  password_hash TEXT NOT NULL,
  role TEXT DEFAULT 'Vehicle Owner',
  emergency_alerts INTEGER DEFAULT 1,
  notifications INTEGER DEFAULT 1,
  created_at TEXT
);

CREATE TABLE IF NOT EXISTS devices(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  name TEXT DEFAULT 'ESP32 Safety Unit',
  key_hash TEXT UNIQUE NOT NULL,
  last_seen_at TEXT,
  last_lat REAL,
  last_lng REAL,
  last_location_at TEXT
);

CREATE TABLE IF NOT EXISTS contacts(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  name TEXT NOT NULL,
  phone TEXT NOT NULL,
  relationship TEXT NOT NULL,
  is_primary INTEGER DEFAULT 0,
  created_at TEXT
);

CREATE TABLE IF NOT EXISTS events(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  incident_id TEXT UNIQUE,
  user_id INTEGER NOT NULL,
  device_id INTEGER,
  event_type TEXT NOT NULL,
  status TEXT NOT NULL,
  description TEXT,
  latitude REAL,
  longitude REAL,
  location_text TEXT,
  occurred_at TEXT NOT NULL,
  resolved_at TEXT
);

CREATE TABLE IF NOT EXISTS notification_log(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  event_id INTEGER,
  contact_id INTEGER,
  channel TEXT,
  status TEXT,
  message TEXT,
  created_at TEXT
);
"""


# Provides a small compatibility layer so existing endpoints can use
# the same ? placeholders and lastrowid logic with PostgreSQL.
class CompatCursor:
    def __init__(self, cursor):
        self.cursor = cursor
        self.lastrowid = None

    def execute(self, sql, params=()):
        sql = sql.replace("?", "%s")
        is_insert = sql.lstrip().upper().startswith("INSERT INTO")

        if is_insert and "RETURNING" not in sql.upper():
            sql = sql.rstrip().rstrip(";") + " RETURNING id"
            self.cursor.execute(sql, params)
            inserted = self.cursor.fetchone()
            if inserted is not None:
                self.lastrowid = inserted["id"]
        else:
            self.cursor.execute(sql, params)

        return self

    def fetchone(self):
        return self.cursor.fetchone()

    def fetchall(self):
        return self.cursor.fetchall()


class CompatConnection:
    def __init__(self, connection):
        self.connection = connection

    def execute(self, sql, params=()):
        cursor = CompatCursor(self.connection.cursor())
        return cursor.execute(sql, params)

    def commit(self):
        self.connection.commit()

    def close(self):
        self.connection.close()


def init_db():
    if USE_POSTGRES:
        con = psycopg.connect(DATABASE_URL, row_factory=dict_row)
        try:
            pg_schema = SCHEMA.replace(
                "INTEGER PRIMARY KEY AUTOINCREMENT",
                "BIGSERIAL PRIMARY KEY"
            )
            for statement in pg_schema.split(";"):
                if statement.strip():
                    con.execute(statement)
            con.commit()
        finally:
            con.close()
    else:
        con = sqlite3.connect(DB_PATH)
        try:
            con.executescript(SCHEMA)
            con.commit()
        finally:
            con.close()


def db():
    if "db" not in g:
        if USE_POSTGRES:
            connection = psycopg.connect(
                DATABASE_URL,
                row_factory=dict_row
            )
            g.db = CompatConnection(connection)
        else:
            g.db = sqlite3.connect(DB_PATH)
            g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(_exc):
    connection = g.pop("db", None)
    if connection is not None:
        connection.close()


def now_iso():
    return dt.datetime.now(dt.timezone.utc).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )


def parse_iso(value):
    if not value:
        return None
    try:
        return dt.datetime.strptime(
            value, "%Y-%m-%dT%H:%M:%SZ"
        ).replace(tzinfo=dt.timezone.utc)
    except (TypeError, ValueError):
        return None


def is_recent(value):
    timestamp = parse_iso(value)
    return bool(timestamp) and (
        dt.datetime.now(dt.timezone.utc) - timestamp
    ).total_seconds() <= ONLINE_SECONDS


def err(code, message, status=400):
    return jsonify({
        "error": {
            "code": code,
            "message": message
        }
    }), status


def hash_key(key):
    return hashlib.sha256(key.encode()).hexdigest()


def make_token(uid):
    expiry = dt.datetime.now(dt.timezone.utc) + dt.timedelta(days=7)
    return jwt.encode(
        {"sub": str(uid), "exp": expiry},
        JWT_SECRET,
        algorithm="HS256"
    )


def auth_required(fn):
    from functools import wraps

    @wraps(fn)
    def wrapper(*args, **kwargs):
        header = request.headers.get("Authorization", "")
        if not header.startswith("Bearer "):
            return err("unauthorized", "Please sign in.", 401)

        try:
            uid = int(jwt.decode(
                header[7:],
                JWT_SECRET,
                algorithms=["HS256"]
            )["sub"])
        except Exception:
            return err(
                "unauthorized",
                "Session expired. Please sign in again.",
                401
            )

        user = db().execute(
            "SELECT * FROM users WHERE id=?", (uid,)
        ).fetchone()

        if not user:
            return err("unauthorized", "Account not found.", 401)

        g.user = user
        return fn(*args, **kwargs)

    return wrapper


def device_required(fn):
    from functools import wraps

    @wraps(fn)
    def wrapper(*args, **kwargs):
        key = request.headers.get("X-Device-Key", "")
        device = (
            db().execute(
                "SELECT * FROM devices WHERE key_hash=?",
                (hash_key(key),)
            ).fetchone()
            if key else None
        )

        if not device:
            return err(
                "invalid_device_key",
                "Invalid or missing X-Device-Key.",
                401
            )

        g.device = device
        return fn(*args, **kwargs)

    return wrapper


def user_json(user):
    return {
        "id": user["id"],
        "full_name": user["full_name"],
        "email": user["email"],
        "phone": user["phone"] or "",
        "role": user["role"],
        "emergency_alerts_enabled": bool(user["emergency_alerts"]),
        "notifications_enabled": bool(user["notifications"])
    }


def contact_json(contact):
    return {
        "id": contact["id"],
        "name": contact["name"],
        "phone": contact["phone"],
        "relationship": contact["relationship"],
        "is_primary": bool(contact["is_primary"])
    }


def event_json(event):
    return {
        "incident_id": event["incident_id"],
        "event_type": event["event_type"],
        "status": event["status"],
        "description": event["description"] or "",
        "latitude": event["latitude"],
        "longitude": event["longitude"],
        "location_text": event["location_text"] or "Unknown",
        "occurred_at": event["occurred_at"],
        "resolved_at": event["resolved_at"]
    }


def device_json(device):
    connected = is_recent(device["last_seen_at"])
    return {
        "id": device["id"],
        "name": device["name"],
        "status": "Connected" if connected else "Disconnected",
        "last_seen_at": device["last_seen_at"]
    }


def body():
    return request.get_json(silent=True) or {}


# ---------------------------------------------------------------------
# Health
# ---------------------------------------------------------------------

@app.get("/health")
def health():
    return {"status": "ok"}


# ---------------------------------------------------------------------
# Authentication
# ---------------------------------------------------------------------

@app.post("/api/v1/auth/register")
def register():
    data = body()
    name = (data.get("full_name") or "").strip()
    email = (data.get("email") or "").strip().lower()
    phone = (data.get("phone") or "").strip()
    password = data.get("password") or ""

    if not name:
        return err("validation", "Name is required")

    if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email):
        return err("validation", "Please enter a valid email address")

    if phone and not re.fullmatch(r"\d{10}", phone):
        return err("validation", "Please enter a valid 10-digit phone number")

    if len(password) < 6:
        return err("validation", "Password must be at least 6 characters")

    connection = db()

    if connection.execute(
        "SELECT 1 FROM users WHERE email=?", (email,)
    ).fetchone():
        return err("email_taken", "This email is already registered.", 409)

    cursor = connection.execute(
        """INSERT INTO users
           (full_name, email, phone, password_hash, created_at)
           VALUES (?, ?, ?, ?, ?)""",
        (
            name,
            email,
            phone,
            generate_password_hash(password),
            now_iso()
        )
    )
    uid = cursor.lastrowid

    device_key = "dev_" + secrets.token_urlsafe(24)
    connection.execute(
        "INSERT INTO devices(user_id, key_hash) VALUES(?, ?)",
        (uid, hash_key(device_key))
    )
    connection.commit()

    user = connection.execute(
        "SELECT * FROM users WHERE id=?", (uid,)
    ).fetchone()

    return jsonify({
        "access_token": make_token(uid),
        "user": user_json(user),
        "device_key": device_key
    }), 201


@app.post("/api/v1/auth/login")
def login():
    data = body()
    email = (data.get("email") or "").strip().lower()

    user = db().execute(
        "SELECT * FROM users WHERE email=?", (email,)
    ).fetchone()

    if not user or not check_password_hash(
        user["password_hash"], data.get("password") or ""
    ):
        return err("invalid_credentials", "Invalid email or password", 401)

    return jsonify({
        "access_token": make_token(user["id"]),
        "user": user_json(user)
    })


@app.post("/api/v1/auth/forgot-password")
def forgot():
    return jsonify({
        "message": (
            "If this email is registered, password reset instructions "
            "will be sent to that email address."
        )
    })


@app.get("/api/v1/auth/me")
@auth_required
def me():
    return jsonify({"user": user_json(g.user)})


# ---------------------------------------------------------------------
# Profile and settings
# ---------------------------------------------------------------------

@app.put("/api/v1/profile")
@auth_required
def update_profile():
    data = body()
    name = (data.get("full_name") or g.user["full_name"]).strip()
    phone = (
        data.get("phone")
        if data.get("phone") is not None
        else g.user["phone"] or ""
    ).strip()

    if not name:
        return err("validation", "Name is required")

    if phone and not re.fullmatch(r"\d{10}", phone):
        return err("validation", "Please enter a valid 10-digit phone number")

    connection = db()
    connection.execute(
        "UPDATE users SET full_name=?, phone=? WHERE id=?",
        (name, phone, g.user["id"])
    )
    connection.commit()

    user = connection.execute(
        "SELECT * FROM users WHERE id=?", (g.user["id"],)
    ).fetchone()

    return jsonify({"user": user_json(user)})


@app.put("/api/v1/profile/settings")
@auth_required
def update_settings():
    data = body()
    alerts = int(bool(data.get(
        "emergency_alerts_enabled",
        bool(g.user["emergency_alerts"])
    )))
    notifications = int(bool(data.get(
        "notifications_enabled",
        bool(g.user["notifications"])
    )))

    connection = db()
    connection.execute(
        "UPDATE users SET emergency_alerts=?, notifications=? WHERE id=?",
        (alerts, notifications, g.user["id"])
    )
    connection.commit()

    user = connection.execute(
        "SELECT * FROM users WHERE id=?", (g.user["id"],)
    ).fetchone()

    return jsonify({"user": user_json(user)})


# ---------------------------------------------------------------------
# Emergency contacts
# ---------------------------------------------------------------------

def ensure_primary(uid):
    connection = db()

    if connection.execute(
        "SELECT 1 FROM contacts WHERE user_id=? AND is_primary=1",
        (uid,)
    ).fetchone():
        return

    first = connection.execute(
        "SELECT id FROM contacts WHERE user_id=? ORDER BY id LIMIT 1",
        (uid,)
    ).fetchone()

    if first:
        connection.execute(
            "UPDATE contacts SET is_primary=1 WHERE id=?",
            (first["id"],)
        )


def validate_contact(data):
    name = (data.get("name") or "").strip()
    phone = (data.get("phone") or "").strip()
    relationship = (data.get("relationship") or "").strip()

    if not name:
        return None, "Name is required"

    if not re.fullmatch(r"\d{10}", phone):
        return None, "Please enter a valid 10-digit phone number"

    if relationship not in RELATIONSHIPS:
        return None, "Please choose a relationship"

    return (name, phone, relationship), None


@app.get("/api/v1/contacts")
@auth_required
def list_contacts():
    rows = db().execute(
        """SELECT * FROM contacts
           WHERE user_id=?
           ORDER BY is_primary DESC, id ASC""",
        (g.user["id"],)
    ).fetchall()

    return jsonify({"items": [contact_json(row) for row in rows]})


@app.post("/api/v1/contacts")
@auth_required
def add_contact():
    data = body()
    values, error = validate_contact(data)

    if error:
        return err("validation", error)

    connection = db()
    uid = g.user["id"]

    has_any = connection.execute(
        "SELECT 1 FROM contacts WHERE user_id=?", (uid,)
    ).fetchone()

    make_primary = bool(data.get("is_primary")) or not has_any

    if make_primary:
        connection.execute(
            "UPDATE contacts SET is_primary=0 WHERE user_id=?",
            (uid,)
        )

    cursor = connection.execute(
        """INSERT INTO contacts
           (user_id, name, phone, relationship, is_primary, created_at)
           VALUES (?, ?, ?, ?, ?, ?)""",
        (uid, *values, int(make_primary), now_iso())
    )
    connection.commit()

    contact = connection.execute(
        "SELECT * FROM contacts WHERE id=?", (cursor.lastrowid,)
    ).fetchone()

    return jsonify({"contact": contact_json(contact)}), 201


def own_contact(contact_id):
    return db().execute(
        "SELECT * FROM contacts WHERE id=? AND user_id=?",
        (contact_id, g.user["id"])
    ).fetchone()


@app.put("/api/v1/contacts/<int:cid>")
@auth_required
def edit_contact(cid):
    if not own_contact(cid):
        return err("not_found", "Contact not found", 404)

    data = body()
    values, error = validate_contact(data)

    if error:
        return err("validation", error)

    connection = db()
    uid = g.user["id"]

    if data.get("is_primary"):
        connection.execute(
            "UPDATE contacts SET is_primary=0 WHERE user_id=?", (uid,)
        )
        connection.execute(
            "UPDATE contacts SET is_primary=1 WHERE id=?", (cid,)
        )

    connection.execute(
        "UPDATE contacts SET name=?, phone=?, relationship=? WHERE id=?",
        (*values, cid)
    )
    ensure_primary(uid)
    connection.commit()

    return jsonify({"contact": contact_json(own_contact(cid))})


@app.delete("/api/v1/contacts/<int:cid>")
@auth_required
def delete_contact(cid):
    if not own_contact(cid):
        return err("not_found", "Contact not found", 404)

    connection = db()
    connection.execute("DELETE FROM contacts WHERE id=?", (cid,))
    ensure_primary(g.user["id"])
    connection.commit()

    return jsonify({"deleted": True})


@app.post("/api/v1/contacts/<int:cid>/set-primary")
@auth_required
def set_primary(cid):
    if not own_contact(cid):
        return err("not_found", "Contact not found", 404)

    connection = db()
    connection.execute(
        "UPDATE contacts SET is_primary=0 WHERE user_id=?",
        (g.user["id"],)
    )
    connection.execute(
        "UPDATE contacts SET is_primary=1 WHERE id=?", (cid,)
    )
    connection.commit()

    return jsonify({"contact": contact_json(own_contact(cid))})


# ---------------------------------------------------------------------
# Events and notification logging
# ---------------------------------------------------------------------

def notify_contacts(connection, user, event_row):
    """Logs emergency notification text; does not send real SMS."""
    if not user["emergency_alerts"]:
        return 0

    contacts = connection.execute(
        """SELECT * FROM contacts
           WHERE user_id=?
           ORDER BY is_primary DESC, id""",
        (user["id"],)
    ).fetchall()

    link = (
        f"https://maps.google.com/?q="
        f"{event_row['latitude']},{event_row['longitude']}"
    )
    message = (
        f"EMERGENCY: {user['full_name']}'s vehicle reported a "
        f"{event_row['event_type']} ({event_row['incident_id']}). "
        f"Location: {link}"
    )

    for contact in contacts:
        connection.execute(
            """INSERT INTO notification_log
               (event_id, contact_id, channel, status, message, created_at)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (
                event_row["id"],
                contact["id"],
                "console",
                "logged",
                message,
                now_iso()
            )
        )
        print(
            f"[NOTIFY] -> {contact['name']} "
            f"({contact['phone']}): {message}",
            flush=True
        )

    return len(contacts)


def create_event(connection, user, device_id, event_type,
                 description, lat, lng, occurred_at=None):
    status = STATUS_BY_TYPE[event_type]
    location = (
        f"{lat:.5f}, {lng:.5f}"
        if lat is not None and lng is not None
        else "Unknown"
    )

    cursor = connection.execute(
        """INSERT INTO events
           (user_id, device_id, event_type, status, description,
            latitude, longitude, location_text, occurred_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            user["id"],
            device_id,
            event_type,
            status,
            description,
            lat,
            lng,
            location,
            occurred_at or now_iso()
        )
    )

    event_id = cursor.lastrowid
    incident_id = f"INC-{event_id:06d}"

    connection.execute(
        "UPDATE events SET incident_id=? WHERE id=?",
        (incident_id, event_id)
    )

    event = connection.execute(
        "SELECT * FROM events WHERE id=?", (event_id,)
    ).fetchone()

    if event_type in ALERT_TYPES:
        notify_contacts(connection, user, event)

    connection.commit()
    return event


@app.get("/api/v1/events/summary")
@auth_required
def events_summary():
    connection = db()
    uid = g.user["id"]

    total = connection.execute(
        "SELECT COUNT(*) c FROM events WHERE user_id=?", (uid,)
    ).fetchone()["c"]

    latest = connection.execute(
        """SELECT * FROM events WHERE user_id=?
           ORDER BY occurred_at DESC, id DESC LIMIT 1""",
        (uid,)
    ).fetchone()

    system_status = (
        latest["status"]
        if latest and latest["status"] in ("Danger", "Warning")
        else "Normal"
    )

    device = connection.execute(
        "SELECT * FROM devices WHERE user_id=? ORDER BY id LIMIT 1",
        (uid,)
    ).fetchone()

    return jsonify({
        "total": total,
        "latest_event": event_json(latest) if latest else None,
        "system_status": system_status,
        "device": device_json(device) if device else None
    })


@app.get("/api/v1/safety/insights")
@auth_required
def safety_insights():
    connection = db()
    uid = g.user["id"]

    latest = connection.execute(
        """SELECT * FROM events WHERE user_id=?
           ORDER BY occurred_at DESC, id DESC LIMIT 1""",
        (uid,)
    ).fetchone()

    cutoff = (
        dt.datetime.now(dt.timezone.utc) - dt.timedelta(hours=24)
    ).strftime("%Y-%m-%dT%H:%M:%SZ")

    recent = connection.execute(
        """SELECT COUNT(*) c FROM events
           WHERE user_id=? AND occurred_at>=?""",
        (uid, cutoff)
    ).fetchone()["c"]

    device = connection.execute(
        "SELECT * FROM devices WHERE user_id=? ORDER BY id LIMIT 1",
        (uid,)
    ).fetchone()

    score = 8 + min(recent * 7, 28)

    if latest:
        score += {
            "Danger": 55,
            "Warning": 25,
            "Normal": 0,
            "Resolved": 5
        }.get(latest["status"], 10)

    if not device or not is_recent(device["last_seen_at"]):
        score += 12

    score = min(score, 100)

    if score >= 75:
        priority = "CRITICAL"
        assessment = (
            "Immediate human review recommended. A recent danger event "
            "or unhealthy device signal increases response risk."
        )
    elif score >= 45:
        priority = "HIGH"
        assessment = (
            "Attention recommended. Recent safety activity indicates "
            "elevated operational risk."
        )
    elif score >= 25:
        priority = "MODERATE"
        assessment = (
            "System is mostly stable, but continued monitoring is recommended."
        )
    else:
        priority = "LOW"
        assessment = (
            "No significant risk signal is visible from the latest "
            "available telemetry."
        )

    actions = (
        "Open live map | Check latest event | Call emergency services "
        "if an accident is confirmed | Notify primary contact | "
        "Review event history"
    )

    return jsonify({
        "risk_score": score,
        "priority": priority,
        "assessment": assessment,
        "actions": actions,
        "latest_event": event_json(latest) if latest else None
    })


@app.get("/api/v1/events")
@auth_required
def list_events():
    limit = min(max(request.args.get("limit", 50, type=int), 1), 200)
    offset = max(request.args.get("offset", 0, type=int), 0)
    status = request.args.get("status")

    sql = "FROM events WHERE user_id=?"
    args = [g.user["id"]]

    if status:
        sql += " AND status=?"
        args.append(status)

    total = db().execute(
        "SELECT COUNT(*) c " + sql, args
    ).fetchone()["c"]

    rows = db().execute(
        "SELECT * " + sql +
        " ORDER BY occurred_at DESC, id DESC LIMIT ? OFFSET ?",
        args + [limit, offset]
    ).fetchall()

    return jsonify({
        "items": [event_json(row) for row in rows],
        "total": total
    })


def own_event(incident_id):
    return db().execute(
        "SELECT * FROM events WHERE incident_id=? AND user_id=?",
        (incident_id, g.user["id"])
    ).fetchone()


@app.get("/api/v1/events/<iid>")
@auth_required
def get_event(iid):
    event = own_event(iid)
    return (
        jsonify({"event": event_json(event)})
        if event
        else err("not_found", "Event not found", 404)
    )


@app.post("/api/v1/events/<iid>/resolve")
@auth_required
def resolve_event(iid):
    event = own_event(iid)

    if not event:
        return err("not_found", "Event not found", 404)

    connection = db()
    connection.execute(
        "UPDATE events SET status='Resolved', resolved_at=? WHERE id=?",
        (now_iso(), event["id"])
    )
    connection.commit()

    return jsonify({"event": event_json(own_event(iid))})


# ---------------------------------------------------------------------
# Location
# ---------------------------------------------------------------------

@app.get("/api/v1/location/latest")
@auth_required
def latest_location():
    device = db().execute(
        "SELECT * FROM devices WHERE user_id=? ORDER BY id LIMIT 1",
        (g.user["id"],)
    ).fetchone()

    if not device or device["last_lat"] is None:
        return jsonify({
            "lat": None,
            "lng": None,
            "status": "No data",
            "last_updated": None
        })

    return jsonify({
        "lat": device["last_lat"],
        "lng": device["last_lng"],
        "status": (
            "Live" if is_recent(device["last_location_at"])
            else "Last known"
        ),
        "last_updated": device["last_location_at"]
    })


# ---------------------------------------------------------------------
# Devices
# ---------------------------------------------------------------------

@app.get("/api/v1/devices")
@auth_required
def list_devices():
    devices = db().execute(
        "SELECT * FROM devices WHERE user_id=?",
        (g.user["id"],)
    ).fetchall()

    return jsonify({"items": [device_json(device) for device in devices]})


@app.post("/api/v1/devices/rotate-key")
@auth_required
def rotate_key():
    connection = db()
    device = connection.execute(
        "SELECT * FROM devices WHERE user_id=? ORDER BY id LIMIT 1",
        (g.user["id"],)
    ).fetchone()

    key = "dev_" + secrets.token_urlsafe(24)

    if device:
        connection.execute(
            "UPDATE devices SET key_hash=? WHERE id=?",
            (hash_key(key), device["id"])
        )
    else:
        connection.execute(
            "INSERT INTO devices(user_id, key_hash) VALUES(?, ?)",
            (g.user["id"], hash_key(key))
        )

    connection.commit()
    return jsonify({"device_key": key})


@app.post("/api/v1/device/location")
@device_required
def device_location():
    data = body()

    try:
        lat = float(data["lat"])
        lng = float(data["lng"])
    except (KeyError, TypeError, ValueError):
        return err("validation", "lat and lng are required numbers")

    timestamp = now_iso()
    connection = db()

    connection.execute(
        """UPDATE devices
           SET last_lat=?, last_lng=?, last_location_at=?, last_seen_at=?
           WHERE id=?""",
        (lat, lng, timestamp, timestamp, g.device["id"])
    )
    connection.commit()

    return jsonify({"ok": True})


@app.post("/api/v1/device/events")
@device_required
def device_event():
    data = body()
    event_type = data.get("event_type")

    if event_type not in STATUS_BY_TYPE:
        return err(
            "validation",
            "event_type must be one of: " + ", ".join(STATUS_BY_TYPE)
        )

    lat, lng = data.get("lat"), data.get("lng")

    try:
        lat = float(lat) if lat is not None else None
        lng = float(lng) if lng is not None else None
    except (TypeError, ValueError):
        return err("validation", "lat/lng must be numbers")

    connection = db()
    user = connection.execute(
        "SELECT * FROM users WHERE id=?",
        (g.device["user_id"],)
    ).fetchone()

    timestamp = now_iso()

    if lat is not None and lng is not None:
        connection.execute(
            """UPDATE devices
               SET last_lat=?, last_lng=?, last_location_at=?
               WHERE id=?""",
            (lat, lng, timestamp, g.device["id"])
        )

    connection.execute(
        "UPDATE devices SET last_seen_at=? WHERE id=?",
        (timestamp, g.device["id"])
    )

    event = create_event(
        connection,
        user,
        g.device["id"],
        event_type,
        data.get("description") or "",
        lat,
        lng
    )

    return jsonify({"event": event_json(event)}), 201


@app.post("/api/v1/demo/simulate")
@auth_required
def demo_simulate():
    """Simulate an ESP32 event for demonstrations without hardware."""
    event_type = body().get("event_type", "Confirmed Accident")

    if event_type not in STATUS_BY_TYPE:
        return err("validation", "Unknown event_type")

    connection = db()
    device = connection.execute(
        "SELECT * FROM devices WHERE user_id=? ORDER BY id LIMIT 1",
        (g.user["id"],)
    ).fetchone()

    if not device:
        return err(
            "device_not_found",
            "No safety device is registered for this account.",
            404
        )

    lat = DEMO_LAT + random.uniform(-0.01, 0.01)
    lng = DEMO_LNG + random.uniform(-0.01, 0.01)
    timestamp = now_iso()

    connection.execute(
        """UPDATE devices
           SET last_lat=?, last_lng=?, last_location_at=?, last_seen_at=?
           WHERE id=?""",
        (lat, lng, timestamp, timestamp, device["id"])
    )

    descriptions = {
        "Confirmed Accident":
            "Crash detected by accelerometer. Impact above threshold.",
        "Possible Accident":
            "Sudden deceleration detected. Awaiting confirmation.",
        "Obstacle Detected":
            "Obstacle detected ahead by ultrasonic sensor.",
        "System Warning":
            "Sensor reading out of range.",
        "System Check":
            "Routine system check passed.",
        "Confirmed Emergency":
            "Driver triggered emergency."
    }

    event = create_event(
        connection,
        g.user,
        device["id"],
        event_type,
        descriptions[event_type],
        lat,
        lng
    )

    return jsonify({"event": event_json(event)}), 201


# Initialize tables when the application starts.
init_db()


if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=int(os.environ.get("PORT", 5000)),
        debug=False
    )
