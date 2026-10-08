import os, tempfile
os.environ["DB_PATH"] = os.path.join(tempfile.mkdtemp(), "t.db")
import app as A
c = A.app.test_client()
J = lambda r: r.get_json()
def H(t): return {"Authorization": "Bearer " + t}

r = c.post("/api/v1/auth/register", json={"full_name": "Test User", "email": "T@x.com", "phone": "9876543210", "password": "secret1"})
assert r.status_code == 201, r.data
tok, key = J(r)["access_token"], J(r)["device_key"]
assert c.post("/api/v1/auth/register", json={"full_name": "A", "email": "t@x.com", "password": "secret1"}).status_code == 409
assert c.post("/api/v1/auth/register", json={"full_name": "A", "email": "b@x.com", "password": "123"}).status_code == 400
assert c.post("/api/v1/auth/login", json={"email": "t@x.com", "password": "bad"}).status_code == 401
r = c.post("/api/v1/auth/login", json={"email": "t@x.com", "password": "secret1"}); assert r.status_code == 200
assert c.get("/api/v1/auth/me").status_code == 401
assert J(c.get("/api/v1/auth/me", headers=H(tok)))["user"]["email"] == "t@x.com"

# contacts + primary rules
a = J(c.post("/api/v1/contacts", headers=H(tok), json={"name": "Mom", "phone": "9000000001", "relationship": "Mother"}))["contact"]
b = J(c.post("/api/v1/contacts", headers=H(tok), json={"name": "Raj", "phone": "9000000002", "relationship": "Friend"}))["contact"]
assert a["is_primary"] and not b["is_primary"]
assert c.post("/api/v1/contacts", headers=H(tok), json={"name": "X", "phone": "123", "relationship": "Friend"}).status_code == 400
c.post(f"/api/v1/contacts/{b['id']}/set-primary", headers=H(tok))
items = J(c.get("/api/v1/contacts", headers=H(tok)))["items"]
assert items[0]["name"] == "Raj" and sum(i["is_primary"] for i in items) == 1
c.delete(f"/api/v1/contacts/{b['id']}", headers=H(tok))
items = J(c.get("/api/v1/contacts", headers=H(tok)))["items"]
assert len(items) == 1 and items[0]["is_primary"]

# device flow
assert c.post("/api/v1/device/events", json={"event_type": "Confirmed Accident"}).status_code == 401
assert c.post("/api/v1/device/location", headers={"X-Device-Key": key}, json={"lat": 21.1, "lng": 79.0}).status_code == 200
loc = J(c.get("/api/v1/location/latest", headers=H(tok))); assert loc["status"] == "Live" and loc["lat"] == 21.1
r = c.post("/api/v1/device/events", headers={"X-Device-Key": key}, json={"event_type": "Confirmed Accident", "description": "boom", "lat": 21.1, "lng": 79.0})
assert r.status_code == 201; ev = J(r)["event"]; assert ev["status"] == "Danger" and ev["incident_id"].startswith("INC-")
s = J(c.get("/api/v1/events/summary", headers=H(tok)))
assert s["total"] == 1 and s["system_status"] == "Danger" and s["device"]["status"] == "Connected"
with A.app.app_context():
    n = A.sqlite3.connect(A.DB_PATH).execute("select count(*) from notification_log").fetchone()[0]
assert n == 1, n
assert c.post(f"/api/v1/events/{ev['incident_id']}/resolve", headers=H(tok)).status_code == 200
assert J(c.get("/api/v1/events/summary", headers=H(tok)))["system_status"] == "Normal"
# settings off -> no notification on next accident
c.put("/api/v1/profile/settings", headers=H(tok), json={"emergency_alerts_enabled": False, "notifications_enabled": True})
J(c.post("/api/v1/demo/simulate", headers=H(tok), json={"event_type": "Confirmed Accident"}))
with A.app.app_context():
    n2 = A.sqlite3.connect(A.DB_PATH).execute("select count(*) from notification_log").fetchone()[0]
assert n2 == 1
# profile + lists
assert J(c.put("/api/v1/profile", headers=H(tok), json={"full_name": "New Name", "phone": "9111111111"}))["user"]["full_name"] == "New Name"
assert J(c.get("/api/v1/events", headers=H(tok)))["total"] == 2
assert J(c.get("/api/v1/devices", headers=H(tok)))["items"][0]["name"] == "ESP32 Safety Unit"
print("ALL BACKEND TESTS PASSED")
