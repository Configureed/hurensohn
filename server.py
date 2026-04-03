import hashlib
import json
import os
import secrets
import threading
import time
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlparse

# ---- KeyAuth Configuration ----
KEYAUTH_OWNERID = "qMVbhDdhYm"
KEYAUTH_APPNAME = "Webseite"
KEYAUTH_VERSION = "1.0"
KEYAUTH_URL = "https://keyauth.win/api/1.2/"


def keyauth_init() -> str:
    params = urllib.parse.urlencode({
        "type": "init",
        "ver": KEYAUTH_VERSION,
        "name": KEYAUTH_APPNAME,
        "ownerid": KEYAUTH_OWNERID,
    }).encode("utf-8")
    req = urllib.request.Request(KEYAUTH_URL, data=params)
    with urllib.request.urlopen(req, timeout=8) as r:
        data = json.loads(r.read().decode("utf-8"))
    if not data.get("success"):
        raise RuntimeError(data.get("message", "KeyAuth init failed"))
    return data["sessionid"]


def keyauth_validate_license(key: str, hwid: str) -> dict:
    sessionid = keyauth_init()
    params = urllib.parse.urlencode({
        "type": "license",
        "key": key,
        "hwid": hwid,
        "sessionid": sessionid,
        "name": KEYAUTH_APPNAME,
        "ownerid": KEYAUTH_OWNERID,
    }).encode("utf-8")
    req = urllib.request.Request(KEYAUTH_URL, data=params)
    with urllib.request.urlopen(req, timeout=8) as r:
        data = json.loads(r.read().decode("utf-8"))
    return data


ROOT = Path(__file__).parent.resolve()
DATA_DIR = ROOT / "data"
DB_FILE = DATA_DIR / "database.json"

DB_LOCK = threading.Lock()

# Reload protection: if an IP loads the page more than 5 times in 60 seconds,
# the IP is blocked for 10 minutes.
RATE_LIMIT_WINDOW_SECONDS = 60
RATE_LIMIT_MAX_PAGE_LOADS = 5
RATE_LIMIT_BLOCK_SECONDS = 10 * 60
IP_RATE_LOCK = threading.Lock()
IP_RATE_STATE = {}


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def password_hash(raw: str) -> str:
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def load_json(path: Path, fallback: dict) -> dict:
    if not path.exists():
        return fallback
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def save_json(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=True)


def load_db() -> dict:
    db = load_json(DB_FILE, {"users": [], "sessions": [], "reset_requests": []})
    db.setdefault("users", [])
    db.setdefault("sessions", [])
    db.setdefault("reset_requests", [])
    return db


def save_db(db: dict) -> None:
    save_json(DB_FILE, db)


def find_user_by_username(db: dict, username: str):
    target = username.lower()
    for user in db["users"]:
        if user["username"].lower() == target:
            return user
    return None


def normalize_email(raw: str) -> str:
    return str(raw or "").strip().lower()


def is_valid_email(email: str) -> bool:
    return "@" in email and "." in email.split("@")[-1]


def find_user_by_email(db: dict, email: str):
    target = normalize_email(email)
    if not target:
        return None
    for user in db["users"]:
        if normalize_email(user.get("email", "")) == target:
            return user
    return None


def is_admin(user) -> bool:
    return bool(user and user.get("username", "").lower() == "viac")


def public_project_payload(p: dict, include_offline: bool = False):
    if p.get("offline") and not include_offline:
        return None
    return {
        "id": p["id"],
        "title": p["title"],
        "description": p.get("description", ""),
        "language": p["language"],
        "scriptType": p.get("script_type", "General"),
        "checkedStatus": p.get("checked_status", "Unchecked"),
        "createdAt": p.get("created_at", ""),
        "previewImage": p.get("image_data_url", ""),
        "offline": p.get("offline", False),
    }


def public_user_payload(user: dict, include_offline: bool = False) -> dict:
    scripts = []
    for p in user.get("projects", []):
        payload = public_project_payload(p, include_offline)
        if payload is not None:
            scripts.append(payload)
    return {
        "id": user["id"],
        "displayName": user.get("profile", {}).get("display_name") or user["username"],
        "bio": user.get("profile", {}).get("bio", ""),
        "avatarUrl": user.get("profile", {}).get("avatar_url", ""),
        "uploadedScripts": scripts,
    }


def issue_session(db: dict, user_id: str) -> str:
    token = secrets.token_hex(24)
    db["sessions"].append({"token": token, "user_id": user_id, "created_at": now_iso()})
    return token


def get_user_by_token(db: dict, token: str):
    if not token:
        return None
    session = next((s for s in db["sessions"] if s["token"] == token), None)
    if not session:
        return None
    return next((u for u in db["users"] if u["id"] == session["user_id"]), None)


def parse_token(handler: BaseHTTPRequestHandler) -> str:
    auth = handler.headers.get("Authorization", "")
    if auth.startswith("Bearer "):
        return auth[7:].strip()
    return ""


def read_json_body(handler: BaseHTTPRequestHandler):
    length = int(handler.headers.get("Content-Length", "0"))
    raw = handler.rfile.read(length) if length > 0 else b"{}"
    try:
        return json.loads(raw.decode("utf-8"))
    except Exception:
        return None


def get_client_ip(handler: BaseHTTPRequestHandler) -> str:
    forwarded = handler.headers.get("X-Forwarded-For", "").strip()
    if forwarded:
        return forwarded.split(",")[0].strip()
    if handler.client_address and handler.client_address[0]:
        return handler.client_address[0]
    return "unknown"


def check_page_load_rate_limit(ip: str):
    now_ts = int(time.time())
    with IP_RATE_LOCK:
        state = IP_RATE_STATE.get(ip, {"hits": [], "blocked_until": 0})
        blocked_until = int(state.get("blocked_until", 0))
        if blocked_until > now_ts:
            return False, blocked_until - now_ts

        hits = [t for t in state.get("hits", []) if now_ts - int(t) < RATE_LIMIT_WINDOW_SECONDS]
        hits.append(now_ts)

        if len(hits) > RATE_LIMIT_MAX_PAGE_LOADS:
            new_blocked_until = now_ts + RATE_LIMIT_BLOCK_SECONDS
            IP_RATE_STATE[ip] = {"hits": [], "blocked_until": new_blocked_until}
            return False, RATE_LIMIT_BLOCK_SECONDS

        IP_RATE_STATE[ip] = {"hits": hits, "blocked_until": 0}
        return True, 0


class AppHandler(BaseHTTPRequestHandler):
    server_version = "SkidpasterHTTP/1.0"

    def end_headers(self):
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        super().end_headers()

    def respond_json(self, status: int, payload: dict):
        data = json.dumps(payload, ensure_ascii=True).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_OPTIONS(self):
        self.send_response(204)
        self.end_headers()

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path

        if path in ["/", "/index.html"]:
            client_ip = get_client_ip(self)
            allowed, wait_seconds = check_page_load_rate_limit(client_ip)
            if not allowed:
                body = (
                    "Too many reloads. Your IP is blocked for {} seconds."
                    .format(wait_seconds)
                ).encode("utf-8")
                self.send_response(429)
                self.send_header("Content-Type", "text/plain; charset=utf-8")
                self.send_header("Retry-After", str(wait_seconds))
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return

        if path == "/api/health":
            self.respond_json(200, {"ok": True})
            return

        if path == "/api/owner":
            self.respond_json(200, {
                "name": "Owner",
                "headline": "Creator of skidpaster.xyz",
                "bio": "I build and share scripts/projects on skidpaster.xyz. This platform is focused on creator profiles, clean uploads, and direct project delivery.",
            })
            return

        if path == "/api/users/public":
            token = parse_token(self)
            with DB_LOCK:
                db = load_db()
                requester = get_user_by_token(db, token) if token else None
            admin = is_admin(requester)
            users_out = []
            for u in db["users"]:
                include_off = admin or bool(requester and requester["id"] == u["id"])
                payload = public_user_payload(u, include_offline=include_off)
                if payload["uploadedScripts"] or admin:
                    users_out.append(payload)
            self.respond_json(200, {"users": users_out})
            return

        if path == "/api/projects/all":
            token = parse_token(self)
            with DB_LOCK:
                db = load_db()
                requester = get_user_by_token(db, token) if token else None
            admin = is_admin(requester)
            projects_out = []
            for u in db["users"]:
                owner_name = u.get("profile", {}).get("display_name") or u["username"]
                owner_id = u["id"]
                for p in u.get("projects", []):
                    is_owner = requester and requester["id"] == owner_id
                    payload = public_project_payload(p, include_offline=admin or bool(is_owner))
                    if payload is not None:
                        payload["ownerName"] = owner_name
                        payload["ownerId"] = owner_id
                        projects_out.append(payload)
            projects_out.sort(key=lambda x: x.get("createdAt", ""), reverse=True)
            self.respond_json(200, {"projects": projects_out})
            return

        if path == "/api/projects/my":
            token = parse_token(self)
            with DB_LOCK:
                db = load_db()
                user = get_user_by_token(db, token)
            if not user:
                self.respond_json(401, {"ok": False, "error": "Unauthorized"})
                return
            projects = []
            for p in user.get("projects", []):
                projects.append({
                    "id": p["id"],
                    "title": p["title"],
                    "description": p.get("description", ""),
                    "language": p["language"],
                    "scriptType": p.get("script_type", "General"),
                    "checkedStatus": p.get("checked_status", "Unchecked"),
                    "createdAt": p.get("created_at", ""),
                    "previewImage": p.get("image_data_url", ""),
                    "offline": p.get("offline", False),
                })
            self.respond_json(200, {"projects": projects})
            return

        if path == "/api/auth/me":
            token = parse_token(self)
            with DB_LOCK:
                db = load_db()
                user = get_user_by_token(db, token)
            if not user:
                self.respond_json(401, {"ok": False, "error": "Unauthorized"})
                return
            self.respond_json(200, {
                "ok": True,
                "user": {
                    "id": user["id"],
                    "username": user["username"],
                    "email": user.get("email", ""),
                    "isAdmin": is_admin(user),
                    "profile": user.get("profile", {}),
                },
            })
            return

        if path.startswith("/api/projects/") and path.endswith("/download"):
            parts = path.strip("/").split("/")
            if len(parts) != 4:
                self.respond_json(404, {"ok": False, "error": "Invalid path"})
                return
            project_id = parts[2]
            dl_token = parse_token(self)
            with DB_LOCK:
                db = load_db()
                dl_requester = get_user_by_token(db, dl_token) if dl_token else None
            project = None
            project_owner_user = None
            for u in db["users"]:
                found = next((p for p in u.get("projects", []) if p["id"] == project_id), None)
                if found:
                    project = found
                    project_owner_user = u
                    break
            if not project:
                self.respond_json(404, {"ok": False, "error": "Project not found"})
                return
            if project.get("offline"):
                is_dl_owner = dl_requester and project_owner_user and dl_requester["id"] == project_owner_user["id"]
                if not is_admin(dl_requester) and not is_dl_owner:
                    self.respond_json(403, {"ok": False, "error": "Project is offline"})
                    return
            filename = "{}.txt".format("".join([c if c.isalnum() or c in "-_" else "_" for c in project["title"]])[:60] or "project")
            body = project.get("code", "").encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Content-Disposition", 'attachment; filename="{}"'.format(filename))
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return

        self.serve_static(path)

    def do_POST(self):
        parsed = urlparse(self.path)
        path = parsed.path
        payload = read_json_body(self)

        if payload is None:
            self.respond_json(400, {"ok": False, "error": "Invalid JSON body"})
            return

        if path == "/api/auth/register":
            username = str(payload.get("username", "")).strip()
            raw_password = str(payload.get("password", ""))
            email = normalize_email(payload.get("email", ""))
            license_key = str(payload.get("licenseKey", "")).strip()

            if not username or not raw_password or not license_key:
                self.respond_json(400, {"ok": False, "error": "Missing required fields"})
                return
            if email and not is_valid_email(email):
                self.respond_json(400, {"ok": False, "error": "Invalid email address"})
                return

            hwid = "WEB-" + password_hash(username)[:16]
            try:
                ka = keyauth_validate_license(license_key, hwid)
            except Exception:
                self.respond_json(502, {"ok": False, "error": "License validation service unavailable. Try again."})
                return
            if not ka.get("success"):
                self.respond_json(403, {"ok": False, "error": ka.get("message", "Invalid or expired license key")})
                return

            with DB_LOCK:
                db = load_db()
                if find_user_by_username(db, username):
                    self.respond_json(409, {"ok": False, "error": "Username already exists"})
                    return
                if email and find_user_by_email(db, email):
                    self.respond_json(409, {"ok": False, "error": "Email already in use"})
                    return

                user_id = "u-" + secrets.token_hex(8)
                user = {
                    "id": user_id,
                    "username": username,
                    "password_hash": password_hash(raw_password),
                    "email": email,
                    "license_key": license_key,
                    "created_at": now_iso(),
                    "profile": {"display_name": username, "bio": "", "avatar_url": ""},
                    "projects": [],
                }
                db["users"].append(user)
                token = issue_session(db, user_id)
                save_db(db)

            self.respond_json(200, {"ok": True, "token": token, "user": {"id": user_id, "username": username}})
            return

        if path == "/api/auth/login":
            username = str(payload.get("username", "")).strip()
            raw_password = str(payload.get("password", ""))
            if not username or not raw_password:
                self.respond_json(400, {"ok": False, "error": "Missing required fields"})
                return

            with DB_LOCK:
                db = load_db()
                user = find_user_by_username(db, username)
                if not user or user.get("password_hash") != password_hash(raw_password):
                    self.respond_json(401, {"ok": False, "error": "Invalid credentials"})
                    return
                token = issue_session(db, user["id"])
                save_db(db)

            self.respond_json(200, {"ok": True, "token": token, "user": {"id": user["id"], "username": user["username"]}})
            return

        if path == "/api/auth/logout":
            token = parse_token(self)
            if not token:
                self.respond_json(400, {"ok": False, "error": "Missing token"})
                return
            with DB_LOCK:
                db = load_db()
                db["sessions"] = [s for s in db["sessions"] if s["token"] != token]
                save_db(db)
            self.respond_json(200, {"ok": True})
            return

        if path == "/api/auth/connect-email":
            token = parse_token(self)
            email = normalize_email(payload.get("email", ""))
            if not email or not is_valid_email(email):
                self.respond_json(400, {"ok": False, "error": "Invalid email address"})
                return
            with DB_LOCK:
                db = load_db()
                user = get_user_by_token(db, token)
                if not user:
                    self.respond_json(401, {"ok": False, "error": "Unauthorized"})
                    return
                existing = find_user_by_email(db, email)
                if existing and existing["id"] != user["id"]:
                    self.respond_json(409, {"ok": False, "error": "Email already in use"})
                    return
                user["email"] = email
                save_db(db)
            self.respond_json(200, {"ok": True, "email": email})
            return

        if path == "/api/auth/forgot-password/request":
            email = normalize_email(payload.get("email", ""))
            if not email or not is_valid_email(email):
                self.respond_json(400, {"ok": False, "error": "Invalid email address"})
                return
            with DB_LOCK:
                db = load_db()
                user = find_user_by_email(db, email)
                if user:
                    reset_token = secrets.token_urlsafe(24)
                    expires_at = int(time.time()) + 20 * 60
                    db["reset_requests"].append({
                        "token": reset_token,
                        "user_id": user["id"],
                        "expires_at": expires_at,
                        "created_at": now_iso(),
                    })
                    save_db(db)
                    self.respond_json(
                        200,
                        {
                            "ok": True,
                            "message": "Reset request created. Use token to set a new password.",
                            "resetToken": reset_token,
                        },
                    )
                    return
            self.respond_json(200, {"ok": True, "message": "If this email exists, a reset was requested."})
            return

        if path == "/api/auth/forgot-password/confirm":
            reset_token = str(payload.get("token", "")).strip()
            new_password = str(payload.get("newPassword", ""))
            if not reset_token or not new_password:
                self.respond_json(400, {"ok": False, "error": "Missing token or password"})
                return
            with DB_LOCK:
                db = load_db()
                now_ts = int(time.time())
                req = next((r for r in db["reset_requests"] if r.get("token") == reset_token), None)
                if not req:
                    self.respond_json(404, {"ok": False, "error": "Invalid reset token"})
                    return
                if int(req.get("expires_at", 0)) < now_ts:
                    db["reset_requests"] = [r for r in db["reset_requests"] if r.get("token") != reset_token]
                    save_db(db)
                    self.respond_json(410, {"ok": False, "error": "Reset token expired"})
                    return
                user = next((u for u in db["users"] if u["id"] == req["user_id"]), None)
                if not user:
                    self.respond_json(404, {"ok": False, "error": "User not found"})
                    return
                user["password_hash"] = password_hash(new_password)
                db["reset_requests"] = [r for r in db["reset_requests"] if r.get("token") != reset_token]
                save_db(db)
            self.respond_json(200, {"ok": True, "message": "Password reset successful"})
            return

        if path == "/api/profile":
            token = parse_token(self)
            display_name = str(payload.get("displayName", "")).strip()
            bio = str(payload.get("bio", "")).strip()
            avatar_url = str(payload.get("avatarUrl", "")).strip()

            with DB_LOCK:
                db = load_db()
                user = get_user_by_token(db, token)
                if not user:
                    self.respond_json(401, {"ok": False, "error": "Unauthorized"})
                    return

                existing_bio = user.get("profile", {}).get("bio", "")
                if existing_bio:
                    self.respond_json(409, {"ok": False, "error": "Profile already created"})
                    return

                user["profile"] = {
                    "display_name": display_name or user["username"],
                    "bio": bio,
                    "avatar_url": avatar_url,
                }
                save_db(db)

            self.respond_json(200, {"ok": True})
            return

        if path == "/api/projects":
            token = parse_token(self)
            with DB_LOCK:
                db = load_db()
                user = get_user_by_token(db, token)
                if not user:
                    self.respond_json(401, {"ok": False, "error": "Unauthorized"})
                    return

                title = str(payload.get("title", "")).strip()
                description = str(payload.get("description", "")).strip()
                language = str(payload.get("language", "")).strip() or "Other"
                script_type = str(payload.get("scriptType", "")).strip() or "General"
                checked_status = str(payload.get("checkedStatus", "")).strip() or "Unchecked"
                code = str(payload.get("code", ""))
                image_data_url = str(payload.get("imageDataUrl", "")).strip()

                if not title or not code:
                    self.respond_json(400, {"ok": False, "error": "Title and code are required"})
                    return

                project = {
                    "id": "p-" + secrets.token_hex(8),
                    "title": title,
                    "description": description,
                    "language": language,
                    "script_type": script_type,
                    "checked_status": checked_status,
                    "code": code,
                    "image_data_url": image_data_url,
                    "created_at": now_iso(),
                    "offline": False,
                }
                user.setdefault("projects", []).append(project)
                save_db(db)

            self.respond_json(200, {"ok": True})
            return

        if path.startswith("/api/projects/") and path.endswith("/toggle-offline"):
            parts = path.strip("/").split("/")
            if len(parts) != 4:
                self.respond_json(404, {"ok": False, "error": "Invalid path"})
                return
            project_id = parts[2]
            tog_token = parse_token(self)
            with DB_LOCK:
                db = load_db()
                tog_requester = get_user_by_token(db, tog_token)
                if not tog_requester:
                    self.respond_json(401, {"ok": False, "error": "Unauthorized"})
                    return
                project = None
                proj_owner = None
                for u in db["users"]:
                    found = next((p for p in u.get("projects", []) if p["id"] == project_id), None)
                    if found:
                        project = found
                        proj_owner = u
                        break
                if not project:
                    self.respond_json(404, {"ok": False, "error": "Project not found"})
                    return
                is_proj_owner = proj_owner and tog_requester["id"] == proj_owner["id"]
                if not is_proj_owner and not is_admin(tog_requester):
                    self.respond_json(403, {"ok": False, "error": "Forbidden"})
                    return
                project["offline"] = not project.get("offline", False)
                save_db(db)
            self.respond_json(200, {"ok": True, "offline": project["offline"]})
            return

        self.respond_json(404, {"ok": False, "error": "Not found"})

    def serve_static(self, path: str):
        if path in ["", "/"]:
            target = ROOT / "index.html"
        else:
            clean = unquote(path).lstrip("/")
            target = ROOT / clean

        if target.is_dir():
            target = target / "index.html"

        if not target.exists() or not str(target.resolve()).startswith(str(ROOT)):
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b"Not Found")
            return

        mime = "text/plain; charset=utf-8"
        suffix = target.suffix.lower()
        if suffix == ".html":
            mime = "text/html; charset=utf-8"
        elif suffix == ".css":
            mime = "text/css; charset=utf-8"
        elif suffix == ".js":
            mime = "application/javascript; charset=utf-8"
        elif suffix == ".json":
            mime = "application/json; charset=utf-8"
        elif suffix in [".png", ".jpg", ".jpeg", ".gif", ".webp"]:
            mime = "image/" + suffix.lstrip(".")

        body = target.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", mime)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def main():
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    if not DB_FILE.exists():
        save_db({"users": [], "sessions": [], "reset_requests": []})

    port = int(os.environ.get("PORT", "8080"))
    host = "0.0.0.0"
    httpd = ThreadingHTTPServer((host, port), AppHandler)
    print("Running on http://{}:{}".format(host, port))
    httpd.serve_forever()


if __name__ == "__main__":
    main()
