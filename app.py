"""
MedVault - diagnostic lab report portal (CYC386 Secure Software lab sprint)

Hardened version. Fixes: T-01 buffer overflow (native/parser.c), T-02 command
injection, T-03 IDOR, T-04 CSRF, T-05 clickjacking, T-06 hard-coded secret,
T-07 debug mode, T-08 audit logging.
"""
import ctypes
import hmac
import logging
import os
import re
import secrets
import sqlite3
import subprocess
import uuid

from flask import (Flask, abort, flash, g, redirect, render_template, request,
                   send_from_directory, session, url_for)
from werkzeug.security import check_password_hash, generate_password_hash

BASE = os.path.dirname(os.path.abspath(__file__))
UPLOADS = os.path.join(BASE, "uploads")
ARCHIVES = os.path.join(BASE, "archives")
DB_PATH = os.environ.get("MEDVAULT_DB", os.path.join(BASE, "medvault.db"))

app = Flask(__name__)
# T-06 FIX: secret comes from the environment, random fallback (never in source code)
app.config["SECRET_KEY"] = os.environ.get("MEDVAULT_SECRET_KEY") or secrets.token_hex(32)
# T-04 FIX (defence in depth): cookie never sent on cross-site requests
app.config["SESSION_COOKIE_SAMESITE"] = "Strict"
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SECURE"] = os.environ.get("MEDVAULT_SECURE_COOKIES", "0") == "1"
app.config["MAX_CONTENT_LENGTH"] = 1024 * 1024   # PN-06: 1 MB upload limit

ARCHIVE_NAME_RE = re.compile(r"^[A-Za-z0-9_-]{1,40}$")   # T-02 FIX: allow-list

# T-08 FIX: audit log of security-relevant actions
logging.basicConfig(level=logging.INFO, format="%(asctime)s AUDIT %(message)s")
audit = logging.getLogger("medvault.audit")


# ---------------------------------------------------------------- native parser
_lib = ctypes.CDLL(os.path.join(BASE, "native", "libparser.so"))
_lib.parse_header.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_size_t]
_lib.parse_header.restype = ctypes.c_int


def parse_header(line):
    """Returns (status, patient_name). status: 1 verified, 0 not verified, <0 invalid."""
    out = ctypes.create_string_buffer(64)
    status = _lib.parse_header(line.encode("utf-8", "replace"), out, 64)
    return status, out.value.decode("utf-8", "replace")


# ---------------------------------------------------------------- database
def db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(_exc):
    conn = g.pop("db", None)
    if conn is not None:
        conn.close()


def init_db():
    os.makedirs(UPLOADS, exist_ok=True)
    os.makedirs(ARCHIVES, exist_ok=True)
    fresh = not os.path.exists(DB_PATH)
    conn = sqlite3.connect(DB_PATH)
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY, username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL, role TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS reports (
            id INTEGER PRIMARY KEY, owner_id INTEGER NOT NULL,
            patient_name TEXT, verified INTEGER NOT NULL,
            stored_name TEXT NOT NULL, original_name TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS shares (
            report_id INTEGER NOT NULL, doctor_id INTEGER NOT NULL,
            UNIQUE(report_id, doctor_id));
    """)
    if fresh:
        users = [("alice", "alice123", "patient"), ("bob", "bob123", "patient"),
                 ("drkhan", "doctor123", "doctor"), ("drevil", "evil123", "doctor")]
        for name, pw, role in users:
            conn.execute("INSERT INTO users (username, password_hash, role) VALUES (?,?,?)",
                         (name, generate_password_hash(pw), role))
        for owner_id, sample in [(1, "alice_cbc.lab"), (2, "bob_lipid.lab")]:
            with open(os.path.join(BASE, "samples", sample), encoding="utf-8") as f:
                text = f.read()
            status, name = parse_header(text.splitlines()[0])
            stored = uuid.uuid4().hex + ".lab"
            with open(os.path.join(UPLOADS, stored), "w", encoding="utf-8") as f:
                f.write(text)
            conn.execute("INSERT INTO reports (owner_id, patient_name, verified, stored_name, original_name)"
                         " VALUES (?,?,?,?,?)", (owner_id, name, int(status == 1), stored, sample))
    conn.commit()
    conn.close()


# ---------------------------------------------------------------- auth helpers
def current_user():
    uid = session.get("user_id")
    if uid is None:
        return None
    return db().execute("SELECT * FROM users WHERE id = ?", (uid,)).fetchone()


def login_required(view):
    def wrapper(*args, **kwargs):
        if current_user() is None:
            return redirect(url_for("login"))
        return view(*args, **kwargs)
    wrapper.__name__ = view.__name__
    return wrapper


def get_report_for_user(report_id, owner_only=False):
    """T-03 FIX: central object-level authorization.
    Patients may access only their own reports; doctors only reports shared with them.
    Anything else returns 404 so attackers cannot even tell the report exists."""
    user = current_user()
    report = db().execute("SELECT * FROM reports WHERE id = ?", (report_id,)).fetchone()
    if report is None or user is None:
        abort(404)
    if report["owner_id"] == user["id"]:
        return report
    if not owner_only and user["role"] == "doctor":
        shared = db().execute("SELECT 1 FROM shares WHERE report_id = ? AND doctor_id = ?",
                              (report_id, user["id"])).fetchone()
        if shared:
            return report
    audit.info("DENIED user=%s report=%s", user["username"], report_id)
    abort(404)


# ---------------------------------------------------------------- CSRF protection
def csrf_token():
    """T-04 FIX: one random synchronizer token per session."""
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_urlsafe(32)
    return session["csrf_token"]


@app.before_request
def check_csrf():
    if request.method == "POST":
        sent = request.form.get("csrf_token", "")
        expected = session.get("csrf_token", "")
        if not expected or not hmac.compare_digest(sent, expected):
            audit.info("CSRF REJECTED path=%s", request.path)
            abort(400, "Invalid or missing CSRF token")


# ---------------------------------------------------------------- security headers
@app.after_request
def security_headers(resp):
    resp.headers["X-Frame-Options"] = "DENY"                                   # T-05 FIX
    resp.headers["Content-Security-Policy"] = "frame-ancestors 'none'; default-src 'self'; style-src 'self' 'unsafe-inline'"
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["Referrer-Policy"] = "no-referrer"
    resp.headers["Cache-Control"] = "no-store"
    return resp


@app.context_processor
def inject_user():
    return {"user": current_user(), "csrf_token": csrf_token}


# ---------------------------------------------------------------- routes
@app.route("/")
def index():
    return redirect(url_for("dashboard"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        row = db().execute("SELECT * FROM users WHERE username = ?",
                           (request.form.get("username", ""),)).fetchone()
        if row and check_password_hash(row["password_hash"], request.form.get("password", "")):
            session.clear()
            session["user_id"] = row["id"]
            audit.info("LOGIN user=%s", row["username"])
            return redirect(url_for("dashboard"))
        audit.info("LOGIN FAILED user=%s", request.form.get("username", "")[:40])
        flash("Invalid username or password")
    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/dashboard")
@login_required
def dashboard():
    user = current_user()
    if user["role"] == "doctor":
        reports = db().execute(
            "SELECT r.* FROM reports r JOIN shares s ON s.report_id = r.id WHERE s.doctor_id = ?",
            (user["id"],)).fetchall()
    else:
        reports = db().execute("SELECT * FROM reports WHERE owner_id = ?", (user["id"],)).fetchall()
    return render_template("dashboard.html", reports=reports)


@app.route("/upload", methods=["POST"])
@login_required
def upload():
    f = request.files.get("report")
    if not f or not f.filename:
        flash("Choose a .lab file")
        return redirect(url_for("dashboard"))
    text = f.read().decode("utf-8", "replace")
    status, name = parse_header(text.splitlines()[0] if text else "")
    if status < 0:
        audit.info("UPLOAD REJECTED user=%s reason=bad-header", current_user()["username"])
        flash("Invalid report header: patient name must be 1-31 characters")
        return redirect(url_for("dashboard"))
    stored = uuid.uuid4().hex + ".lab"
    with open(os.path.join(UPLOADS, stored), "w", encoding="utf-8") as out:
        out.write(text)
    db().execute("INSERT INTO reports (owner_id, patient_name, verified, stored_name, original_name)"
                 " VALUES (?,?,?,?,?)", (current_user()["id"], name, int(status == 1), stored, f.filename))
    db().commit()
    audit.info("UPLOAD user=%s verified=%s", current_user()["username"], int(status == 1))
    flash("Report uploaded")
    return redirect(url_for("dashboard"))


@app.route("/report/<int:report_id>")
@login_required
def view_report(report_id):
    report = get_report_for_user(report_id)          # T-03 FIX
    with open(os.path.join(UPLOADS, report["stored_name"]), encoding="utf-8") as f:
        content = f.read()
    shared_with = db().execute(
        "SELECT u.username FROM shares s JOIN users u ON u.id = s.doctor_id WHERE s.report_id = ?",
        (report_id,)).fetchall()
    return render_template("report.html", report=report, content=content, shared_with=shared_with)


@app.route("/report/<int:report_id>/share", methods=["POST"])
@login_required
def share_report(report_id):
    get_report_for_user(report_id, owner_only=True)  # only the owner may share (token checked in check_csrf)
    doctor = db().execute("SELECT * FROM users WHERE username = ? AND role = 'doctor'",
                          (request.form.get("doctor", ""),)).fetchone()
    if doctor is None:
        flash("No such doctor")
    else:
        db().execute("INSERT OR IGNORE INTO shares (report_id, doctor_id) VALUES (?, ?)",
                     (report_id, doctor["id"]))
        db().commit()
        audit.info("SHARE user=%s report=%s doctor=%s", current_user()["username"], report_id, doctor["username"])
        flash("Report shared with " + doctor["username"])
    return redirect(url_for("view_report", report_id=report_id))


@app.route("/report/<int:report_id>/compress", methods=["POST"])
@login_required
def compress_report(report_id):
    report = get_report_for_user(report_id, owner_only=True)
    archive = request.form.get("archive_name", "report")
    # T-02 FIX: strict allow-list, then an argument list with NO shell
    if not ARCHIVE_NAME_RE.fullmatch(archive):
        audit.info("COMPRESS REJECTED user=%s name=%r", current_user()["username"], archive[:60])
        abort(400, "Archive name may contain only letters, digits, - and _")
    subprocess.run(  # nosec B603 - fixed argv, validated input, no shell
        ["tar", "-czf", os.path.join(ARCHIVES, archive + ".tar.gz"),
         "-C", UPLOADS, report["stored_name"]],
        shell=False, check=True, timeout=15)
    audit.info("COMPRESS user=%s report=%s", current_user()["username"], report_id)
    flash(f"Archive created: {archive}.tar.gz")
    return redirect(url_for("view_report", report_id=report_id))


@app.route("/archives/<path:filename>")
@login_required
def download_archive(filename):
    return send_from_directory(ARCHIVES, filename, as_attachment=True)


init_db()

if __name__ == "__main__":
    # T-07 FIX: debug never on; production runs under gunicorn (see Dockerfile)
    app.run(host="127.0.0.1", port=5000, debug=False)
