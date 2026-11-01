"""
MedVault - diagnostic lab report portal (CYC386 Secure Software lab sprint)

WARNING: this is the deliberately VULNERABLE baseline (tag v0-vulnerable).
Run it only on your own machine for the lab demonstration.
Known issues: T-01 buffer overflow (native/parser.c), T-02 command injection,
T-03 IDOR, T-04 CSRF, T-05 clickjacking, T-06 hard-coded secret, T-07 debug mode.
"""
import ctypes
import os
import sqlite3
import subprocess
import uuid

from flask import (Flask, abort, flash, g, redirect, render_template, request,
                   send_from_directory, session, url_for)
from werkzeug.security import check_password_hash, generate_password_hash

BASE = os.path.dirname(os.path.abspath(__file__))
UPLOADS = os.path.join(BASE, "uploads")
ARCHIVES = os.path.join(BASE, "archives")
DB_PATH = os.path.join(BASE, "medvault.db")

app = Flask(__name__)
app.config["SECRET_KEY"] = "medvault-dev-secret-123"   # T-06: hard-coded secret


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


@app.context_processor
def inject_user():
    return {"user": current_user()}


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
            return redirect(url_for("dashboard"))
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
        flash("Invalid report header")
        return redirect(url_for("dashboard"))
    stored = uuid.uuid4().hex + ".lab"
    with open(os.path.join(UPLOADS, stored), "w", encoding="utf-8") as out:
        out.write(text)
    db().execute("INSERT INTO reports (owner_id, patient_name, verified, stored_name, original_name)"
                 " VALUES (?,?,?,?,?)", (current_user()["id"], name, int(status == 1), stored, f.filename))
    db().commit()
    flash("Report uploaded")
    return redirect(url_for("dashboard"))


@app.route("/report/<int:report_id>")
@login_required
def view_report(report_id):
    # T-03 IDOR: loads ANY report by id, never checks who owns it
    report = db().execute("SELECT * FROM reports WHERE id = ?", (report_id,)).fetchone()
    if report is None:
        abort(404)
    with open(os.path.join(UPLOADS, report["stored_name"]), encoding="utf-8") as f:
        content = f.read()
    shared_with = db().execute(
        "SELECT u.username FROM shares s JOIN users u ON u.id = s.doctor_id WHERE s.report_id = ?",
        (report_id,)).fetchall()
    return render_template("report.html", report=report, content=content, shared_with=shared_with)


@app.route("/report/<int:report_id>/share", methods=["POST"])
@login_required
def share_report(report_id):
    # T-04 CSRF: no anti-CSRF token is checked
    doctor = db().execute("SELECT * FROM users WHERE username = ? AND role = 'doctor'",
                          (request.form.get("doctor", ""),)).fetchone()
    if doctor is None:
        flash("No such doctor")
    else:
        db().execute("INSERT OR IGNORE INTO shares (report_id, doctor_id) VALUES (?, ?)",
                     (report_id, doctor["id"]))
        db().commit()
        flash("Report shared with " + doctor["username"])
    return redirect(url_for("view_report", report_id=report_id))


@app.route("/report/<int:report_id>/compress", methods=["POST"])
@login_required
def compress_report(report_id):
    report = db().execute("SELECT * FROM reports WHERE id = ?", (report_id,)).fetchone()
    if report is None:
        abort(404)
    archive = request.form.get("archive_name", "report")
    # T-02 COMMAND INJECTION: user input is pasted into a shell command
    cmd = f"tar -czf archives/{archive}.tar.gz -C uploads {report['stored_name']}"
    subprocess.run(cmd, shell=True, cwd=BASE)
    flash(f"Archive created: {archive}.tar.gz")
    return redirect(url_for("view_report", report_id=report_id))


@app.route("/archives/<path:filename>")
@login_required
def download_archive(filename):
    return send_from_directory(ARCHIVES, filename, as_attachment=True)


init_db()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)   # T-07: debug mode on
