"""
CyberSentinel - Clean Flask Backend (FIXED VERSION)
Run: python app.py
"""

from flask import Flask, render_template, request, jsonify, session, redirect, url_for
import hashlib, secrets, string, socket, re, os, sqlite3, base64, time
from datetime import datetime
import requests as req
from cryptography.fernet import Fernet
import google.generativeai as genai
from groq import Groq
from functools import wraps

# ─────────────────────────────
# APP CONFIG
# ─────────────────────────────
app = Flask(__name__)
app.secret_key = secrets.token_hex(32)

DB_PATH = os.path.join(os.path.dirname(__file__), "cybersentinel.db")

last_call = {}
COOLDOWN = 3

# ─────────────────────────────
# AI SETUP
# ─────────────────────────────
api_key = os.environ.get("GEMINI_API_KEY")
groq_key = os.environ.get("GROQ_API_KEY")

client = Groq(api_key=groq_key) if groq_key else None

model = None
if api_key:
    genai.configure(api_key=api_key)
    model = genai.GenerativeModel("gemini-1.5-flash")
    

# ─────────────────────────────
# DATABASE
# ─────────────────────────────
def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()

    cur.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        email TEXT UNIQUE,
        password TEXT,
        salt TEXT,
        created TEXT
    )
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS history (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        type TEXT,
        target TEXT,
        verdict TEXT,
        created TEXT
    )
    """)

    conn.commit()
    conn.close()

# ─────────────────────────────
# HELPERS
# ─────────────────────────────
def hash_password(password, salt=None):
    if not salt:
        salt = secrets.token_hex(16)
    h = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 260000)
    return hashlib.sha256(h).hexdigest(), salt

def current_user():
    uid = session.get("user_id")
    if not uid:
        return None
    with get_db() as conn:
        return conn.execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()

def save_history(uid, t, target, verdict):
    with get_db() as conn:
        conn.execute(
            "INSERT INTO history (user_id,type,target,verdict,created) VALUES (?,?,?,?,?)",
            (uid, t, target, verdict, datetime.utcnow().strftime("%Y-%m-%d %H:%M"))
        )
        conn.commit()

def login_required(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        if not current_user():
            return redirect(url_for("login_page"))
        return f(*args, **kwargs)
    return wrap

# ─────────────────────────────
# AI SAFE CALLS
# ─────────────────────────────
def safe_groq_call(message):
    try:
        return client.chat.completions.create(
            model="llama-3.1-8b-instant",
            messages=[{"role": "user", "content": message}]
        ).choices[0].message.content
    except:
        return None


def safe_gemini_call(message):
    try:
        return model.generate_content(message).text
    except Exception as e:
        if "429" in str(e) or "quota" in str(e).lower():
            return "GEMINI_QUOTA"
        return None
# ─────────────────────────────
# ROUTES
# ─────────────────────────────

@app.route("/")
def home():
    return render_template("index.html")

@app.route("/login")
def login_page():
    return render_template("login.html")

@app.route("/dashboard")
@login_required
def dashboard():
    u = current_user()
    return render_template("dashboard.html", username=u["username"])

# ───────── AUTH ─────────

@app.route("/api/register", methods=["POST"])
def register():
    d = request.json
    username = d.get("username","").lower().strip()
    email = d.get("email","").lower().strip()
    password = d.get("password","")

    if not username or not email or not password:
        return jsonify({"error":"missing fields"}),400

    hashed, salt = hash_password(password)

    try:
        with get_db() as conn:
            conn.execute(
                "INSERT INTO users(username,email,password,salt,created) VALUES (?,?,?,?,?)",
                (username,email,hashed,salt,datetime.utcnow().strftime("%Y-%m-%d %H:%M"))
            )
            conn.commit()
        return jsonify({"ok":True})
    except:
        return jsonify({"error":"user exists"}),400

@app.route("/api/login", methods=["POST"])
def login():
    d = request.json
    identifier = d.get("identifier","").lower().strip()
    password = d.get("password","")

    with get_db() as conn:
        user = conn.execute(
            "SELECT * FROM users WHERE username=? COLLATE NOCASE OR email=? COLLATE NOCASE",
            (identifier,identifier)
        ).fetchone()

    if not user:
        return jsonify({"error":"Account not found"}),401

    hashed,_ = hash_password(password,user["salt"])

    if hashed != user["password"]:
        return jsonify({"error":"Wrong password"}),401

    session["user_id"] = user["id"]
    return jsonify({"ok":True})

@app.route("/api/logout", methods=["POST"])
def logout():
    session.clear()
    return jsonify({"ok":True})

# ───────── CHAT ─────────

@app.route("/api/chat", methods=["POST"])
def chat():
    d = request.json or {}
    messages = d.get("messages", [])

    if not messages:
        return jsonify({"reply": "No message"}), 400

    msg = messages[-1]["content"]

    # 1️⃣ Try Groq
    reply = safe_groq_call(msg)
    if reply:
        return jsonify({"reply": reply})

    # 2️⃣ Try Gemini
    reply = safe_gemini_call(msg)

    if reply == "GEMINI_QUOTA":
        return jsonify({
            "reply": "⚡ Gemini limit hit. Switching brain..."
        })

    if reply:
        return jsonify({"reply": reply})

    # 3️⃣ Final fallback
    return jsonify({
        "reply": "AI is tired rn 😭 try again in a bit"
    })
# ───────── DEBUG ─────────

@app.route("/debug-users")
def debug_users():
    with get_db() as conn:
        rows = conn.execute("SELECT username,email FROM users").fetchall()
    return jsonify([dict(r) for r in rows])

# ───────── MAIN ─────────

if __name__ == "__main__":
    init_db()
    print("🔥 CyberSentinel running → http://127.0.0.1:5000")
    app.run(debug=True)