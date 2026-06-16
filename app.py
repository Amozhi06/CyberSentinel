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

DB_PATH = "cybersentinel.db"
if not os.path.exists(DB_PATH):
    open(DB_PATH, "w").close()

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

@app.route("/api/me")
def me():
    user = current_user()
    if not user:
        return jsonify({"logged_in": False})
    return jsonify({
        "logged_in": True,
        "username": user["username"]
    })

# ══════════════════════════════════════════
#  MODULE 1 — PHISHING DETECTOR
# ══════════════════════════════════════════
@app.route("/api/phishing", methods=["POST"])
def phishing():
    d   = request.json or {}
    url = d.get("url", "").strip()
    if not url:
        return jsonify({"error": "Please enter a URL."}), 400
 
    risk    = 0
    reasons = []
 
    if len(url) > 75:
        risk += 20; reasons.append("Unusually long URL")
    if "@" in url:
        risk += 30; reasons.append("Contains @ symbol")
    if re.match(r"https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", url):
        risk += 40; reasons.append("IP address used instead of domain name")
    if not url.startswith("https://"):
        risk += 20; reasons.append("No HTTPS — connection not encrypted")
 
    try:
        domain = url.split("/")[2]
        if "-" in domain:
            risk += 10; reasons.append("Dash in domain name")
        if domain.count(".") > 3:
            risk += 20; reasons.append("Excessive subdomains")
    except IndexError:
        pass
 
    for kw in ["login","verify","update","secure","account","banking","confirm","password","free","winner","lucky"]:
        if kw in url.lower():
            risk += 10; reasons.append(f"Suspicious keyword: '{kw}'")
 
    live_status   = "unknown"
    status_code   = None
    response_time = None
    final_url     = url
    redirected    = False
 
    try:
        t0            = time.time()
        resp          = req.get(url, timeout=6, allow_redirects=True, headers={"User-Agent": "Mozilla/5.0"})
        response_time = round((time.time() - t0) * 1000)
        status_code   = resp.status_code
        final_url     = resp.url
        redirected    = final_url.rstrip("/") != url.rstrip("/")
        live_status   = "reachable" if status_code < 400 else "error"
    except req.exceptions.ConnectionError:
        live_status = "unreachable"
    except req.exceptions.Timeout:
        live_status = "timeout"
    except Exception:
        live_status = "error"
 
    risk    = min(risk, 100)
    verdict = "SAFE" if risk < 20 else "SUSPICIOUS" if risk < 50 else "PHISHING"
    color   = "green" if verdict == "SAFE" else "yellow" if verdict == "SUSPICIOUS" else "red"
 
    u = current_user()
    if u:
        save_history(u["id"], "phishing", url, verdict)
 
    return jsonify({
        "url": url, "risk_score": risk, "verdict": verdict, "color": color,
        "reasons": reasons, "live_status": live_status,
        "status_code": status_code, "response_time": response_time,
        "redirected": redirected, "final_url": final_url
    })
 
 
# ══════════════════════════════════════════
#  MODULE 2 — PASSWORD ANALYZER
# ══════════════════════════════════════════
COMMON_PASSWORDS = {
    "password","123456","12345678","admin","qwerty","letmein","welcome",
    "monkey","dragon","master","iloveyou","sunshine","princess","football",
    "shadow","superman","michael","password1","abc123","111111","123123",
    "pass","pass123","root","toor","test","guest","user"
}
 
def gen_password():
    chars = string.ascii_letters + string.digits + "!@#$%^&*"
    while True:
        p = ''.join(secrets.choice(chars) for _ in range(14))
        if (any(c.isupper() for c in p) and any(c.islower() for c in p)
                and any(c.isdigit() for c in p)
                and any(c in "!@#$%^&*" for c in p)):
            return p
 
@app.route("/api/password", methods=["POST"])
def analyze_password():
    d    = request.json or {}
    name = d.get("name", "").strip()
    dob  = d.get("dob",  "").strip()
    pwd  = d.get("password", "")
    if not pwd:
        return jsonify({"error": "Please enter a password."}), 400
 
    score       = 0
    suggestions = []
    warnings    = []
    special     = "!@#$%^&*()_+-=[]{}|;:,.<>?"
 
    if len(pwd) >= 12:   score += 2
    elif len(pwd) >= 8:  score += 1
    else: suggestions.append("Use at least 8 characters (12+ is ideal)")
 
    if any(c.isupper() for c in pwd): score += 1
    else: suggestions.append("Add at least one uppercase letter")
    if any(c.islower() for c in pwd): score += 1
    else: suggestions.append("Add at least one lowercase letter")
    if any(c.isdigit() for c in pwd): score += 1
    else: suggestions.append("Add at least one number")
    if any(c in special for c in pwd): score += 1
    else: suggestions.append("Add at least one special character (!@#$%^&*)")
 
    if name and name.lower() in pwd.lower():
        warnings.append("Password contains your name"); score = max(0, score-1)
    if dob and dob in pwd:
        warnings.append("Password contains your date of birth"); score = max(0, score-1)
    if pwd.lower() in COMMON_PASSWORDS:
        warnings.append("This is one of the most commonly used passwords"); score = max(0, score-2)
    if re.search(r'(.)\1{2,}', pwd):
        warnings.append("Repeated characters detected (e.g. 'aaa')"); score = max(0, score-1)
 
    score    = max(0, min(score, 6))
    strength = "WEAK" if score <= 2 else "MEDIUM" if score <= 4 else "STRONG"
    hashed   = hashlib.sha256(pwd.encode()).hexdigest()
 
    u = current_user()
    if u:
        save_history(u["id"], "password", "***hidden***", strength)
 
    return jsonify({
        "length": len(pwd), "score": score, "max_score": 6,
        "strength": strength, "suggestions": suggestions,
        "warnings": warnings, "sha256": hashed,
        "suggested_passwords": [gen_password() for _ in range(3)]
    })
 
 
# ══════════════════════════════════════════
#  MODULE 3 — VULNERABILITY SCANNER
# ══════════════════════════════════════════
PORTS = {
    21:   {"name":"FTP",      "risk":"high",   "advice":"Sends data in plaintext. Use SFTP or FTPS instead."},
    22:   {"name":"SSH",      "risk":"low",    "advice":"Generally safe. Disable password login; use SSH keys."},
    23:   {"name":"Telnet",   "risk":"high",   "advice":"Completely unencrypted. Replace with SSH immediately."},
    25:   {"name":"SMTP",     "risk":"medium", "advice":"Restrict relay to prevent spam/abuse."},
    80:   {"name":"HTTP",     "risk":"medium", "advice":"Unencrypted. Redirect all traffic to HTTPS (443)."},
    443:  {"name":"HTTPS",    "risk":"low",    "advice":"Correct. Ensure TLS 1.2+ and valid certificate."},
    3306: {"name":"MySQL",    "risk":"high",   "advice":"Database exposed publicly — restrict to localhost only."},
    3389: {"name":"RDP",      "risk":"high",   "advice":"Top ransomware attack vector. Disable if not needed."},
    8080: {"name":"HTTP-Alt", "risk":"medium", "advice":"Common dev port. Never expose in production."},
}
 
@app.route("/api/scan", methods=["POST"])
def scan():
    d      = request.json or {}
    target = d.get("target", "").strip()
    if not target:
        return jsonify({"error": "Please enter an IP or hostname."}), 400
    if not re.match(r"^(\d{1,3}\.){3}\d{1,3}$|^[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$", target):
        return jsonify({"error": "Invalid IP address or hostname format."}), 400
 
    open_ports   = []
    closed_ports = []
 
    for port, info in PORTS.items():
        sock  = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        entry = {"port": port, **info}
        if sock.connect_ex((target, port)) == 0:
            open_ports.append(entry)
        else:
            closed_ports.append(entry)
        sock.close()
 
    high_risk    = [p for p in open_ports if p["risk"] == "high"]
    overall_risk = "HIGH" if high_risk else ("MEDIUM" if open_ports else "LOW")
 
    u = current_user()
    if u:
        save_history(u["id"], "scan", target, overall_risk)
 
    return jsonify({
        "target": target, "open_ports": open_ports,
        "closed_ports": closed_ports,
        "overall_risk": overall_risk, "total_open": len(open_ports)
    })
 
 
# ══════════════════════════════════════════
#  MODULE 4 — FILE ENCRYPTION / DECRYPTION
# ══════════════════════════════════════════
@app.route("/api/encrypt", methods=["POST"])
def encrypt():
    if "file" not in request.files or request.files["file"].filename == "":
        return jsonify({"error": "No file uploaded."}), 400
    f    = request.files["file"]
    data = f.read()
    key  = Fernet.generate_key()
    enc  = Fernet(key).encrypt(data)
 
    u = current_user()
    if u:
        save_history(u["id"], "encrypt", f.filename, "ENCRYPTED")
 
    return jsonify({
        "original_filename":  f.filename,
        "encrypted_filename": "encrypted_" + f.filename,
        "encrypted_data":     base64.b64encode(enc).decode(),
        "key":                base64.b64encode(key).decode(),
        "original_size":      len(data),
        "encrypted_size":     len(enc)
    })
 
@app.route("/api/decrypt", methods=["POST"])
def decrypt():
    if "file" not in request.files:
        return jsonify({"error": "No file uploaded."}), 400
    key_b64 = request.form.get("key", "").strip()
    if not key_b64:
        return jsonify({"error": "Encryption key is required."}), 400
    try:
        key   = base64.b64decode(key_b64)
        plain = Fernet(key).decrypt(request.files["file"].read())
        return jsonify({"decrypted_data": base64.b64encode(plain).decode(), "size": len(plain)})
    except Exception:
        return jsonify({"error": "Decryption failed — wrong key or corrupted file."}), 400
 
 
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
    print("🔥 CyberSentinel running locally")

    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)