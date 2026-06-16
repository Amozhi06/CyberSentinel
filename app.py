"""
CyberSentinel - Clean Flask Backend (FIXED VERSION)
Run: python app.py
"""
from flask import Flask, request, jsonify, session, render_template
import os, time, secrets, sqlite3, hashlib
from datetime import datetime
from functools import wraps
from collections import defaultdict
from flask import Response, stream_with_context
import json
import google.generativeai as genai
from groq import Groq

# ─────────────────────────────
# APP INIT
# ─────────────────────────────
app = Flask(__name__)
app.secret_key = secrets.token_hex(32)

DB_PATH = "cybersentinel.db"

# ─────────────────────────────
# RATE LIMIT + MEMORY
# ─────────────────────────────
user_last_call = defaultdict(float)
user_chat_memory = defaultdict(list)

COOLDOWN = 3  # per user cooldown (anti spam)
MAX_MEMORY = 10  # last 10 messages stored

# ─────────────────────────────
# AI SETUP
# ─────────────────────────────
groq_key = os.environ.get("GROQ_API_KEY")
gemini_key = os.environ.get("GEMINI_API_KEY")

client = Groq(api_key=groq_key) if groq_key else None

model = None
if gemini_key:
    genai.configure(api_key=gemini_key)
    model = genai.GenerativeModel("gemini-1.5-flash")


# ─────────────────────────────
# DB
# ─────────────────────────────
def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    with get_db() as conn:
        conn.execute("""
        CREATE TABLE IF NOT EXISTS users(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            email TEXT UNIQUE,
            password TEXT,
            salt TEXT,
            created TEXT
        )
        """)

        conn.execute("""
        CREATE TABLE IF NOT EXISTS chat_history(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id TEXT,
            role TEXT,
            message TEXT,
            created TEXT
        )
        """)


# ─────────────────────────────
# HELPERS
# ─────────────────────────────
def hash_password(pwd, salt=None):
    if not salt:
        salt = secrets.token_hex(16)
    h = hashlib.pbkdf2_hmac("sha256", pwd.encode(), salt.encode(), 260000)
    return hashlib.sha256(h).hexdigest(), salt


def current_user():
    return session.get("user_id")


def save_chat(uid, role, msg):
    with get_db() as conn:
        conn.execute(
            "INSERT INTO chat_history(user_id,role,message,created) VALUES (?,?,?,?)",
            (uid, role, msg, datetime.utcnow().isoformat())
        )


# ─────────────────────────────
# SAFE AI ROUTER 
# ─────────────────────────────
def call_groq(msg):
    try:
        if not client:
            return None

        return client.chat.completions.create(
            model="llama-3.1-8b-instant",
            messages=[{"role": "user", "content": msg}]
        ).choices[0].message.content

    except:
        return None


def call_gemini(msg):
    try:
        if not model:
            return None

        res = model.generate_content(msg)
        return res.text

    except Exception as e:
        if "429" in str(e) or "quota" in str(e).lower():
            return "QUOTA"
        return None


def ai_router(msg):
    reply = call_groq(msg)
    if reply:
        return reply

    reply = call_gemini(msg)

    if reply == "QUOTA":
        return "⚡ AI limit reached. Try again in a few seconds."

    if reply:
        return reply

    return "⚡ AI is currently unavailable."

# ─────────────────────────────
# LOGIN DECORATOR
# ─────────────────────────────
def login_required(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        if not current_user():
            return jsonify({"error": "not logged in"}), 401
        return f(*args, **kwargs)
    return wrap


# ─────────────────────────────
# CHAT 
# ─────────────────────────────
@app.route("/api/chat", methods=["POST"])
def chat():
    data = request.json or {}
    messages = data.get("messages", [])

    if not messages:
        return jsonify({"reply": "No message"}), 400

    msg = messages[-1]["content"]
    uid = current_user() or "guest"

    # ───── 1. COOLDOWN (ANTI SPAM)
    now = time.time()
    if now - user_last_call[uid] < COOLDOWN:
        return jsonify({
            "reply": "⏳ chill bro… AI is cooling down",
            "typing": True
        })

    user_last_call[uid] = now

    # ───── 2. SAVE USER MESSAGE (memory)
    user_chat_memory[uid].append({"role": "user", "msg": msg})
    user_chat_memory[uid] = user_chat_memory[uid][-MAX_MEMORY:]

    save_chat(uid, "user", msg)

    # ───── 3. AI CALL (SMART ROUTER)
    reply = ai_router(msg)

    if not reply:
        return jsonify({
            "reply": "⚡ AI overloaded. Try again in a moment.",
            "typing": True
        })

    # ───── 4. SAVE AI RESPONSE
    user_chat_memory[uid].append({"role": "ai", "msg": reply})
    save_chat(uid, "ai", reply)

    # ───── 5. STREAM-LIKE RESPONSE (SIMULATED)
    return jsonify({
        "reply": reply,
        "typing": False,
        "stream": True,
        "memory": user_chat_memory[uid]
    })

# ─────────────────────────────
# apichat-stream 
# ─────────────────────────────
@app.route("/api/chat-stream", methods=["POST"])
def chat_stream():
    data = request.json or {}
    messages = data.get("messages", [])

    if not messages:
        return jsonify({"error": "No message"}), 400

    msg = messages[-1]["content"]

    def generate():
        reply = ai_router(msg)

        if not reply:
            yield f"data: {json.dumps({'token': '⚡ AI overloaded'})}\n\n"
            return

        for word in reply.split():
            time.sleep(0.04)
            yield f"data: {json.dumps({'token': word + ' '})}\n\n"

        yield "data: [DONE]\n\n"

    return Response(stream_with_context(generate()), mimetype="text/event-stream")


# ─────────────────────────────
# AUTH (MINIMAL CLEAN)
# ─────────────────────────────
@app.route("/api/login", methods=["POST"])
def login():
    data = request.json
    user = data.get("username")
    session["user_id"] = user
    return jsonify({"ok": True})


@app.route("/api/logout", methods=["POST"])
def logout():
    session.clear()
    return jsonify({"ok": True})

# ─────────────────────────────
# landing + chat pages
# ─────────────────────────────
@app.route("/")
def landing():
    return render_template("landing.html")

@app.route("/chat")
def chat_page():
    return render_template("chat.html")

@app.route("/login")
def login_page():
    return render_template("login.html")

@app.route("/dashboard")
def dashboard():
    return render_template("dashboard.html")

# ─────────────────────────────
# INIT + RUN
# ─────────────────────────────
if __name__ == "__main__":
    init_db()
    print("🔥 CyberSentinel running")
    app.run(debug=True)