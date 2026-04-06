from werkzeug.security import generate_password_hash, check_password_hash
from flask import Flask, request, jsonify, render_template, redirect, session
from flask_cors import CORS
import joblib
import re
import os
import sqlite3
from dotenv import load_dotenv
from urllib.parse import urlparse

# ======================
# ENV LOAD
# ======================
load_dotenv()
API_KEY = os.getenv("API_KEY")

app = Flask(__name__)
app.secret_key = "secret123"

# 🔥 SESSION FIX
app.config['SESSION_COOKIE_SAMESITE'] = "Lax"
app.config['SESSION_COOKIE_SECURE'] = False

# 🔥 CORS FIX
CORS(app, supports_credentials=True)

# ======================
# TRUSTED DOMAINS
# ======================
TRUSTED_DOMAINS = {
    "google.com",
    "facebook.com",
    "youtube.com",
    "instagram.com",
    "linkedin.com",
    "wikipedia.org",
    "amazon.com",
    "microsoft.com",
    "apple.com"
}

# ======================
# DB INIT
# ======================
def init_db():
    conn = sqlite3.connect("scam.db")
    cursor = conn.cursor()

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS history (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        url TEXT,
        domain TEXT,
        score INTEGER,
        status TEXT,
        reason TEXT,
        username TEXT
    )
    """)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        password TEXT
    )
    """)

    conn.commit()
    conn.close()

init_db()

# ======================
# LOAD ML MODEL
# ======================
model = joblib.load("model.pkl")
vectorizer = joblib.load("vectorizer.pkl")

# ======================
# HELPERS
# ======================
def normalize_url(url):
    if not url:
        return ""
    if not url.startswith("http"):
        return "http://" + url
    return url

def get_domain(url):
    try:
        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        return domain.replace("www.", "")
    except:
        return ""

def is_valid_url(url):
    pattern = re.compile(r'^(https?:\/\/)?([\w\-]+\.)+[\w\-]+')
    return re.match(pattern, url)

# ======================
# ROUTES
# ======================
@app.route("/")
def home():
    return render_template("login.html")

@app.route("/dashboard")
def dashboard():
    if "user" not in session:
        return redirect("/")

    # 🔥 ADMIN CHECK
    if session["user"] == "admin":
        return redirect("/admin")

    return render_template("index.html")

@app.route("/admin")
def admin():
    if "user" not in session or session["user"] != "admin":
        return redirect("/")

    return render_template("admin.html")

@app.route("/admin-data")
def admin_data():
    if "user" not in session or session["user"] != "admin":
        return jsonify([])

    conn = sqlite3.connect("scam.db")
    cursor = conn.cursor()

    cursor.execute("""
        SELECT username, url, status, score 
        FROM history
        ORDER BY id DESC
    """)

    rows = cursor.fetchall()
    conn.close()

    return jsonify([
        {
            "username": r[0],
            "url": r[1],
            "status": r[2],
            "score": r[3]
        }
        for r in rows
    ])

@app.route("/logout")
def logout():
    session.pop("user", None)
    return redirect("/")



# ======================
# AUTH
# ======================
@app.route("/signup", methods=["POST"])
def signup():
    data = request.get_json()
    username = data.get("username")
    password = data.get("password")

    import re

    if len(password) < 6:
        return jsonify({"success": False, "message": "Password must be at least 6 characters"})

    if not re.search(r"[A-Z]", password):
        return jsonify({"success": False, "message": "Add at least 1 Capital Letter"})

    if not re.search(r"[0-9]", password):
        return jsonify({"success": False, "message": "Add at least 1 Number"})

    conn = sqlite3.connect("scam.db")
    cursor = conn.cursor()

    try:
        hashed_password = generate_password_hash(password)

        cursor.execute(
            "INSERT INTO users (username, password) VALUES (?, ?)",
            (username, hashed_password)
        )

        conn.commit()
        return jsonify({"success": True})
    except:
        return jsonify({"success": False, "message": "User already exists"})
    finally:
        conn.close()

@app.route("/login", methods=["POST"])
def login():
    data = request.get_json()
    username = data.get("username")
    password = data.get("password")

    conn = sqlite3.connect("scam.db")
    cursor = conn.cursor()

    cursor.execute(
        "SELECT * FROM users WHERE username=?",
        (username,)
    )

    user = cursor.fetchone()
    conn.close()

    if user and check_password_hash(user[2], password):
        session["user"] = username
        print("LOGIN SUCCESS:", session.get("user"))
        return jsonify({"success": True})
    else:
        return jsonify({"success": False, "message": "Invalid credentials"})

# ======================
# SCAN API (FINAL FIXED LOGIC)
# ======================
@app.route("/check", methods=["POST"])
def check():
    print("SESSION USER:", session.get("user"))

    user = session.get("user", "extension_user")

    data = request.get_json()
    url = data.get("url", "").strip()

    url = normalize_url(url)

    if not url or not is_valid_url(url):
        return jsonify({
            "url": url,
            "domain": "",
            "score": 0,
            "status": "Invalid",
            "reason": "Invalid URL",
            "ml_prediction": 0
        })

    domain = get_domain(url) or url

    # default values
    ml_prediction = 0
    score = 30
    status = "Safe"

    # 🔥 WHY SCAM LIST
    reason_list = []

# 🔥 HTTP check (NEW)
    if url.startswith("http://"):
     score += 20
    reason_list.append("⚠️ Not secure (HTTP used)")

    # ======================
    # TRUSTED DOMAIN
    # ======================
    if domain in TRUSTED_DOMAINS:
        score = 5
        status = "Safe"
        reason = "Trusted verified domain"

    else:
        # ======================
        # FETCH HTML
        # ======================
        html_content = ""
        try:
            import requests
            res = requests.get(url, timeout=5)
            html_content = res.text.lower()
        except:
            html_content = ""

        # ======================
        # SUSPICIOUS WORDS
        # ======================
        suspicious_words = [
            "login", "verify", "bank", "update",
            "password", "secure", "account", "confirm"
        ]

        has_password_field = "type=\"password\"" in html_content
        keyword_flag = any(word in url.lower() for word in suspicious_words)

        # ======================
        # ML PREDICTION
        # ======================
        try:
            X_ml = vectorizer.transform([url])
            ml_prediction = model.predict(X_ml)[0]
        except:
            ml_prediction = 0

        # ======================
        # SCORE CALCULATION
        # ======================
        for word in suspicious_words:
            if word in url.lower():
                score += 10

        if ml_prediction == 1:
            score += 40

        # ======================
        # FAKE LOGIN DETECTION
        # ======================
        if has_password_field and keyword_flag:
            score = 95
            status = "Dangerous"
        else:
            if score >= 80:
                status = "Dangerous"
            elif score >= 50:
                status = "Suspicious"
            else:
                status = "Safe"

        # ======================
        # 🔥 WHY SCAM (FINAL REASON)
        # ======================
        

        # ======================
# 🔥 WHY SCAM (FINAL REASON)
# ======================

    for word in suspicious_words:
     if word in url.lower():
        reason_list.append(f"Contains: {word}")

    if ml_prediction == 1:
       reason_list.append("AI detected phishing pattern")

    if has_password_field:
       reason_list.append("Login/password field found")

    if has_password_field and keyword_flag:
       reason_list.append("🚨 Fake login page detected")

    if reason_list:
       reason = " | ".join(reason_list)
    else:
        reason = "No major risk detected"

    # ======================
    # SAVE HISTORY
    # ======================
    conn = sqlite3.connect("scam.db")
    cursor = conn.cursor()

    cursor.execute("""
    INSERT INTO history (url, domain, score, status, reason, username)
    VALUES (?, ?, ?, ?, ?, ?)
""", (url, domain, score, status, reason, user))

    conn.commit()
    conn.close()

    return jsonify({
        "url": url,
        "domain": domain,
        "score": score,
        "status": status,
        "ml_prediction": int(ml_prediction),
        "reason": reason
    })

# ======================
# HISTORY (USER-WISE)
# ======================
@app.route("/history")
def history():
    if "user" not in session:
        return jsonify([])

    conn = sqlite3.connect("scam.db")
    cursor = conn.cursor()

    cursor.execute(
        "SELECT url, domain, score, status, reason FROM history WHERE username=? ORDER BY id DESC",
        (session["user"],)
    )

    rows = cursor.fetchall()
    conn.close()

    return jsonify([
        {
            "url": r[0],
            "domain": r[1],
            "score": r[2],
            "status": r[3],
            "reason": r[4]
        }
        for r in rows
    ])

# ======================
# RUN
# ======================
if __name__ == "__main__":
    app.run(debug=True)