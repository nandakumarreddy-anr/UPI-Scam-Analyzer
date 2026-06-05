import email

from flask import Flask, render_template, request, redirect, jsonify, session
import mysql.connector
import bcrypt
import re
import random
import smtplib
import os
from email.mime.text import MIMEText
import joblib
import pandas as pd

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "secret123")

ADMIN_EMAIL = "nandakumarreddy63@gmail.com"

# ---------------- DATABASE ----------------

import mysql.connector
import os

try:
    print("DB_HOST =", os.getenv("DB_HOST"))
    print("DB_PORT =", os.getenv("DB_PORT"))
    print("DB_USER =", os.getenv("DB_USER"))
    print("DB_NAME =", os.getenv("DB_NAME"))

    db = mysql.connector.connect(
        host=os.getenv("DB_HOST"),
        port=int(os.getenv("DB_PORT", "11510")),
        user=os.getenv("DB_USER"),
        password=os.getenv("DB_PASSWORD"),
        database=os.getenv("DB_NAME")
    )

    cursor = db.cursor(buffered=True)

    print("✅ Database Connected Successfully")

except Exception as e:
    print("❌ Database Connection Error:", str(e))

    db = None
    cursor = None
# ---------------- LOAD MODELS ----------------
try:
    sms_model = joblib.load("sms_model.pkl")
    sms_vectorizer = joblib.load("sms_vectorizer.pkl")
except:
    sms_model = None
    sms_vectorizer = None

try:
    url_model = joblib.load("url_model.pkl")
except:
    url_model = None

try:
    upi_model = joblib.load("upi_model.pkl")
    upi_vectorizer = joblib.load("upi_vectorizer.pkl")
except:
    upi_model = None
    upi_vectorizer = None

# ---------------- OTP STORAGE ----------------
otp_storage = {}

# ---------------- EMAIL ----------------
def send_email(to_email, subject, body):
    sender_email = os.getenv("EMAIL_USER")
    app_password = os.getenv("EMAIL_PASS")

    print("EMAIL_USER =", sender_email)
    print("EMAIL_PASS exists =", bool(app_password))

    try:
        msg = MIMEText(body)
        msg['Subject'] = subject
        msg['From'] = sender_email
        msg['To'] = to_email

        print("Connecting SMTP...")

        with smtplib.SMTP("smtp.gmail.com", 587, timeout=20) as server:
            server.starttls()

            print("Logging in...")

            server.login(sender_email, app_password)

            print("Sending mail...")

            server.sendmail(
                sender_email,
                to_email,
                msg.as_string()
            )

        print("✅ Email sent successfully")

    except Exception as e:
        print("❌ Email error:", repr(e))
        raise
# ---------------- HELPER ----------------
def get_result(score):
    if score <= 3:
        return "Safe"
    elif score <= 7:
        return "Warning"
    else:
        return "Dangerous"

# ---------------- HOME ----------------
@app.route('/')
def home():
    return redirect('/dashboard')

# ---------------- REGISTER ----------------
@app.route('/register', methods=['GET', 'POST'])
def register():

    if cursor is None:
        return "Database connection failed ❌"

    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        password = request.form['password']
        confirm = request.form['confirm']

        if password != confirm:
            return "Passwords do not match ❌"

        cursor.execute(
            "SELECT * FROM users WHERE email=%s",
            (email,)
        )

        existing = cursor.fetchone()

        if existing:
            return "Email already registered ❌"

        otp = str(random.randint(100000, 999999))

        otp_storage[email] = (otp, name, password)

        print(f"OTP for {email}: {otp}")

        return render_template("otp.html", email=email)

    return render_template("register.html")

# ---------------- VERIFY OTP ----------------
@app.route('/verify_otp', methods=['POST'])
def verify_otp():
    email = request.form['email']
    user_otp = request.form['otp']

    if email in otp_storage:
        otp, name, password = otp_storage[email]

        if user_otp == otp:
            hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt())

            cursor.execute(
                "INSERT INTO users (name,email,password) VALUES (%s,%s,%s)",
                (name, email, hashed)
            )
            db.commit()

            otp_storage.pop(email)
            return redirect('/login')

    return "Invalid OTP ❌"

# ---------------- LOGIN ----------------
@app.route('/login', methods=['GET', 'POST'])
def login():

    if cursor is None:
        return "Database connection failed ❌"

    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        cursor.execute(
            "SELECT * FROM users WHERE email=%s",
            (email,)
        )

        user = cursor.fetchone()

        if user:
            stored = user[3]

            if isinstance(stored, str):
                stored = stored.encode()

            if bcrypt.checkpw(password.encode(), stored):
                session['user'] = email
                return redirect('/dashboard')

        return "Invalid login ❌"

    return render_template("login.html")
# ---------------- LOGOUT ----------------
@app.route('/logout')
def logout():
    session.clear()
    return redirect('/login')
# ---------------- forgot password ----------------
@app.route('/forgot', methods=['GET','POST'])
def forgot():
    if request.method == 'POST':
        email = request.form['email']

        otp = str(random.randint(100000,999999))
        otp_storage[email] = otp

        print(f"RESET OTP for {email}: {otp}")

        return render_template("reset_otp.html", email=email)

    return render_template("forgot.html")
# ----------------  ROUTE EXISTS ----------------
@app.route('/verify_reset_otp', methods=['POST'])
def verify_reset_otp():
    email = request.form['email']
    otp = request.form['otp']

    if email in otp_storage and otp_storage[email] == otp:
        return render_template("new_password.html", email=email)

    return "Invalid OTP ❌"
# ---------------- update password ----------------
@app.route('/update_password', methods=['POST'])
def update_password():
    email = request.form['email']
    password = request.form['password']
    confirm = request.form['confirm']

    if password != confirm:
        return "Passwords do not match ❌"

    hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt())

    cursor.execute(
        "UPDATE users SET password=%s WHERE email=%s",
        (hashed, email)
    )
    db.commit()

    # remove OTP after use
    otp_storage.pop(email, None)

    return redirect('/login')
# ---------------- DASHBOARD ----------------
@app.route('/dashboard')
def dashboard():
    return render_template("dashboard.html", user="Demo User")

# ---------------- ADMIN ----------------
@app.route('/admin', methods=['GET','POST'])
def admin():
    if 'user' not in session:
        return redirect('/login')

    if session['user'] != ADMIN_EMAIL:
        return redirect('/dashboard')

    if request.method == 'POST':
        data = request.form['data']
        type_ = request.form['type']
        reason = request.form['reason']

        cursor.execute(
            "INSERT INTO blacklist (data,type,reason) VALUES (%s,%s,%s)",
            (data,type_,reason)
        )
        db.commit()

    cursor.execute("SELECT * FROM blacklist")
    items = cursor.fetchall()

    return render_template("admin.html", items=items, user=session['user'])
# ---------------- DELETE BLACKLIST ----------------
@app.route('/delete_blacklist/<int:id>', methods=['POST'])
def delete_blacklist(id):

    cursor.execute(
        "DELETE FROM blacklist WHERE id=%s",
        (id,)
    )

    db.commit()

    return redirect('/admin')
# ---------------- HISTORY ----------------
@app.route('/history')
def history():
    if 'user' not in session:
        return redirect('/login')

    cursor.execute("""
        SELECT type, input_data, score, result, created_at 
        FROM scans 
        ORDER BY id DESC
    """)
    scans = cursor.fetchall()

    return render_template("history.html", scans=scans, user=session['user'])

# ---------------- PAGES ----------------
@app.route('/upi')
def upi():
    return render_template("upi.html", user="Demo User")

@app.route('/url')
def url_page():
    return render_template("url.html", user="Demo User")

@app.route('/sms')
def sms():
    return render_template("sms.html", user="Demo User")

# ---------------- UPI CHECK ----------------
@app.route('/check_upi', methods=['POST'])
def check_upi():

    upi = request.json['upi'].lower()

    score = 0
    reasons = []

    # 🔍 RULES

    if not re.match(r'^[\w.-]+@[\w.-]+$', upi):
        score += 5
        reasons.append("Invalid UPI format")

    if any(x in upi for x in ["win", "free", "cash", "offer", "bonus"]):
        score += 5
        reasons.append("Contains scam keywords")

    if upi_model and upi_vectorizer:
        try:
            vec = upi_vectorizer.transform([upi])
            pred = upi_model.predict(vec)[0]

            if pred == 1:
                score += 3
                reasons.append("ML model flagged")

        except Exception as e:
            print("UPI Model Error:", e)

    result = get_result(score)

    return jsonify({
        "score": score,
        "result": result,
        "reason": ", ".join(reasons) if reasons else "Looks normal"
    })
# ---------------- URL CHECK ----------------
@app.route('/check_url', methods=['POST'])
def check_url():
    url = request.json['url'].lower()
    score = 0
    reasons = []

    # 🔴 BLACKLIST
    cursor.execute(
        "SELECT * FROM blacklist WHERE LOWER(data)=%s AND type='URL'",
        (url,)
    )
    blacklist_item = cursor.fetchone()

    if blacklist_item:
        result = "Dangerous"

        cursor.execute(
            "INSERT INTO scans (user_id, type, input_data, score, result) VALUES (%s,%s,%s,%s,%s)",
            (1, "URL", url, 10, result)
        )
        db.commit()

        return jsonify({
            "score": 10,
            "result": result,
            "reason": "Blacklisted by admin"
        })

    # 🔍 RULES
    if any(x in url for x in ["login","verify","bank","secure","offer","win"]):
        score += 3
        reasons.append("Suspicious keywords")

    if "bit.ly" in url or "tinyurl" in url:
        score += 5
        reasons.append("Shortened URL")

    if url.count('.') > 3:
        score += 2
        reasons.append("Too many dots")

    if re.search(r'\d+\.\d+\.\d+\.\d+', url):
        score += 5
        reasons.append("IP address used")

    if len(url) > 75:
        score += 2
        reasons.append("Very long URL")

    if not url.startswith("https"):
        score += 2
        reasons.append("Not secure (HTTP)")

    if "@" in url:
        score += 4
        reasons.append("Contains @ symbol")

    if url_model:
        try:
            pred = url_model.predict([url])[0]
            if pred == 1:
                score += 3
                reasons.append("ML model flagged")
        except:
            pass

    result = get_result(score)

    # 💾 SAVE
    cursor.execute(
        "INSERT INTO scans (user_id, type, input_data, score, result) VALUES (%s,%s,%s,%s,%s)",
        (1, "URL", url, score, result)
    )
    db.commit()

    return jsonify({
        "score": score,
        "result": result,
        "reason": ", ".join(reasons) if reasons else "Looks safe"
    })
# ---------------- SMS CHECK ----------------
@app.route('/check_sms', methods=['POST'])
def check_sms():
    sms = request.json['sms'].lower()
    score = 0
    reasons = []

    # 🔴 BLACKLIST
    cursor.execute(
        "SELECT * FROM blacklist WHERE LOWER(data)=%s AND type='SMS'",
        (sms,)
    )
    blacklist_item = cursor.fetchone()

    if blacklist_item:
        result = "Dangerous"

        cursor.execute(
            "INSERT INTO scans (user_id, type, input_data, score, result) VALUES (%s,%s,%s,%s,%s)",
            (1, "SMS", sms, 10, result)
        )
        db.commit()

        return jsonify({
            "score": 10,
            "result": result,
            "reason": "Blacklisted by admin"
        })

    # 🔍 RULES
    if re.search(r'\d{4,}', sms):
        reasons.append("Contains large numbers")

    if any(x in sms for x in ["rs","₹","money","cash"]):
        score += 3
        reasons.append("Money-related content")

    if any(x in sms for x in ["win","free","claim","urgent"]):
        score += 3
        reasons.append("Scam keywords")

    if any(x in sms for x in ["withdraw","transfer","credited"]):
        score += 3
        reasons.append("Financial words")

    if "http" in sms:
        score += 4
        reasons.append("Contains link")

    if sms_model and sms_vectorizer:
        vec = sms_vectorizer.transform([sms])
        pred = sms_model.predict(vec)[0]
        if pred == 1:
            score += 3
            reasons.append("ML model flagged")

    result = get_result(score)

    # 💾 SAVE
    cursor.execute(
        "INSERT INTO scans (user_id, type, input_data, score, result) VALUES (%s,%s,%s,%s,%s)",
        (1, "SMS", sms, score, result)
    )
    db.commit()

    return jsonify({
        "score": score,
        "result": result,
        "reason": ", ".join(reasons) if reasons else "Looks normal"
    })
# ---------------- RUN ----------------
if __name__ == "__main__":
    app.run(debug=True)