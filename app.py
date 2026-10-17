
import os
import re
import sqlite3
import ipaddress
import joblib

from datetime import datetime
from urllib.parse import urlsplit
from threading import Lock

from flask import (
    Flask,
    render_template,
    request,
    jsonify,
    send_file
)

from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet
from werkzeug.utils import secure_filename


# ==================================================
# PHISHGUARD AI - CONFIGURATION
# ==================================================

app = Flask(__name__)

BASE_DIR = os.path.abspath(os.path.dirname(__file__))

DB_NAME = os.path.join(BASE_DIR, "phishing.db")
MODEL_PATH = os.path.join(BASE_DIR, "model.pkl")
REPORT_DIR = os.path.join(BASE_DIR, "reports")

os.makedirs(REPORT_DIR, exist_ok=True)

app.config["MAX_CONTENT_LENGTH"] = 2 * 1024 * 1024

report_lock = Lock()


# ==================================================
# LOAD MACHINE LEARNING MODEL
# ==================================================

model = None
model_error = None

try:
    if os.path.isfile(MODEL_PATH):
        model = joblib.load(MODEL_PATH)
        print("ML model loaded successfully.")
    else:
        model_error = "model.pkl was not found."
        print(model_error)

except Exception as exc:
    model_error = str(exc)
    print("ML model loading failed:", model_error)


# ==================================================
# DATABASE INITIALIZATION
# ==================================================

def init_db():
    conn = sqlite3.connect(DB_NAME)

    try:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target TEXT NOT NULL,
                score INTEGER NOT NULL,
                status TEXT NOT NULL,
                scan_time TEXT NOT NULL
            )
        """)

        conn.commit()

    finally:
        conn.close()


def get_db_connection():
    return sqlite3.connect(DB_NAME, timeout=10)


init_db()


# ==================================================
# COMMON RISK CLASSIFICATION
# ==================================================

def classify_score(score):
    score = max(0, min(100, int(score)))

    if score >= 60:
        return "PHISHING"

    if score >= 30:
        return "SUSPICIOUS"

    return "SAFE"


# ==================================================
# URL PHISHING DETECTION
# ==================================================

def analyze_url(url):
    url = (url or "").strip()

    score = 0
    reasons = []

    if not url:
        return 0, "INVALID", ["Please enter a URL."]

    # Add a scheme if the user enters a domain without one.
    parsed_input = url

    if not re.match(
        r"^[a-zA-Z][a-zA-Z0-9+.-]*://",
        parsed_input
    ):
        parsed_input = "https://" + parsed_input

    try:
        parsed = urlsplit(parsed_input)

        hostname = parsed.hostname or ""
        scheme = parsed.scheme.lower()

        # Accessing port can raise ValueError for malformed URLs.
        _ = parsed.port

    except ValueError:
        return 0, "INVALID", ["The URL format is invalid."]

    if scheme not in ("http", "https") or not hostname:
        return 0, "INVALID", [
            "Enter a valid HTTP or HTTPS URL."
        ]

    lower_url = url.lower()
    lower_host = hostname.lower()

    # 1. @ symbol in the URL authority section.
    if "@" in parsed.netloc:
        score += 30
        reasons.append(
            "URL contains an @ symbol in its authority section."
        )

    # 2. Common URL shorteners.
    shorteners = {
        "bit.ly",
        "tinyurl.com",
        "t.co",
        "is.gd",
        "cutt.ly",
        "rb.gy",
        "shorturl.at"
    }

    if lower_host in shorteners:
        score += 30
        reasons.append("URL shortener detected.")

    # 3. IP address used instead of a domain name.
    try:
        ipaddress.ip_address(hostname)

        score += 40
        reasons.append(
            "The URL uses an IP address as its hostname."
        )

    except ValueError:
        pass

    # 4. Unusually long URL.
    if len(url) > 75:
        score += 15
        reasons.append("Unusually long URL.")

    # 5. Suspicious keywords.
    suspicious_words = [
        "login",
        "verify",
        "secure",
        "update",
        "account",
        "banking",
        "signin",
        "confirm",
        "password",
        "wallet",
        "credential"
    ]

    for word in suspicious_words:
        if word in lower_url:
            score += 10
            reasons.append(
                f"Suspicious keyword detected: {word}"
            )

    # 6. Suspicious domain extensions.
    suspicious_tlds = [
        ".xyz",
        ".top",
        ".click",
        ".tk",
        ".gq"
    ]

    for tld in suspicious_tlds:
        if lower_host.endswith(tld):
            score += 25
            reasons.append(
                f"Suspicious domain extension: {tld}"
            )

    score = min(score, 100)
    status = classify_score(score)

    if not reasons:
        reasons.append(
            "No configured warning indicators were detected."
        )

    return score, status, reasons


# ==================================================
# EMAIL PHISHING DETECTION
# ==================================================

def analyze_email(text):
    text = (text or "").strip()

    if not text:
        return 0, "INVALID", [
            "Please enter email content."
        ]

    score = 0
    reasons = []

    lower_text = text.lower()

    suspicious_phrases = [
        "urgent",
        "verify your account",
        "click here",
        "limited time",
        "account suspended",
        "bank details",
        "reset password",
        "act now",
        "confirm your password",
        "unusual activity",
        "your account will be closed",
        "immediately verify"
    ]

    # 1. Detect suspicious phrases.
    for phrase in suspicious_phrases:
        if phrase in lower_text:
            score += 15
            reasons.append(
                f"Suspicious phrase detected: {phrase}"
            )

    # 2. Detect links.
    links = re.findall(
        r"https?://[^\s<>\"']+",
        text,
        re.IGNORECASE
    )

    if links:
        score += 20
        reasons.append(
            f"External link(s) detected: {len(links)}"
        )

    score = min(score, 100)
    status = classify_score(score)

    if not reasons:
        reasons.append(
            "No configured warning indicators were detected."
        )

    return score, status, reasons


# ==================================================
# SAVE SCAN TO DATABASE
# ==================================================

def save_scan(target, score, status):
    scan_time = datetime.now().strftime(
        "%Y-%m-%d %H:%M:%S"
    )

    conn = get_db_connection()

    try:
        conn.execute("""
            INSERT INTO scans (
                target,
                score,
                status,
                scan_time
            )
            VALUES (?, ?, ?, ?)
        """, (
            target,
            score,
            status,
            scan_time
        ))

        conn.commit()

    finally:
        conn.close()


# ==================================================
# HOME PAGE - URL AND EMAIL SCANNER
# ==================================================

@app.route("/", methods=["GET", "POST"])
def home():
    result = None

    if request.method == "POST":

        scan_type = request.form.get(
            "scan_type", "url"
        ).strip().lower()

        if scan_type == "url":

            target = request.form.get(
                "url", ""
            ).strip()

            score, status, reasons = analyze_url(
                target
            )

        elif scan_type == "email":

            target = request.form.get(
                "email_content", ""
            ).strip()

            score, status, reasons = analyze_email(
                target
            )

        else:
            target = ""
            score = 0
            status = "INVALID"
            reasons = ["Invalid scan type."]

        # Save valid scan attempts only.
        if target and status != "INVALID":
            save_scan(target, score, status)

        result = {
            "target": target,
            "score": score,
            "status": status,
            "reasons": reasons
        }

    return render_template(
        "index.html",
        result=result
    )


# ==================================================
# DASHBOARD
# ==================================================

@app.route("/dashboard")
def dashboard():
    conn = get_db_connection()

    try:
        cur = conn.cursor()

        cur.execute("""
            SELECT COUNT(*)
            FROM scans
        """)
        total = cur.fetchone()[0]

        cur.execute("""
            SELECT COUNT(*)
            FROM scans
            WHERE status = 'SAFE'
        """)
        safe = cur.fetchone()[0]

        cur.execute("""
            SELECT COUNT(*)
            FROM scans
            WHERE status = 'SUSPICIOUS'
        """)
        suspicious = cur.fetchone()[0]

        cur.execute("""
            SELECT COUNT(*)
            FROM scans
            WHERE status = 'PHISHING'
        """)
        phishing = cur.fetchone()[0]

        cur.execute("""
            SELECT target, status, score, scan_time
            FROM scans
            ORDER BY id DESC
            LIMIT 10
        """)
        recent = cur.fetchall()

    finally:
        conn.close()

    return render_template(
        "dashboard.html",
        total=total,
        safe=safe,
        suspicious=suspicious,
        phishing=phishing,
        recent=recent
    )


# ==================================================
# STATISTICS API
# ==================================================

@app.route("/stats", methods=["GET"])
def stats():
    conn = get_db_connection()

    try:
        cur = conn.cursor()

        cur.execute("""
            SELECT status, COUNT(*)
            FROM scans
            GROUP BY status
        """)

        counts = dict(cur.fetchall())

    finally:
        conn.close()

    return jsonify({
        "total": sum(counts.values()),
        "safe": counts.get("SAFE", 0),
        "suspicious": counts.get("SUSPICIOUS", 0),
        "phishing": counts.get("PHISHING", 0)
    })


# ==================================================
# PDF REPORT GENERATION
# ==================================================

@app.route(
    "/report/<int:score>/<status>",
    methods=["GET"]
)
def report(score, status):

    allowed_statuses = {
        "SAFE",
        "SUSPICIOUS",
        "PHISHING"
    }

    if status not in allowed_statuses:
        return jsonify({
            "error": "Invalid report status."
        }), 400

    if not 0 <= score <= 100:
        return jsonify({
            "error": "Risk score must be between 0 and 100."
        }), 400

    # Use a separate report file for each request.
    filename = (
        "report_"
        + datetime.now().strftime("%Y%m%d_%H%M%S_%f")
        + ".pdf"
    )

    pdf_path = os.path.join(
        REPORT_DIR,
        secure_filename(filename)
    )

    styles = getSampleStyleSheet()

    elements = [
        Paragraph(
            "PhishGuard AI - Scan Report",
            styles["Title"]
        ),
        Spacer(1, 20),
        Paragraph(
            f"Risk Score: {score}/100",
            styles["Normal"]
        ),
        Spacer(1, 10),
        Paragraph(
            f"Status: {status}",
            styles["Normal"]
        ),
        Spacer(1, 20),
        Paragraph(
            "This report uses configured detection rules. "
            "It does not guarantee that a URL or email is safe.",
            styles["Normal"]
        ),
        Spacer(1, 20),
        Paragraph(
            "Generated on: "
            + datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            styles["Normal"]
        )
    ]

    with report_lock:
        doc = SimpleDocTemplate(
            pdf_path,
            pagesize=letter
        )
        doc.build(elements)

    return send_file(
        pdf_path,
        as_attachment=True,
        download_name="PhishGuard_AI_Report.pdf"
    )


# ==================================================
# HEALTH CHECK
# ==================================================

@app.route("/health", methods=["GET"])
def health():
    return jsonify({
        "application": "PhishGuard AI",
        "status": "running",
        "model_loaded": model is not None
    })


# ==================================================
# ERROR HANDLERS
# ==================================================

@app.errorhandler(404)
def page_not_found(error):
    return jsonify({
        "error": "Page not found."
    }), 404


@app.errorhandler(413)
def request_too_large(error):
    return jsonify({
        "error": "Input is too large. Maximum request size is 2 MB."
    }), 413


# ==================================================
# RUN APPLICATION
# ==================================================

if __name__ == "__main__":
    print("=" * 45)
    print("       PHISHGUARD AI")
    print("=" * 45)
    print("Database:", DB_NAME)
    print("ML model loaded:", model is not None)
    print("Starting Flask server...")

    app.run(
        host="127.0.0.1",
        port=5000,
        debug=True
    )
