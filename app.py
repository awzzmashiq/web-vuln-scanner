from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
import subprocess
import os
import re

app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "*"}}, supports_credentials=True)

# Database Configuration
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///scans.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# Database Model for Scan Results
class ScanResult(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    url = db.Column(db.String(500), nullable=False)
    vulnerabilities = db.Column(db.JSON, nullable=False)
    security_score = db.Column(db.Integer, nullable=False)

with app.app_context():
    db.create_all()

# Validate URL format
def is_valid_url(url):
    regex = re.compile(
        r'^(https?://)'  # Must start with http:// or https://
        r'([\da-z\.-]+)\.([a-z\.]{2,6})'  # Domain name
        r'([\/\w \.-]*)*/?$'  # Path
    )
    return re.match(regex, url) is not None

# Calculate Security Score
def calculate_security_score(vulnerabilities, url):
    score = 100  # Start at 100
    threat_indicators = {
        "Network Security": 100,
        "DNS Health": 100,
        "Patching Cadence": 100,
        "Endpoint Security": 100,
        "IP Reputation": 100,
        "Application Security": 100,
        "Cubit Score": 100,
        "Hacker Chatter": 100
    }

    # 🔴 **Check if the URL is using HTTP (not HTTPS)**
    if url.startswith("http://"):
        print("⚠️ Detected HTTP (not HTTPS) - Deducting 30 points")
        threat_indicators["Network Security"] -= 30

    # 🔍 **Reduce score based on vulnerabilities**
    for vuln in vulnerabilities:
        if "X-Content-Type-Options header is not set" in vuln:
            threat_indicators["Network Security"] -= 15
        if "SQL Injection" in vuln or "SQL" in vuln:
            threat_indicators["Application Security"] -= 40
        if "Cross-Site Scripting" in vuln or "XSS" in vuln:
            threat_indicators["Application Security"] -= 30
        if "malware" in vuln or "spam" in vuln:
            threat_indicators["IP Reputation"] -= 40
        if "out of date" in vuln:
            threat_indicators["Patching Cadence"] -= 35

    # 🛡️ **Ensure no negative scores**
    for key in threat_indicators:
        if threat_indicators[key] < 0:
            threat_indicators[key] = 0

    # 🔢 **Calculate final security score**
    overall_score = sum(threat_indicators.values()) // len(threat_indicators)

    # 🔡 Convert to grades (A, B, C, D, F)
    def grade(score):
        if score >= 90: return "A"
        elif score >= 75: return "B"
        elif score >= 60: return "C"
        elif score >= 40: return "D"
        else: return "F"

    for category in threat_indicators:
        threat_indicators[category] = {"score": threat_indicators[category], "grade": grade(threat_indicators[category])}

    return overall_score, threat_indicators

# Run Nikto Scan
def run_nikto_scan(target_url):
    try:
        print(f"🔍 Running Nikto scan for: {target_url}")

        nikto_path = os.path.abspath("nikto/program/nikto.pl")
        if not os.path.exists(nikto_path):
            return {"error": "Nikto script not found. Ensure it's installed correctly."}

        result = subprocess.run(
            ["perl", nikto_path, "-h", target_url], 
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=120
        )

        vulnerabilities = [line.strip() for line in result.stdout.split("\n") if "OSVDB" in line or "XSS" in line or "SQL" in line or "vulnerability" in line]

        overall_score, threat_indicators = calculate_security_score(vulnerabilities, target_url)

        return {"security_score": overall_score, "threat_indicators": threat_indicators, "vulnerabilities": vulnerabilities}

    except subprocess.TimeoutExpired:
        return {"error": "Nikto scan took too long and was stopped."}

# API to Scan a Website
@app.route('/scan', methods=['POST'])
def scan_website():
    data = request.get_json()
    url = data.get("url")

    if not is_valid_url(url):
        return jsonify({"error": "Invalid URL"}), 400

    scan_results = run_nikto_scan(url)

    return jsonify(scan_results)

# Fetch Scan Results
@app.route('/results', methods=['GET'])
def get_scan_results():
    results = ScanResult.query.all()
    return jsonify([{"id": r.id, "url": r.url, "vulnerabilities": r.vulnerabilities, "security_score": r.security_score} for r in results])

if __name__ == '__main__':
    app.run(debug=True)
