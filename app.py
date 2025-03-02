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

        print(f"✅ Nikto Output:\n{result.stdout}")
        print(f"⚠️ Nikto Errors:\n{result.stderr}")

        vulnerabilities = []
        score = 100

        # Reduce score for HTTP (no SSL)
        if target_url.startswith("http://"):
            vulnerabilities.append("⚠️ Website is using HTTP instead of HTTPS. Not secure!")
            score -= 20  

        for line in result.stdout.split("\n"):
            if "OSVDB" in line or "XSS" in line or "SQL" in line or "vulnerability" in line:
                vulnerabilities.append(line.strip())
                if "SQL" in line:
                    score -= 20
                elif "XSS" in line:
                    score -= 15
                elif "TRACE" in line or "insecure headers" in line:
                    score -= 10
                elif "admin" in line or "open directory" in line:
                    score -= 5
                elif "information leakage" in line:
                    score -= 5
                else:
                    score -= 2  

            # Detect missing security headers
            if "X-Content-Type-Options header is not set" in line:
                vulnerabilities.append("Missing X-Content-Type-Options header (Clickjacking Risk)")
                score -= 5

            if "Server: No banner retrieved" in line:
                vulnerabilities.append("Server fingerprinting disabled (No Banner)")
                score -= 2

        return {"vulnerabilities": vulnerabilities, "security_score": max(score, 0)}

    except subprocess.TimeoutExpired:
        return {"error": "Nikto scan took too long and was stopped."}

    except Exception as e:
        return {"error": str(e)}

# API to Scan a Website
@app.route('/scan', methods=['POST'])
def scan_website():
    data = request.get_json()
    
    if not data or "url" not in data:
        return jsonify({"error": "URL is required"}), 400

    url = data["url"].strip()

    # Validate URL before scanning
    if not is_valid_url(url):
        return jsonify({"error": "Invalid URL format"}), 400

    print(f"📡 Received scan request for: {url}")

    scan_results = run_nikto_scan(url)

    # If Nikto scan fails, return an error response
    if "error" in scan_results:
        return jsonify({"error": scan_results["error"]}), 500

    # Save results if scan is successful
    new_scan = ScanResult(url=url, vulnerabilities=scan_results["vulnerabilities"], security_score=scan_results["security_score"])
    db.session.add(new_scan)
    db.session.commit()

    return jsonify(scan_results)

# Fetch Scan Results
@app.route('/results', methods=['GET'])
def get_scan_results():
    results = ScanResult.query.all()
    return jsonify([{"id": r.id, "url": r.url, "vulnerabilities": r.vulnerabilities, "security_score": r.security_score} for r in results])

if __name__ == '__main__':
    app.run(debug=True)
