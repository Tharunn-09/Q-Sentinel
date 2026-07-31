# ==============================================================================
# Q-Sentinel Backend API
# Run: python app.py
# ==============================================================================

from flask import Flask, request, jsonify, session
from flask_cors import CORS
import socket
import ssl
import datetime
import random
import string
import hashlib
import json
import pyotp
import urllib.request
import urllib.parse
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, ec, dsa
import groq
import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

import database_mongo as db

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "qsentinel-mfa-secret-2026")


# ┌────────────────────────────────────────────────────────┐
# │  API KEYS                                              │
# └────────────────────────────────────────────────────────┘

# ADD YOUR GROQ API KEY HERE (line below)
# Get your API key from: https://console.groq.com/
GROQ_API_KEY = os.environ.get("GROQ_API_KEY", "")

# Configure Groq client
client = groq.Groq(api_key=GROQ_API_KEY)
API_KEY = "qsentinel-team-vectorx-2026"


def add_options_route(route_func):
    """Wrap a route to also handle OPTIONS preflight requests."""
    original = route_func
    def wrapper(*args, **kwargs):
        if request.method == "OPTIONS":
            response = app.make_response("")
            response.headers["Access-Control-Allow-Origin"] = "*"
            response.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
            response.headers["Access-Control-Allow-Headers"] = "Content-Type, X-API-Key"
            return response
        return original(*args, **kwargs)
    wrapper.__name__ = original.__name__
    return wrapper

# Apply OPTIONS handler to all API routes via before_request
@app.before_request
def handle_options():
    if request.method == "OPTIONS":
        response = app.make_response("")
        response.headers["Access-Control-Allow-Origin"] = "*"
        response.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
        response.headers["Access-Control-Allow-Headers"] = "Content-Type, X-API-Key"
        return response

# Allow frontend HTML to communicate with this backend
CORS(app, resources={r"/*": {"origins": "*"}})

def check_api_key():
    """Validate the frontend API key."""
    return request.headers.get("X-API-Key", "") == API_KEY

# ─ 1. Serve Frontend & Health Endpoints ──────────────────────────────────────────
@app.route("/", methods=["GET"])
def index():
    try:
        with open("Q-Sentinel_PNB.html", "r", encoding="utf-8") as f:
            return f.read()
    except Exception as e:
        return f"Error loading frontend: {str(e)}", 500

@app.route("/pnb_logo.jpg", methods=["GET"])
def serve_pnb_logo():
    from flask import send_from_directory
    return send_from_directory(".", "pnb_logo.jpg")

@app.route("/logo.png", methods=["GET"])
def serve_logo():
    from flask import send_from_directory
    return send_from_directory(".", "logo.png")

@app.route("/uco_logo.png", methods=["GET"])
def serve_uco_logo():
    from flask import send_from_directory
    return send_from_directory(".", "uco_logo.png")

@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok", "service": "Q-Sentinel Backend Online"})

# ─ 2. TLS Scanner Endpoint ────────────────────────────────────────────────────
@app.route("/scan", methods=["POST"])
def scan():
    print(f"\n[SCAN] Received scan request")
    if not check_api_key():
        print(f"[SCAN] Unauthorized - invalid API key")
        return jsonify({"error": "Unauthorized — invalid or missing API key"}), 401

    data = request.get_json(force=True, silent=True) or {}
    hostname = (data.get("hostname") or "").strip()
    port     = int(data.get("port", 443))

    print(f"[SCAN] Scanning {hostname}:{port}")
    if not hostname:
        print(f"[SCAN] Missing hostname")
        return jsonify({"error": "Hostname is required"}), 400

    try:
        result = analyze_tls(hostname, port)

        # Print scan details to terminal (VS Code terminal)
        print("\n" + "="*60)
        print(f"  TLS SCAN RESULTS FOR: {hostname}")
        print("="*60)
        print(f"  IP Address    : {result.get('ipAddress', 'N/A')}")
        print(f"  TLS Version   : {result.get('tls', 'N/A')}")
        print(f"  Cipher        : {result.get('cipher', 'N/A')}")
        print(f"  Cert Algo     : {result.get('certAlgo', 'N/A')} ({result.get('keySize', 'N/A')}-bit)")
        print(f"  Issuer        : {result.get('issuer', 'N/A')}")
        print(f"  Subject       : {result.get('subject', 'N/A')}")
        print(f"  Serial Number : {result.get('serialNumber', 'N/A')}")
        print(f"  Valid From    : {result.get('validFrom', 'N/A')}")
        print(f"  Expiry        : {result.get('expiry', 'N/A')}")
        print(f"  Days Left     : {result.get('daysLeft', 'N/A')}")
        print(f"  Key Strength  : {result.get('keyStrength', 'N/A')}")
        print(f"  Key Exchange  : {result.get('keyExchange', 'N/A')}")
        print(f"  Fingerprint   : {result.get('fingerprint', 'N/A')}")
        print(f"  Signature Algo: {result.get('signatureAlgorithm', 'N/A')}")
        print(f"  SSL Grade     : {result.get('sslGrade', 'N/A')}")
        print(f"  Quantum Risk  : {result.get('quantumRisk', 'N/A')}")
        print("="*60 + "\n")

        # Store scan results in database
        try:
            scan_id, host_id = db.store_scan_results(result, hostname, port)
            result['scan_id'] = str(scan_id)
            result['host_id'] = str(host_id)
            result['db_stored'] = True
        except Exception as db_error:
            result['db_stored'] = False
            result['db_error'] = str(db_error)

        return jsonify(result)
    except Exception as e:
        print(f"[SCAN] Error scanning {hostname}: {str(e)}")
        return jsonify({"error": str(e)}), 500

def analyze_tls(hostname, port):
    """Performs live TLS handshake and extracts cert details."""
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    with socket.create_connection((hostname, port), timeout=5) as sock:
        with context.wrap_socket(sock, server_hostname=hostname) as ssock:
            cipher_info = ssock.cipher()
            cipher_name = cipher_info[0]
            tls_version = cipher_info[1].replace('v', ' ')
            der_cert = ssock.getpeercert(binary_form=True)

    cert = x509.load_der_x509_certificate(der_cert, default_backend())

    issuer = "Unknown CA"
    issuer_attrs_cn = cert.issuer.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
    if issuer_attrs_cn:
        issuer = issuer_attrs_cn[0].value

    try:
        not_after = cert.not_valid_after_utc
    except AttributeError:
        not_after = cert.not_valid_after.replace(tzinfo=datetime.timezone.utc)
        
    now = datetime.datetime.now(datetime.timezone.utc)
    days_left = (not_after - now).days
    months = ['Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec']
    expiry_str = f"{not_after.day:02d} {months[not_after.month-1]} {not_after.year}"

    public_key = cert.public_key()
    if isinstance(public_key, rsa.RSAPublicKey):
        cert_algo = "RSA"
        key_size = public_key.key_size
    elif isinstance(public_key, ec.EllipticCurvePublicKey):
        cert_algo = "ECDSA"
        key_size = public_key.curve.key_size
    else:
        cert_algo = "UNKNOWN"
        key_size = 0

    quantum_risk = "LOW"
    if tls_version in ["TLS 1.0", "TLS 1.1", "SSLv3"] or key_size <= 1024 or "RC4" in cipher_name:
        quantum_risk = "CRITICAL"
    elif "CBC" in cipher_name or (cert_algo == "RSA" and key_size <= 2048):
        quantum_risk = "HIGH"
    elif cert_algo == "RSA" and key_size <= 3072:
        quantum_risk = "MODERATE"

    ssl_grade = "B"
    if days_left < 0 or tls_version in ["TLS 1.0", "SSLv3"] or key_size < 1024:
        ssl_grade = "F"
    elif tls_version == "TLS 1.1":
        ssl_grade = "C"
    elif tls_version == "TLS 1.3" and key_size >= 2048 and days_left > 30:
        ssl_grade = "A+"

    # Get additional certificate details
    subject = cert.subject.rfc4514_string()
    serial_number = str(cert.serial_number)

    try:
        sig_algo = cert.signature_hash_algorithm.name + "With" + type(cert.public_key()).__name__
    except Exception:
        sig_algo = str(cert.signature_algorithm_oid)

    # Get validity dates
    try:
        not_before = cert.not_valid_before_utc
    except AttributeError:
        not_before = cert.not_valid_before.replace(tzinfo=datetime.timezone.utc)

    months = ['Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec']
    valid_from_str = f"{not_before.day:02d} {months[not_before.month-1]} {not_before.year}"

    # Calculate key strength
    key_strength = "UNKNOWN"
    if cert_algo == "RSA":
        if key_size < 2048:
            key_strength = "WEAK"
        elif key_size < 3072:
            key_strength = "ACCEPTABLE"
        else:
            key_strength = "STRONG"
    elif cert_algo == "ECDSA":
        if key_size < 256:
            key_strength = "WEAK"
        elif key_size < 384:
            key_strength = "ACCEPTABLE"
        else:
            key_strength = "STRONG"

    # Get IP address
    try:
        ip_address = socket.gethostbyname(hostname)
    except Exception:
        ip_address = "Unknown"

    # Generate fingerprint
    fingerprint = ":".join("{:02x}".format(b) for b in der_cert[:20])

    # Key exchange method
    key_exchange = "Unknown"
    cipher_upper = cipher_name.upper()
    if "ECDHE" in cipher_upper:
        key_exchange = "ECDHE (Elliptic Curve Diffie-Hellman Ephemeral)"
    elif "DHE" in cipher_upper or "EDH" in cipher_upper:
        key_exchange = "DHE (Diffie-Hellman Ephemeral)"
    elif "TLS_AES" in cipher_upper or "TLS_CHACHA" in cipher_upper:
        key_exchange = "X25519 / P-256 (TLS 1.3 Ephemeral)"
    elif "RSA" in cipher_upper:
        key_exchange = "RSA (Static - No Forward Secrecy)"
    elif tls_version == "TLS 1.3":
        key_exchange = "X25519 / P-256 (TLS 1.3 Ephemeral)"

    return {
        "host": hostname,
        "port": port,
        "ipAddress": ip_address,
        "tls": tls_version,
        "cipher": cipher_name,
        "certAlgo": cert_algo,
        "keySize": key_size,
        "issuer": issuer,
        "expiry": expiry_str,
        "daysLeft": days_left,
        "quantumRisk": quantum_risk,
        "sslGrade": ssl_grade,
        "pqcDetected": False,
        "errors": [],
        "subject": subject,
        "serialNumber": serial_number,
        "signatureAlgorithm": sig_algo,
        "validFrom": valid_from_str,
        "keyStrength": key_strength,
        "fingerprint": fingerprint,
        "keyExchange": key_exchange
    }

# ─ 3. Subfinder Subdomain Discovery ──────────────────────────────────────────
@app.route("/api/subfinder-subdomains", methods=["GET"])
def subfinder_subdomains():
    """Use Subfinder (passive) to discover subdomains for a given hostname."""
    hostname = request.args.get("hostname", "").strip()
    if not hostname:
        return jsonify({"error": "hostname is required"}), 400

    # Extract base domain
    parts = hostname.lower().strip().split(".")
    if len(parts) < 2:
        return jsonify({"error": "invalid hostname"}), 400

    two_part_tlds = ["co.in", "org.in", "net.in", "bank.in", "gov.in", "edu.in", "co.uk", "org.uk", "com.au", "ac.in", "nic.in"]
    joined2 = ".".join(parts[-2:])
    joined3 = ".".join(parts[-3:]) if len(parts) >= 3 else ""

    if len(parts) >= 3 and any(tld in joined2 or joined3.endswith("." + tld) for tld in two_part_tlds):
        base_domain = ".".join(parts[-3:])
    else:
        base_domain = ".".join(parts[-2:])

    print(f"[SUBFINDER] Enumerating subdomains for: {base_domain}")

    subdomains = []
    try:
        import subprocess, json as json_mod
        result = subprocess.run(
            [r"C:\tools\subfinder\subfinder.exe", "-d", base_domain, "-silent", "-json"],
            capture_output=True, text=True, timeout=60, shell=False
        )
        if result.returncode == 0 and result.stdout.strip():
            for line in result.stdout.strip().split("\n"):
                try:
                    entry = json_mod.loads(line)
                    sub = (entry.get("host") or entry.get("name") or "").strip().lower()
                    if sub and sub.endswith("." + base_domain) and sub not in subdomains:
                        subdomains.append(sub)
                except Exception:
                    pass
        elif result.stderr:
            print(f"[SUBFINDER] stderr: {result.stderr[:200]}")
    except subprocess.TimeoutExpired:
        print("[SUBFINDER] Timed out after 60s")
        return jsonify({"error": "Subfinder timed out", "subdomains": [], "count": 0}), 200
    except FileNotFoundError:
        print("[SUBFINDER] Binary not found")
        return jsonify({"error": "Subfinder binary not found at C:\\tools\\subfinder\\subfinder.exe", "subdomains": [], "count": 0}), 200
    except Exception as e:
        print(f"[SUBFINDER] Error: {str(e)}")
        return jsonify({"error": f"Subfinder failed: {str(e)}", "subdomains": [], "count": 0}), 200

    subdomains.sort()
    print(f"[SUBFINDER] Found {len(subdomains)} subdomains for {base_domain}")
    return jsonify({"hostname": hostname, "base_domain": base_domain, "subdomains": subdomains, "count": len(subdomains)})

# ─ 4. Store Scan (Fallback Storage) ──────────────────────────────────────────
@app.route("/api/store-scan", methods=["POST"])
def store_scan():
    """Store scan results from frontend fallback paths (SSL Labs, crt.sh, default)."""
    if not check_api_key():
        return jsonify({"error": "Unauthorized — invalid or missing API key"}), 401

    data = request.get_json(force=True, silent=True) or {}
    hostname = (data.get("host") or data.get("hostname") or "").strip()
    port = int(data.get("port", 443))

    if not hostname:
        return jsonify({"error": "hostname is required"}), 400

    try:
        # Normalize field names to match what store_scan_results expects
        scan_payload = {
            "host":               hostname,
            "port":               port,
            "ipAddress":          data.get("ipAddress", ""),
            "tls":                data.get("tls", "TLS 1.2"),
            "cipher":             data.get("cipher", ""),
            "certAlgo":           data.get("certAlgo", "RSA"),
            "keySize":            data.get("keySize", 2048),
            "issuer":             data.get("issuer", "Unknown"),
            "expiry":             data.get("expiry", "Unknown"),
            "validFrom":          data.get("validFrom", "Unknown"),
            "daysLeft":           data.get("daysLeft", -1),
            "quantumRisk":        data.get("quantumRisk", "UNKNOWN"),
            "sslGrade":           data.get("sslGrade", "?"),
            "keyStrength":        data.get("keyStrength", "UNKNOWN"),
            "keyExchange":        data.get("keyExchange", ""),
            "subject":            data.get("subject", ""),
            "serialNumber":       data.get("serialNumber", ""),
            "signatureAlgorithm": data.get("signatureAlgorithm", ""),
            "fingerprint":        data.get("fingerprint", ""),
            "pqcDetected":        data.get("pqcDetected", False),
            "errors":             data.get("errors", []),
            "scan_source":        data.get("scan_source", "frontend-fallback"),
        }

        print(f"\n[STORE-SCAN] Storing fallback scan for {hostname}:{port} (source: {scan_payload['scan_source']})")

        scan_id, host_id = db.store_scan_results(scan_payload, hostname, port)

        print(f"[STORE-SCAN] ✓ Stored — scan_id={scan_id}, host_id={host_id}")

        return jsonify({
            "status":     "stored",
            "scan_id":    str(scan_id),
            "host_id":    str(host_id),
            "hostname":   hostname,
            "db_stored":  True
        })

    except Exception as e:
        print(f"[STORE-SCAN] Error: {e}")
        return jsonify({"error": str(e), "db_stored": False}), 500


# ─ 4. Groq AI Assistant Endpoint ─────────────────────────────────────────────
@app.route("/api/assistant", methods=["POST"])
def ai_assistant():
    """Handles chat requests from the frontend and sends them to Groq."""
    if not check_api_key():
        return jsonify({"error": "Unauthorized"}), 401

    data = request.get_json(force=True, silent=True) or {}
    question = data.get("question", "").strip()
    scan_data = data.get("scan_data", {})

    if not question:
        return jsonify({"error": "Please provide a question."}), 400

    try:
        # 1. Give Groq the context of the scan
        system_context = f"""You are a Post-Quantum Cryptography expert helping a user secure their web assets.
You are currently analyzing this asset: {scan_data.get('host', 'No asset scanned yet')}
Risk Level: {scan_data.get('quantumRisk', 'Unknown')}
Algorithm: {scan_data.get('certAlgo', 'Unknown')} ({scan_data.get('keySize', 'Unknown')}-bit)
Provide a concise, helpful, and highly technical answer based on these exact facts."""

        # 2. Call the Groq API using chat completions
        response = client.chat.completions.create(
            model="llama-3.3-70b-versatile",
            messages=[
                {"role": "system", "content": system_context},
                {"role": "user", "content": question}
            ],
            temperature=0.7,
            max_tokens=1024
        )

        return jsonify({
            "status": "success",
            "answer": response.choices[0].message.content
        })

    except Exception as e:
        return jsonify({"error": f"Groq API Error: {str(e)}"}), 500

# Initialize database
db.init_database()
print(f"[DB] Q-Sentinel MongoDB database initialized")

# ─ 4. Get Last Scan for Host ─────────────────────────────────────────────────
@app.route("/api/last-scan/<hostname>", methods=["GET"])
def get_last_scan(hostname):
    """Get the most recent scan results for a host."""
    if not check_api_key():
        return jsonify({"error": "Unauthorized"}), 401

    try:
        result = db.get_last_scan_for_host(hostname)
        if result:
            return jsonify(result)
        return jsonify({"error": "No scans found for host"}), 404
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ─ 5. Get Scan History ────────────────────────────────────────────────────────
@app.route("/api/history/<hostname>", methods=["GET"])
def get_history(hostname):
    """Get scan history for a host."""
    if not check_api_key():
        return jsonify({"error": "Unauthorized"}), 401

    limit = request.args.get('limit', 10, type=int)
    try:
        history = db.get_scan_history(hostname, limit)
        return jsonify({"hostname": hostname, "history": history})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ─ 6. Get Comprehensive Report ────────────────────────────────────────────────
@app.route("/api/report/<hostname>", methods=["GET"])
def get_report(hostname):
    """Get comprehensive CBOM, PQC risk, and scan report for a host."""
    if not check_api_key():
        return jsonify({"error": "Unauthorized"}), 401

    try:
        report = db.get_comprehensive_report(hostname)
        if report:
            return jsonify(report)
        return jsonify({"error": "No report found for host"}), 404
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ─ 7. Get Dashboard Summary ───────────────────────────────────────────────────
@app.route("/api/dashboard", methods=["GET"])
def get_dashboard():
    """Get dashboard summary statistics."""
    if not check_api_key():
        return jsonify({"error": "Unauthorized"}), 401

    try:
        summary = db.get_dashboard_summary()
        return jsonify(summary)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ─ 8. Get All Hosts ───────────────────────────────────────────────────────────
@app.route("/api/hosts", methods=["GET"])
def get_hosts():
    """Get all registered hosts."""
    if not check_api_key():
        return jsonify({"error": "Unauthorized"}), 401

    try:
        hosts = db.get_all_hosts()
        return jsonify({"hosts": hosts})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ─ 9. Export CBOM ─────────────────────────────────────────────────────────────
@app.route("/api/export/cbom/<hostname>", methods=["GET"])
def export_cbom(hostname):
    """Export CBOM as JSON."""
    if not check_api_key():
        return jsonify({"error": "Unauthorized"}), 401

    try:
        cbom = db.export_cbom_json(hostname)
        if cbom:
            return jsonify(cbom)
        return jsonify({"error": "No CBOM found for host"}), 404
    except Exception as e:
        return jsonify({"error": str(e)}), 500





# ═══════════════════════════════════════════════════════════════
#  USER AUTHENTICATION & MFA ENDPOINTS (MongoDB-Backed)
# ═══════════════════════════════════════════════════════════════

import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

# Load secrets from environment (or VoxShield fallback)
JWT_SECRET = os.environ.get("JWT_SECRET", "voxshield-secure-token-secret-key-2026-xyz")
GMAIL_USER = os.environ.get("GMAIL_USER", "voxshield.auth@gmail.com")
GMAIL_APP_PASS = os.environ.get("GMAIL_APP_PASS", "iakzmohjtwhwxsru")
RESEND_API_KEY = os.environ.get("RESEND_API_KEY", "")

def send_smtp_email(to_email, subject, text_content, html_content):
    """Utility to send an email using Gmail SMTP."""
    try:
        msg = MIMEMultipart('alternative')
        msg['From'] = f'"Q-Sentinel Security" <{GMAIL_USER}>'
        msg['To'] = to_email
        msg['Subject'] = subject

        part1 = MIMEText(text_content, 'plain')
        part2 = MIMEText(html_content, 'html')
        msg.attach(part1)
        msg.attach(part2)

        server = smtplib.SMTP('smtp.gmail.com', 587)
        server.starttls()
        server.login(GMAIL_USER, GMAIL_APP_PASS)
        server.sendmail(GMAIL_USER, to_email, msg.as_string())
        server.quit()
        return True
    except Exception as e:
        print(f"[SMTP ERROR] Failed to send email: {e}")
        return False

def send_email(to_email, subject, text_content, html_content):
    """Send an email using Resend API if key is present, otherwise fallback to SMTP."""
    if RESEND_API_KEY:
        try:
            import urllib.request
            import json
            url = "https://api.resend.com/emails"
            headers = {
                "Authorization": f"Bearer {RESEND_API_KEY}",
                "Content-Type": "application/json"
            }
            data = {
                "from": "Q-Sentinel Security <onboarding@resend.dev>",
                "to": [to_email],
                "subject": subject,
                "text": text_content,
                "html": html_content
            }
            req = urllib.request.Request(
                url,
                data=json.dumps(data).encode("utf-8"),
                headers=headers,
                method="POST"
            )
            with urllib.request.urlopen(req) as response:
                res_data = json.loads(response.read().decode())
                if response.status == 200 or res_data.get("id"):
                    print(f"[EMAIL] Successfully sent email to {to_email} via Resend API.")
                    return True
        except Exception as e:
            print(f"[RESEND ERROR] Failed to send email via Resend, falling back to SMTP: {e}")
            
    return send_smtp_email(to_email, subject, text_content, html_content)

def generate_signed_token(payload, expires_in_seconds=300):
    """Generate a simple signed token resembling a JWT."""
    import time
    import hmac
    payload_copy = payload.copy()
    payload_copy["exp"] = int(time.time()) + expires_in_seconds
    payload_str = json.dumps(payload_copy, sort_keys=True)
    signature = hmac.new(JWT_SECRET.encode(), payload_str.encode(), hashlib.sha256).hexdigest()
    return f"{payload_str}.{signature}"

def verify_signed_token(token):
    """Verify and decode a signed token."""
    import time
    import hmac
    try:
        parts = token.split(".")
        if len(parts) != 2:
            return None
        payload_str, signature = parts[0], parts[1]
        expected_signature = hmac.new(JWT_SECRET.encode(), payload_str.encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(signature, expected_signature):
            return None
        payload = json.loads(payload_str)
        if int(time.time()) > payload.get("exp", 0):
            return None
        return payload
    except Exception:
        return None

def hash_password(password):
    """Hash password using SHA-256 with salt."""
    salt = "qsentinel_salt_2026_"
    return hashlib.sha256((salt + password).encode()).hexdigest()

def seed_default_user():
    """Seed default Q-Sentinel Agent if not exists."""
    try:
        existing = db.get_user("PNB-AGT-1042")
        if not existing:
            hashed = hash_password("pnbbank@2026")
            user_doc = {
                "employeeId": "PNB-AGT-1042",
                "name": "PNB Agent 1042",
                "email": "agent1042@pnb.co.in",
                "password": hashed,
                "mfaSecret": "ABCDEFGHIJKLMNOPQRST", # 20 character base32
                "mfaEnrolled": False,
                "status": "active",
                "otp": {"code": "", "expiresAt": None},
                "loginAttempts": {"count": 0, "lockUntil": None}
            }
            db.save_user(user_doc)
            print("[AUTH] Seeded default agent PNB-AGT-1042 successfully.")
    except Exception as e:
        print(f"[AUTH ERROR] Failed to seed default user: {e}")

# Seed user on init
db.init_database()
seed_default_user()

def is_strong_password(password):
    if len(password) < 8: return False
    has_upper = any(c.isupper() for c in password)
    has_lower = any(c.islower() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_special = any(not c.isalnum() for c in password)
    return has_upper and has_lower and has_digit and has_special

@app.route("/api/auth/register-init", methods=["POST"])
def register_init():
    if not check_api_key():
        return jsonify({"error": "Unauthorized"}), 401

    data = request.get_json(force=True, silent=True) or {}
    name = (data.get("name") or "").strip()
    email = (data.get("email") or "").strip()
    user = (data.get("user") or "").strip()
    pass_val = data.get("pass", "")

    if not name or not email or not user or not pass_val:
        return jsonify({"error": "All fields are required"}), 400

    if not is_strong_password(pass_val):
        return jsonify({"error": "Password must be at least 8 characters long and contain 1 uppercase, 1 lowercase, 1 number, and 1 special character."}), 400

    try:
        existing_user = db.get_user(user)
        if existing_user and existing_user.get("status") == "active":
            return jsonify({"error": "Employee ID is already registered"}), 400

        existing_email = db.get_user_by_email(email)
        if existing_email and existing_email.get("status") == "active":
            return jsonify({"error": "Email address is already registered"}), 400

        hashed_password = hash_password(pass_val)
        otp_code = str(random.randint(100000, 999999))
        otp_expires = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(minutes=5)

        if existing_user:
            existing_user["name"] = name
            existing_user["email"] = email
            existing_user["password"] = hashed_password
            existing_user["otp"] = {"code": otp_code, "expiresAt": otp_expires}
            db.save_user(existing_user)
        else:
            new_user = {
                "employeeId": user,
                "name": name,
                "email": email,
                "password": hashed_password,
                "mfaSecret": "",
                "mfaEnrolled": False,
                "status": "pending",
                "otp": {"code": otp_code, "expiresAt": otp_expires},
                "loginAttempts": {"count": 0, "lockUntil": None}
            }
            db.save_user(new_user)

        # Send Email
        subject = "Q-Sentinel Verification Code"
        text_content = f"Hello Officer,\n\nWelcome to Q-Sentinel!\n\nPlease verify your registration with this OTP: {otp_code}\n\nValid for 5 minutes."
        html_content = f"""
            <div style="font-family: Arial, sans-serif; max-width: 500px; margin: 0 auto; padding: 20px; border: 1px solid #e0e0e0; border-radius: 8px; background-color: #0d0a0b; color: #f5e6d3;">
              <h2 style="color: #e8b84b; text-align: center;">Q-Sentinel Security</h2>
              <hr style="border: none; border-top: 1px solid rgba(232, 184, 75, 0.2); margin: 20px 0;" />
              <p>Hello Officer,</p>
              <p>Please enter the 6-digit One-Time Password (OTP) below to verify your email address and authorize your officer profile creation:</p>
              <div style="background-color: #1a1014; border: 1px solid rgba(232, 184, 75, 0.4); padding: 18px; text-align: center; font-size: 32px; font-weight: bold; letter-spacing: 6px; color: #e8b84b; margin: 24px 0; border-radius: 8px; font-family: monospace;">
                {otp_code}
              </div>
              <p style="font-size: 11px; color: #8a7060; text-align: center;">Punjab National Bank Cybersecurity Division</p>
            </div>
        """
        send_email(email, subject, text_content, html_content)
        db.log_audit_event(user, "REGISTRATION_OTP_SENT", request.remote_addr, f"Verification OTP sent to {email}.")
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/auth/register-verify", methods=["POST"])
def register_verify():
    if not check_api_key():
        return jsonify({"error": "Unauthorized"}), 401

    data = request.get_json(force=True, silent=True) or {}
    user = (data.get("user") or "").strip()
    otp = (data.get("otp") or "").strip()

    if not user or not otp:
        return jsonify({"error": "Employee ID and OTP are required"}), 400

    try:
        db_user = db.get_user(user)
        if not db_user or db_user.get("status") != "pending":
            return jsonify({"error": "No pending registration found for this Employee ID"}), 400

        otp_doc = db_user.get("otp", {})
        expires_at = otp_doc.get("expiresAt")
        if expires_at:
            if expires_at.tzinfo is None:
                expires_at = expires_at.replace(tzinfo=datetime.timezone.utc)

        if otp_doc.get("code") != otp:
            db.log_audit_event(user, "REGISTRATION_OTP_FAILED", request.remote_addr, "Failed OTP entry during registration.")
            return jsonify({"error": "Incorrect verification code"}), 400

        if expires_at < datetime.datetime.now(datetime.timezone.utc):
            db.log_audit_event(user, "REGISTRATION_OTP_EXPIRED", request.remote_addr, "Expired OTP entry attempt.")
            return jsonify({"error": "OTP has expired"}), 400

        # Generate seed
        alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'
        mfa_secret = ''.join(random.choices(alphabet, k=20))
        
        db_user["status"] = "active"
        db_user["mfaSecret"] = mfa_secret
        db_user["mfaEnrolled"] = False
        db_user["otp"] = {"code": "", "expiresAt": None}
        db.save_user(db_user)

        temp_token = generate_signed_token({"employeeId": db_user["employeeId"], "stage": "mfa"})
        db.log_audit_event(user, "REGISTRATION_COMPLETED", request.remote_addr, "Registration completed. Account activated.")

        return jsonify({"success": True, "mfaSecret": mfa_secret, "tempToken": temp_token})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/auth/login-creds", methods=["POST"])
def login_creds():
    if not check_api_key():
        return jsonify({"error": "Unauthorized"}), 401

    data = request.get_json(force=True, silent=True) or {}
    user = (data.get("user") or "").strip()
    pass_val = data.get("pass", "")

    if not user or not pass_val:
        return jsonify({"error": "Employee ID and password are required"}), 400

    try:
        db_user = db.get_user(user)
        if not db_user or db_user.get("status") != "active":
            db.log_audit_event(user, "LOGIN_FAILED", request.remote_addr, "Failed login attempt with unregistered ID.")
            return jsonify({"error": "Invalid Employee ID or password"}), 401

        attempts = db_user.get("loginAttempts", {"count": 0, "lockUntil": None})
        lock_until = attempts.get("lockUntil")
        if lock_until:
            if lock_until.tzinfo is None:
                lock_until = lock_until.replace(tzinfo=datetime.timezone.utc)
            if lock_until > datetime.datetime.now(datetime.timezone.utc):
                remaining_mins = int((lock_until - datetime.datetime.now(datetime.timezone.utc)).total_seconds() / 60)
                return jsonify({"error": f"Account locked. Try again in {remaining_mins + 1} minute(s)."}), 423

        if hash_password(pass_val) != db_user.get("password"):
            count = attempts.get("count", 0) + 1
            if count >= 5:
                db_user["loginAttempts"] = {
                    "count": count,
                    "lockUntil": datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(minutes=15)
                }
                db.save_user(db_user)
                db.log_audit_event(user, "ACCOUNT_LOCKED", request.remote_addr, "Account automatically locked for 15 minutes.")
                return jsonify({"error": "Invalid credentials. Account locked for 15 minutes."}), 423
            else:
                db_user["loginAttempts"] = {"count": count, "lockUntil": None}
                db.save_user(db_user)
                db.log_audit_event(user, "LOGIN_FAILED", request.remote_addr, f"Failed login credential attempt ({count}/5).")
                return jsonify({"error": f"Invalid credentials. ({5 - count} attempt(s) remaining)"}), 401

        # Success
        db_user["loginAttempts"] = {"count": 0, "lockUntil": None}
        db.save_user(db_user)

        temp_token = generate_signed_token({"employeeId": db_user["employeeId"], "stage": "mfa"})
        db.log_audit_event(user, "CREDS_VERIFICATION_SUCCESS", request.remote_addr, "Credentials verified. Awaiting 2FA.")

        return jsonify({
            "success": True,
            "tempToken": temp_token,
            "mfaEnrolled": db_user.get("mfaEnrolled", False),
            "mfaSecret": db_user.get("mfaSecret") if not db_user.get("mfaEnrolled", False) else None
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/auth/login-mfa", methods=["POST"])
def login_mfa_verify():
    if not check_api_key():
        return jsonify({"error": "Unauthorized"}), 401

    data = request.get_json(force=True, silent=True) or {}
    temp_token = data.get("tempToken", "")
    mfa_code = data.get("mfaCode", "")

    if not temp_token or not mfa_code:
        return jsonify({"error": "Temporary session token and MFA code are required"}), 400

    payload = verify_signed_token(temp_token)
    if not payload or payload.get("stage") != "mfa":
        return jsonify({"error": "Temporary login session expired. Please log in again."}), 401

    try:
        user = payload["employeeId"]
        db_user = db.get_user(user)
        if not db_user or db_user.get("status") != "active":
            return jsonify({"error": "User account not found"}), 401

        # Use pyotp to verify TOTP code
        totp = pyotp.TOTP(db_user["mfaSecret"])
        if not totp.verify(mfa_code, valid_window=1):
            db.log_audit_event(user, "MFA_VERIFICATION_FAILED", request.remote_addr, "Failed 2FA Authenticator token match attempt.")
            return jsonify({"error": "Incorrect code. Check your authenticator app."}), 401

        if not db_user.get("mfaEnrolled", False):
            db_user["mfaEnrolled"] = True
            db.save_user(db_user)
            db.log_audit_event(user, "MFA_ENROLLED", request.remote_addr, "Completed initial TOTP authenticator device setup.")

        final_token = generate_signed_token({"employeeId": db_user["employeeId"], "name": db_user["name"], "email": db_user["email"]}, 43200) # 12h
        db.log_audit_event(user, "LOGIN_SUCCESS", request.remote_addr, "User logged in successfully.")

        return jsonify({"success": True, "token": final_token, "user": {"employeeId": db_user["employeeId"], "name": db_user["name"], "email": db_user["email"]}})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/auth/forgot-password", methods=["POST"])
def forgot_password_request():
    if not check_api_key():
        return jsonify({"error": "Unauthorized"}), 401

    data = request.get_json(force=True, silent=True) or {}
    email = (data.get("email") or "").strip()

    if not email:
        return jsonify({"error": "Email is required"}), 400

    try:
        db_user = db.get_user_by_email(email)
        if not db_user or db_user.get("status") != "active":
            return jsonify({"error": "Email address not registered"}), 400

        otp_code = str(random.randint(100000, 999999))
        otp_expires = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(minutes=5)
        db_user["otp"] = {"code": otp_code, "expiresAt": otp_expires}
        db.save_user(db_user)

        subject = "Q-Sentinel Password Reset Code"
        text_content = f"Hello Officer,\n\nYou requested a password reset. OTP: {otp_code}\n\nValid for 5 minutes."
        html_content = f"""
            <div style="font-family: Arial, sans-serif; max-width: 500px; margin: 0 auto; padding: 20px; border: 1px solid #e0e0e0; border-radius: 8px; background-color: #0d0a0b; color: #f5e6d3;">
              <h2 style="color: #e8b84b; text-align: center;">Q-Sentinel Security</h2>
              <hr style="border: none; border-top: 1px solid rgba(232, 184, 75, 0.2); margin: 20px 0;" />
              <p>Hello Officer,</p>
              <p>Please enter the 6-digit verification code below to authorize your password reset:</p>
              <div style="background-color: #1a1014; border: 1px solid rgba(232, 184, 75, 0.4); padding: 18px; text-align: center; font-size: 32px; font-weight: bold; letter-spacing: 6px; color: #e8b84b; margin: 24px 0; border-radius: 8px; font-family: monospace;">
                {otp_code}
              </div>
              <p style="font-size: 11px; color: #8a7060; text-align: center;">Punjab National Bank Cybersecurity Division</p>
            </div>
        """
        send_email(email, subject, text_content, html_content)
        db.log_audit_event(db_user["employeeId"], "PASSWORD_RESET_OTP_SENT", request.remote_addr, "Password reset OTP sent.")
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/auth/reset-password", methods=["POST"])
def reset_password_confirm():
    if not check_api_key():
        return jsonify({"error": "Unauthorized"}), 401

    data = request.get_json(force=True, silent=True) or {}
    email = (data.get("email") or "").strip()
    otp = (data.get("otp") or "").strip()
    new_password = data.get("newPassword", "")

    if not email or not otp or not new_password:
        return jsonify({"error": "All fields are required"}), 400

    if not is_strong_password(new_password):
        return jsonify({"error": "Password must be at least 8 characters long and contain 1 uppercase, 1 lowercase, 1 number, and 1 special character."}), 400

    try:
        db_user = db.get_user_by_email(email)
        if not db_user or db_user.get("status") != "active":
            return jsonify({"error": "User not found"}), 404

        otp_doc = db_user.get("otp", {})
        expires_at = otp_doc.get("expiresAt")
        if expires_at:
            if expires_at.tzinfo is None:
                expires_at = expires_at.replace(tzinfo=datetime.timezone.utc)

        if otp_doc.get("code") != otp:
            db.log_audit_event(db_user["employeeId"], "PASSWORD_RESET_FAILED", request.remote_addr, "Failed OTP reset entry.")
            return jsonify({"error": "Incorrect verification code"}), 400

        if expires_at < datetime.datetime.now(datetime.timezone.utc):
            db.log_audit_event(db_user["employeeId"], "PASSWORD_RESET_EXPIRED", request.remote_addr, "Expired OTP reset entry attempt.")
            return jsonify({"error": "OTP has expired"}), 400

        new_hashed = hash_password(new_password)
        if db_user.get("password") == new_hashed:
            return jsonify({"error": "New password cannot be the same as the old password"}), 400

        db_user["password"] = new_hashed
        db_user["otp"] = {"code": "", "expiresAt": None}
        db.save_user(db_user)
        db.log_audit_event(db_user["employeeId"], "PASSWORD_RESET_SUCCESS", request.remote_addr, "Password reset successfully completed.")
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


if __name__ == "__main__":
    print("\n" + "="*55)
    print("  Q-Sentinel v1.0 Backend + Groq AI")
    print("  URL : http://localhost:5004")
    print("="*55 + "\n")
    app.run(host="0.0.0.0", port=5004, debug=False, use_reloader=False)

