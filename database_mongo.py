# ==============================================================================
# Q-Sentinel MongoDB Database Module
# Stores: Scans, CBOM, PQC Risk, Certificates, Cipher Suites, Scan History
# ==============================================================================

from pymongo import MongoClient
from datetime import datetime, timezone
import json
import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# MongoDB Connection URI
MONGO_URI = os.environ.get("MONGO_URI", "")
DATABASE_NAME = "qentinel"
DATABASE_PATH = DATABASE_NAME  # For compatibility with original code

# Collection names
COLLECTION_HOSTS = "hosts"
COLLECTION_SCANS = "scans"
COLLECTION_CERTIFICATES = "certificates"
COLLECTION_CBOM = "cbom"
COLLECTION_PQC_RISK = "pqc_risk"
COLLECTION_CIPHER_SUITES = "cipher_suites"
COLLECTION_SCAN_HISTORY = "scan_history"
COLLECTION_VULNERABILITIES = "vulnerabilities"
COLLECTION_COMPLIANCE_STATUS = "compliance_status"
COLLECTION_USERS = "users"
COLLECTION_AUDIT_LOGS = "audit_logs"

# Database connection
client = None
db = None


def connect_to_mongo():
    """Connect to MongoDB."""
    global client, db
    try:
        client = MongoClient(MONGO_URI)
        db = client[DATABASE_NAME]
        # Test connection
        client.admin.command('ping')
        print("[DB] Connected to MongoDB successfully")
        return db
    except Exception as e:
        print(f"[DB] MongoDB connection error: {e}")
        raise e


def init_database():
    """Initialize all database collections with indexes."""
    global db
    if db is None:
        connect_to_mongo()

    # Create indexes for faster queries
    db[COLLECTION_HOSTS].create_index("hostname", unique=True)
    db[COLLECTION_HOSTS].create_index("last_scanned")

    db[COLLECTION_SCANS].create_index("host_id")
    db[COLLECTION_SCANS].create_index("scan_timestamp")

    db[COLLECTION_CBOM].create_index("scan_id")
    db[COLLECTION_CBOM].create_index("risk_level")

    db[COLLECTION_PQC_RISK].create_index("risk_level")

    db[COLLECTION_CERTIFICATES].create_index("scan_id")

    db[COLLECTION_SCAN_HISTORY].create_index("host_id")
    
    db[COLLECTION_USERS].create_index("employeeId", unique=True)
    db[COLLECTION_AUDIT_LOGS].create_index("timestamp")

    print("[DB] MongoDB collections and indexes initialized")


# ┌────────────────────────────────────────────────────────┐
# │  Helper Functions                                       │
# └────────────────────────────────────────────────────────┘

def risk_level_to_score(risk):
    """Convert risk level to numeric score for sorting."""
    mapping = {'CRITICAL': 4, 'HIGH': 3, 'MODERATE': 2, 'LOW': 1, 'UNKNOWN': 0}
    return mapping.get(risk.upper(), 0)


# ┌────────────────────────────────────────────────────────┐
# │  Data Insertion Functions                              │
# └────────────────────────────────────────────────────────┘

def store_scan_results(scan_data, hostname, port=443):
    global db
    if db is None:
        init_database()

    # 1. Upsert host
    db[COLLECTION_HOSTS].update_one(
        {"hostname": hostname},
        {"$set": {
            "hostname": hostname,
            "ip_address": scan_data.get('ipAddress'),
            "port": port,
            "last_scanned": datetime.now(timezone.utc),
            "metadata": {}
        }, "$inc": {"total_scans": 1}},
        upsert=True
    )
    host = db[COLLECTION_HOSTS].find_one({"hostname": hostname})
    host_id = host["_id"]

    # 2. Insert scan
    scan_doc = {
        "host_id": host_id,
        "scan_timestamp": datetime.now(timezone.utc),
        "tls_version": scan_data.get('tls'),
        "cipher_suite": scan_data.get('cipher'),
        "ssl_grade": scan_data.get('sslGrade'),
        "quantum_risk": scan_data.get('quantumRisk'),
        "cert_algo": scan_data.get('certAlgo'),
        "key_size": scan_data.get('keySize'),
        "key_strength": scan_data.get('keyStrength'),
        "key_exchange": scan_data.get('keyExchange'),
        "pqc_detected": scan_data.get('pqcDetected', False),
        "days_left": scan_data.get('daysLeft'),
        "errors": scan_data.get('errors', []),
        "raw_response": scan_data
    }
    scan_id = db[COLLECTION_SCANS].insert_one(scan_doc).inserted_id

    # 3. Certificate
    db[COLLECTION_CERTIFICATES].insert_one({
        "scan_id": scan_id, "host_id": host_id,
        "subject": scan_data.get('subject'),
        "issuer": scan_data.get('issuer'),
        "serial_number": scan_data.get('serialNumber'),
        "fingerprint": scan_data.get('fingerprint'),
        "valid_from": scan_data.get('validFrom'),
        "valid_until": scan_data.get('expiry'),
        "signature_algorithm": scan_data.get('signatureAlgorithm'),
        "public_key_algo": scan_data.get('certAlgo'),
        "key_size": scan_data.get('keySize'),
    })

    # 4. CBOM
    cipher = scan_data.get('cipher', '')
    cert_algo = scan_data.get('certAlgo', '')
    key_size = scan_data.get('keySize', 0)
    tls = scan_data.get('tls', '')
    quantum_risk = scan_data.get('quantumRisk', 'UNKNOWN')

    cbom_entries = [
        {
            "scan_id": scan_id, "host_id": host_id,
            "component_type": "cipher",
            "component_name": cipher,
            "algorithm_family": "AES" if "AES" in cipher else "ChaCha20",
            "key_length": key_size,
            "mode": "GCM" if "GCM" in cipher else "CBC",
            "isquantum_safe": "TLS 1.3" in tls,
            "risk_level": quantum_risk,
        },
        {
            "scan_id": scan_id, "host_id": host_id,
            "component_type": "cert",
            "component_name": f"{cert_algo}-{key_size}",
            "algorithm_family": cert_algo,
            "key_length": key_size,
            "isquantum_safe": False,
            "risk_level": quantum_risk,
            "recommendation": "Migrate to PQC hybrid"
        }
    ]
    db[COLLECTION_CBOM].insert_many(cbom_entries)

    # 5. PQC Risk
    pqc_risks = []
    if cert_algo == "RSA" and key_size <= 2048:
        pqc_risks.append({
            "scan_id": scan_id, "host_id": host_id,
            "risk_category": "certificate",
            "risk_name": f"RSA-{key_size} Weak Key",
            "risk_level": "HIGH",
            "description": f"RSA-{key_size} is vulnerable to quantum attacks",
            "mitigation": "Upgrade to RSA-3072 or migrate to PQC hybrid",
        })
    if "TLS 1.3" not in tls:
        pqc_risks.append({
            "scan_id": scan_id, "host_id": host_id,
            "risk_category": "protocol",
            "risk_name": f"{tls} Deprecated Protocol",
            "risk_level": "MODERATE",
            "description": f"{tls} lacks TLS 1.3 security features",
            "mitigation": "Upgrade to TLS 1.3",
        })
    if not pqc_risks:
        pqc_risks.append({
            "scan_id": scan_id, "host_id": host_id,
            "risk_category": "general",
            "risk_name": "PQC Migration Required",
            "risk_level": "MODERATE",
            "description": "Plan migration to post-quantum cryptography",
            "mitigation": "Adopt CRYSTALS-Kyber/Dilithium",
        })
    db[COLLECTION_PQC_RISK].insert_many(pqc_risks)

    # 6. Cipher suite
    db[COLLECTION_CIPHER_SUITES].insert_one({
        "scan_id": scan_id, "host_id": host_id,
        "cipher_name": cipher,
        "key_exchange_algo": scan_data.get('keyExchange'),
        "encryption_algo": "AES" if "AES" in cipher else "ChaCha20",
        "encryption_key_size": key_size,
        "mode": "GCM" if "GCM" in cipher else "CBC",
        "is_forward_secrecy": "ECDHE" in cipher.upper() or "DHE" in cipher.upper(),
        "is_tls13": "TLS 1.3" in tls,
        "quantum_resistant": "TLS 1.3" in tls,
        "risk_level": quantum_risk
    })

    # 7. Scan history
    critical = sum(1 for r in pqc_risks if r['risk_level'] == 'CRITICAL')
    high = sum(1 for r in pqc_risks if r['risk_level'] == 'HIGH')
    db[COLLECTION_SCAN_HISTORY].insert_one({
        "host_id": host_id, "scan_id": scan_id,
        "scan_date": datetime.now(timezone.utc),
        "overall_grade": scan_data.get('sslGrade'),
        "overall_quantum_risk": quantum_risk,
        "total_issues": len(pqc_risks),
        "critical_issues": critical,
        "high_issues": high,
        "medium_issues": sum(1 for r in pqc_risks if r['risk_level'] == 'MODERATE'),
        "low_issues": sum(1 for r in pqc_risks if r['risk_level'] == 'LOW'),
    })

    return scan_id, host_id

def generate_cbom_entries(scan_data):
    """Generate CBOM entries from scan data."""
    entries = []
    cipher = scan_data.get('cipher', '')
    cert_algo = scan_data.get('certAlgo', '')
    key_size = scan_data.get('keySize', 0)
    quantum_risk = scan_data.get('quantumRisk', 'UNKNOWN')

    # Cipher suite entry
    if cipher:
        enc_algo = extract_encryption_algo(cipher)
        entries.append({
            'component_type': 'cipher',
            'component_name': cipher,
            'algorithm_family': enc_algo,
            'key_length': extract_key_length(cipher),
            'mode': extract_mode(cipher),
            'isquantum_safe': 'TLS 1.3' in scan_data.get('tls', ''),
            'risk_level': quantum_risk,
            'vulnerability': get_cipher_vulnerability(cipher),
            'recommendation': get_cipher_recommendation(cipher)
        })

    # Certificate/Key entry
    if cert_algo:
        entries.append({
            'component_type': 'key_exchange' if 'ECDHE' in cipher.upper() else 'certificate',
            'component_name': f"{cert_algo}-{key_size}",
            'algorithm_family': cert_algo,
            'key_length': key_size,
            'curve': get_curve_for_algo(cert_algo, key_size),
            'isquantum_safe': is_quantum_resistant(cert_algo, key_size),
            'risk_level': quantum_risk,
            'vulnerability': get_key_vulnerability(cert_algo, key_size),
            'recommendation': get_key_recommendation(cert_algo, key_size)
        })

    # Key exchange entry
    key_exchange = scan_data.get('keyExchange', '')
    if key_exchange:
        entries.append({
            'component_type': 'kex',
            'component_name': key_exchange,
            'algorithm_family': 'ECDH' if 'EC' in key_exchange else ('DHE' if 'DH' in key_exchange else 'RSA'),
            'isquantum_safe': 'ECDH' in key_exchange and 'P-256' in key_exchange,
            'risk_level': quantum_risk,
            'vulnerability': get_kex_vulnerability(key_exchange),
            'recommendation': get_kex_recommendation(key_exchange)
        })

    return entries


def generate_pqc_risks(scan_data):
    """Generate PQC risk assessments from scan data."""
    risks = []
    tls_version = scan_data.get('tls', '')
    cipher = scan_data.get('cipher', '')
    cert_algo = scan_data.get('certAlgo', '')
    key_size = scan_data.get('keySize', 0)
    quantum_risk = scan_data.get('quantumRisk', 'UNKNOWN')

    # Protocol version risk
    if tls_version in ['SSLv3', 'TLS 1.0', 'TLS 1.1']:
        risks.append({
            'risk_category': 'protocol',
            'risk_name': f'{tls_version} Deprecation',
            'risk_level': 'CRITICAL',
            'description': f'{tls_version} is deprecated and has known vulnerabilities.',
            'impact': 'Sensitive data may be intercepted via POODLE, BEAST, or similar attacks.',
            'mitigation': 'Upgrade to TLS 1.2 minimum, preferably TLS 1.3.',
            'cwe_id': 'CWE-757',
            'nist_level': 'NIST PQC Timeline 2024'
        })

    # Weak key risk
    if cert_algo == 'RSA' and key_size < 2048:
        risks.append({
            'risk_category': 'certificate',
            'risk_name': f'Weak {cert_algo} Key ({key_size}-bit)',
            'risk_level': 'CRITICAL',
            'description': f'{key_size}-bit RSA keys are considered weak and breakable.',
            'impact': 'Cryptographic keys could be broken by quantum computers (CRQC) or current attacks.',
            'mitigation': 'Upgrade to RSA-2048 minimum, RSA-3072 or RSA-4096 recommended.',
            'cwe_id': 'CWE-310',
            'nist_level': 'NIST SP 800-57'
        })
    elif cert_algo == 'RSA' and key_size < 3072:
        risks.append({
            'risk_category': 'certificate',
            'risk_name': f'Moderate {cert_algo} Key ({key_size}-bit)',
            'risk_level': 'MODERATE',
            'description': f'{key_size}-bit RSA provides moderate security but insufficient for long-term.',
            'impact': 'Keys may become vulnerable as computing power increases.',
            'mitigation': 'Plan migration to RSA-3072 or ECC P-384.',
            'cwe_id': 'CWE-310',
            'nist_level': 'NIST SP 800-57 Part 3'
        })

    # CBC mode risk
    if 'CBC' in cipher:
        risks.append({
            'risk_category': 'cipher',
            'risk_name': 'CBC Mode Vulnerability',
            'risk_level': 'HIGH',
            'description': 'CBC mode ciphers are vulnerable to padding oracle attacks.',
            'impact': 'May allow decryption via POODLE, Lucky Thirteen attacks.',
            'mitigation': 'Prefer GCM or ChaCha20-Poly1305 modes.',
            'cwe_id': 'CWE-757',
            'nist_level': 'NIST SP 800-52'
        })

    # RC4 risk
    if 'RC4' in cipher:
        risks.append({
            'risk_category': 'cipher',
            'risk_name': 'RC4 Deprecation',
            'risk_level': 'CRITICAL',
            'description': 'RC4 cipher has multiple known biases and vulnerabilities.',
            'impact': 'Stream cipher biases allow practical plaintext recovery.',
            'mitigation': 'Remove RC4 immediately, use AES-GCM or ChaCha20.',
            'cwe_id': 'CWE-310',
            'nist_level': 'RFC 7465'
        })

    # No forward secrecy risk
    if 'ECDHE' not in cipher.upper() and 'DHE' not in cipher.upper() and 'TLS 1.3' not in tls_version:
        risks.append({
            'risk_category': 'key_exchange',
            'risk_name': 'No Forward Secrecy',
            'risk_level': 'HIGH',
            'description': 'Cipher suite does not provide forward secrecy.',
            'impact': 'Compromised keys can decrypt past communications.',
            'mitigation': 'Use ECDHE or DHE cipher suites.',
            'cwe_id': 'CWE-310',
            'nist_level': 'NIST SP 800-52'
        })

    # Quantum risk assessment
    if quantum_risk in ['CRITICAL', 'HIGH']:
        risks.append({
            'risk_category': 'algorithm',
            'risk_name': 'Quantum Vulnerable Cryptography',
            'risk_level': quantum_risk,
            'description': 'Current cryptography is vulnerable to quantum computing attacks.',
            'impact': 'CRQC (Cryptanalytically Relevant Quantum Computer) can break RSA/ECC.',
            'mitigation': 'Implement PQC hybrid schemes, monitor NIST PQC standards.',
            'cwe_id': 'CWE-327',
            'nist_level': 'NIST PQC Standardization 2024'
        })

    return risks


# ┌────────────────────────────────────────────────────────┐
# │  Query Functions                                       │
# └────────────────────────────────────────────────────────┘

def get_host_by_id(host_id):
    """Get host details by ID."""
    global db
    if db is None:
        init_database()

    host = db[COLLECTION_HOSTS].find_one({"_id": host_id})
    if host:
        host["id"] = str(host["_id"])
        del host["_id"]
    return host


def get_last_scan_for_host(hostname):
    """Get the most recent scan for a host."""
    global db
    if db is None:
        init_database()

    host = db[COLLECTION_HOSTS].find_one({"hostname": hostname})
    if not host:
        return None

    scan = db[COLLECTION_SCANS].find_one(
        {"host_id": host["_id"]},
        sort=[("scan_timestamp", -1)]
    )

    if scan:
        scan["id"] = str(scan["_id"])
        scan["host_id"] = str(scan["host_id"])
        scan["hostname"] = hostname
        scan["ip_address"] = host.get("ip_address")
        del scan["_id"]
    return scan


def get_scan_history(hostname, limit=10):
    """Get scan history for a host."""
    global db
    if db is None:
        init_database()

    host = db[COLLECTION_HOSTS].find_one({"hostname": hostname})
    if not host:
        return []

    history = list(db[COLLECTION_SCAN_HISTORY].find(
        {"host_id": host["_id"]},
        sort=[("scan_date", -1)],
        limit=limit
    ))

    for h in history:
        h["id"] = str(h["_id"])
        h["host_id"] = str(h["host_id"])
        h["scan_id"] = str(h["scan_id"])
        del h["_id"]
    return history


def get_cbom_for_scan(scan_id):
    """Get CBOM entries for a scan."""
    global db
    if db is None:
        init_database()

    cbom = list(db[COLLECTION_CBOM].find({"scan_id": scan_id}))
    for entry in cbom:
        entry["id"] = str(entry["_id"])
        entry["scan_id"] = str(entry["scan_id"])
        entry["host_id"] = str(entry["host_id"])
        del entry["_id"]
    return cbom


def get_pqc_risks_for_scan(scan_id):
    """Get PQC risks for a scan."""
    global db
    if db is None:
        init_database()

    risks = list(db[COLLECTION_PQC_RISK].find({"scan_id": scan_id}))
    for r in risks:
        r["id"] = str(r["_id"])
        r["scan_id"] = str(r["scan_id"])
        r["host_id"] = str(r["host_id"])
        del r["_id"]
    return risks


def get_all_hosts():
    """Get all registered hosts."""
    global db
    if db is None:
        init_database()

    hosts = list(db[COLLECTION_HOSTS].find(sort=[("last_scanned", -1)]))
    for h in hosts:
        h["id"] = str(h["_id"])
        del h["_id"]
    return hosts


def get_comprehensive_report(hostname):
    """Get a comprehensive report for a host including all details."""
    global db
    if db is None:
        init_database()

    # Get latest scan
    last_scan = get_last_scan_for_host(hostname)
    if not last_scan:
        return None

    scan_id = last_scan.get("id") or last_scan.get("_id")
    if isinstance(scan_id, str):
        from bson.objectid import ObjectId
        scan_id = ObjectId(scan_id)

    # Get CBOM
    cbom = get_cbom_for_scan(scan_id)

    # Get PQC Risks
    pqc_risks = get_pqc_risks_for_scan(scan_id)

    # Get certificate
    cert = db[COLLECTION_CERTIFICATES].find_one({"scan_id": scan_id})
    if cert:
        cert["id"] = str(cert["_id"])
        cert["scan_id"] = str(cert["scan_id"])
        cert["host_id"] = str(cert["host_id"])
        del cert["_id"]

    # Get cipher suite
    cipher = db[COLLECTION_CIPHER_SUITES].find_one({"scan_id": scan_id})
    if cipher:
        cipher["id"] = str(cipher["_id"])
        cipher["scan_id"] = str(cipher["scan_id"])
        cipher["host_id"] = str(cipher["host_id"])
        del cipher["_id"]

    # Get history
    history = get_scan_history(hostname, 10)

    # Get total scans for host
    host = db[COLLECTION_HOSTS].find_one({"hostname": hostname})
    total_scans = host.get("total_scans", 0) if host else 0

    return {
        'host': hostname,
        'last_scan': last_scan,
        'certificate': cert,
        'cipher_suite': cipher,
        'cbom': cbom,
        'pqc_risks': pqc_risks,
        'scan_history': history,
        'summary': {
            'total_scans': total_scans,
            'total_cbom_entries': len(cbom),
            'total_pqc_risks': len(pqc_risks),
            'critical_risks': sum(1 for r in pqc_risks if r.get('risk_level') == 'CRITICAL'),
            'high_risks': sum(1 for r in pqc_risks if r.get('risk_level') == 'HIGH')
        }
    }


def get_dashboard_summary():
    """Get summary stats for dashboard."""
    global db
    if db is None:
        init_database()

    stats = {}

    # Total hosts
    stats['total_hosts'] = db[COLLECTION_HOSTS].count_documents({})

    # Total scans
    stats['total_scans'] = db[COLLECTION_SCANS].count_documents({})

    # Risk distribution
    risk_pipeline = [
        {"$group": {"_id": "$quantum_risk", "count": {"$sum": 1}}}
    ]
    risk_results = db[COLLECTION_SCANS].aggregate(risk_pipeline)
    stats['risk_distribution'] = {r['_id']: r['count'] for r in risk_results if r['_id']}

    # Grade distribution
    grade_pipeline = [
        {"$group": {"_id": "$ssl_grade", "count": {"$sum": 1}}}
    ]
    grade_results = db[COLLECTION_SCANS].aggregate(grade_pipeline)
    stats['grade_distribution'] = {g['_id']: g['count'] for g in grade_results if g['_id']}

    # Recent critical risks
    critical_risks = list(db[COLLECTION_PQC_RISK].aggregate([
        {"$match": {"risk_level": {"$in": ["CRITICAL", "HIGH"]}}},
        {"$lookup": {"from": COLLECTION_HOSTS, "localField": "host_id", "foreignField": "_id", "as": "host"}},
        {"$unwind": "$host"},
        {"$lookup": {"from": COLLECTION_SCANS, "localField": "scan_id", "foreignField": "_id", "as": "scan"}},
        {"$unwind": "$scan"},
        {"$project": {"hostname": "$host.hostname", "risk_name": 1, "risk_level": 1, "scan_timestamp": "$scan.scan_timestamp"}},
        {"$sort": {"scan_timestamp": -1}},
        {"$limit": 10}
    ]))
    stats['critical_risks'] = critical_risks

    # PQC-ready hosts (quantum resistant)
    stats['pqc_ready_hosts'] = db[COLLECTION_SCANS].distinct("host_id", {"quantum_risk": "LOW"}).__len__()

    return stats


# ┌────────────────────────────────────────────────────────┐
# │  Helper Functions for CBOM/PQC Generation              │
# └────────────────────────────────────────────────────────┘

def extract_encryption_algo(cipher):
    """Extract encryption algorithm from cipher suite name."""
    cipher = cipher.upper()
    if 'AES' in cipher:
        return 'AES'
    elif 'CHACHA20' in cipher:
        return 'ChaCha20'
    elif 'RC4' in cipher:
        return 'RC4'
    elif '3DES' in cipher or 'DES' in cipher:
        return '3DES'
    return 'UNKNOWN'


def extract_key_length(cipher):
    """Extract key length from cipher suite name."""
    import re
    match = re.search(r'(\d{3})', cipher)
    return int(match.group(1)) if match else 0


def extract_mode(cipher):
    """Extract cipher mode from cipher suite name."""
    cipher = cipher.upper()
    if 'GCM' in cipher:
        return 'GCM'
    elif 'CBC' in cipher:
        return 'CBC'
    elif 'CHACHA20' in cipher:
        return 'ChaCha20-Poly1305'
    elif 'CCM' in cipher:
        return 'CCM'
    return 'UNKNOWN'


def get_curve_for_algo(algo, key_size):
    """Get appropriate curve for algorithm."""
    if algo == 'ECDSA':
        if key_size >= 384:
            return 'P-384'
        elif key_size >= 256:
            return 'P-256'
        return 'P-256'
    return None


def is_quantum_resistant(algo, key_size):
    """Check if algorithm/key is quantum resistant."""
    if algo == 'ECDSA' and key_size >= 384:
        return True
    return False


def get_cipher_vulnerability(cipher):
    """Get known vulnerabilities for cipher."""
    cipher = cipher.upper()
    if 'RC4' in cipher:
        return 'RC4 has multiple known biases (Fluher, Mantin, Shamir)'
    elif 'CBC' in cipher:
        return 'Vulnerable to padding oracle attacks (Lucky Thirteen)'
    elif 'NULL' in cipher or 'EXPORT' in cipher:
        return 'No encryption or weak export cipher'
    return None


def get_cipher_recommendation(cipher):
    """Get recommendation for cipher."""
    cipher = cipher.upper()
    if 'TLS 1.3' in cipher:
        return 'Use TLS 1.3 with AES-256-GCM or ChaCha20-Poly1305'
    elif 'AES' in cipher and 'GCM' in cipher:
        return 'Good choice, ensure TLS 1.2+'
    elif 'CHACHA20' in cipher:
        return 'Good for performance, especially on mobile'
    elif 'CBC' in cipher:
        return 'Consider migrating to GCM mode'
    elif 'RC4' in cipher or '3DES' in cipher:
        return 'Deprecate immediately, upgrade to AES-GCM'
    return 'Review cipher configuration'


def get_key_vulnerability(algo, key_size):
    """Get vulnerability for key algorithm."""
    if algo == 'RSA':
        if key_size < 2048:
            return 'RSA keys <2048 are breakable with current hardware'
        elif key_size < 3072:
            return 'RSA keys <3072 provide insufficient long-term security'
    elif algo == 'ECDSA':
        if key_size < 384:
            return 'ECDSA P-256 provides moderate quantum resistance'
    return None


def get_key_recommendation(algo, key_size):
    """Get recommendation for key algorithm."""
    if algo == 'RSA':
        if key_size < 2048:
            return 'Upgrade to RSA-2048 minimum, prefer RSA-3072 or RSA-4096'
        return 'Plan PQC hybrid migration (RSA + CRYSTALS-Kyber)'
    elif algo == 'ECDSA':
        if key_size < 384:
            return 'Consider P-384 curve for better quantum resistance'
        return 'Good choice, plan PQC hybrid (ECDSA + CRYSTALS-Dilithium)'
    return 'Review key algorithm selection'


def get_kex_vulnerability(key_exchange):
    """Get vulnerability for key exchange."""
    if 'RSA' in key_exchange:
        return 'No forward secrecy, vulnerable to replay attacks'
    elif 'DHE' in key_exchange and '1024' in key_exchange:
        return 'DHE with small DH groups is vulnerable'
    return None


def get_kex_recommendation(key_exchange):
    """Get recommendation for key exchange."""
    if 'X25519' in key_exchange or 'P-256' in key_exchange:
        return 'Good, ensure TLS 1.3 or hybrid PQC (CRYSTALS-Kyber)'
    elif 'ECDH' in key_exchange:
        return 'Good, prefer P-384 for better security'
    elif 'DHE' in key_exchange:
        return 'Acceptable but prefer ECDHE, plan PQC migration'
    elif 'RSA' in key_exchange:
        return 'Migrate to ECDHE with PQC hybrid key encapsulation'
    return 'Review key exchange configuration'


# ┌────────────────────────────────────────────────────────┐
# │  Export Functions                                       │
# └────────────────────────────────────────────────────────┘

def export_cbom_json(hostname):
    """Export CBOM as JSON for a host."""
    report = get_comprehensive_report(hostname)
    if not report:
        return None

    return {
        'export_date': datetime.now(timezone.utc).isoformat(),
        'host': hostname,
        'cbom': report['cbom'],
        'pqc_risks': report['pqc_risks'],
        'summary': report['summary']
    }


def export_full_report_csv(hostname):
    """Export full report as CSV."""
    report = get_comprehensive_report(hostname)
    if not report:
        return None

    rows = []
    for risk in report['pqc_risks']:
        rows.append({
            'hostname': hostname,
            'risk_category': risk.get('risk_category'),
            'risk_name': risk.get('risk_name'),
            'risk_level': risk.get('risk_level'),
            'description': risk.get('description'),
            'mitigation': risk.get('mitigation'),
            'cwe_id': risk.get('cwe_id', ''),
            'scan_date': report['last_scan'].get('scan_timestamp', '')
        })

    return rows


# ┌────────────────────────────────────────────────────────┐
# │  User & Audit Log Helper Functions                      │
# └────────────────────────────────────────────────────────┘

def get_user(employee_id):
    """Find a user by employeeId."""
    global db
    if db is None:
        init_database()
    return db[COLLECTION_USERS].find_one({"employeeId": employee_id})


def get_user_by_email(email):
    """Find an active user by email (case-insensitive)."""
    global db
    if db is None:
        init_database()
    import re
    return db[COLLECTION_USERS].find_one({
        "email": {"$regex": re.compile("^" + re.escape(email.strip()) + "$", re.IGNORECASE)}
    })


def save_user(user_doc):
    """Insert or update a user document."""
    global db
    if db is None:
        init_database()
    if "_id" in user_doc:
        db[COLLECTION_USERS].replace_one({"_id": user_doc["_id"]}, user_doc)
    else:
        db[COLLECTION_USERS].insert_one(user_doc)


def log_audit_event(employee_id, event_type, ip_address, details):
    """Log an event to the audit_logs collection and print to terminal."""
    global db
    if db is None:
        init_database()
    log_doc = {
        "timestamp": datetime.now(timezone.utc),
        "employeeId": employee_id or "GUEST",
        "eventType": event_type,
        "ipAddress": ip_address or "",
        "details": details
    }
    db[COLLECTION_AUDIT_LOGS].insert_one(log_doc)
    print(f"[AUDIT LOG] {event_type} for user {employee_id or 'GUEST'}: {details}")


# ┌────────────────────────────────────────────────────────┐
# │  Main                                                   │
# └────────────────────────────────────────────────────────┘

if __name__ == "__main__":
    print("Initializing Q-Sentinel MongoDB Database...")
    init_database()
    print(f"Database: {DATABASE_NAME}")
    print("\nCollections created:")
    print("  - hosts")
    print("  - scans")
    print("  - certificates")
    print("  - cbom (Cryptographic Bill of Materials)")
    print("  - pqc_risk (PQC Risk Assessments)")
    print("  - cipher_suites")
    print("  - scan_history")
    print("  - vulnerabilities")
    print("  - compliance_status")