# phase1_scanner/utils.py
# Helper functions — no network calls, just logic

import datetime


def format_timestamp(dt):
    """
    Converts a datetime object into a readable date string
    Example: datetime(2025, 11, 1) → "2025-11-01"
    """
    if dt is None:
        return "Unknown"
    return dt.strftime("%Y-%m-%d")


def days_until_expiry(expiry_date):
    """
    Calculates how many days are left before a certificate expires
    Returns a negative number if already expired
    """
    if expiry_date is None:
        return -1
    now = datetime.datetime.utcnow()
    delta = expiry_date - now
    return delta.days


def classify_key_size(algorithm, key_size):
    """
    Judges whether a cryptographic key size is weak or strong
    against classical (non-quantum) attacks

    RSA / DSA:
      < 2048 bits  → WEAK       (breakable today)
      2048–3071    → ACCEPTABLE (minimum standard)
      3072+        → STRONG

    EC (Elliptic Curve):
      < 256 bits   → WEAK
      256–383      → ACCEPTABLE
      384+         → STRONG
    """
    if algorithm in ["RSA", "DSA"]:
        if key_size < 2048:
            return "WEAK"
        elif key_size < 3072:
            return "ACCEPTABLE"
        else:
            return "STRONG"

    elif algorithm in ["EC", "ECDSA", "ECDH"]:
        if key_size < 256:
            return "WEAK"
        elif key_size < 384:
            return "ACCEPTABLE"
        else:
            return "STRONG"

    else:
        return "UNKNOWN"


def is_pqc_algorithm(algorithm_name):
    """
    Checks if an algorithm is Post-Quantum safe.

    NIST approved 3 standards in 2024:
      FIPS 203 → CRYSTALS-Kyber   (key exchange)
      FIPS 204 → CRYSTALS-Dilithium (digital signatures)
      FIPS 205 → SPHINCS+          (digital signatures)

    Returns True if the algorithm is quantum-safe
    """
    PQC_ALGORITHMS = [
        # FIPS 203 - Key Encapsulation Mechanism
        "kyber",
        "ml-kem",
        "crystals-kyber",
        # FIPS 204 - Digital Signatures
        "dilithium",
        "ml-dsa",
        "crystals-dilithium",
        # FIPS 205 - Digital Signatures
        "sphincs",
        "slh-dsa",
        # Hybrid schemes (classical + PQC combined)
        "x25519kyber768",
        "p256kyber768"
    ]

    alg_lower = algorithm_name.lower()
    return any(pqc in alg_lower for pqc in PQC_ALGORITHMS)


def get_tls_security_level(tls_version):
    """
    Rates a TLS version's security level.

    TLS 1.0 → INSECURE    (banned by NIST, must be disabled)
    TLS 1.1 → DEPRECATED  (also banned, vulnerable to POODLE)
    TLS 1.2 → ACCEPTABLE  (still widely used, some weaknesses)
    TLS 1.3 → RECOMMENDED (best, mandatory forward secrecy)

    score_penalty is added to the quantum risk score later
    """
    levels = {
        "TLSv1":   {"level": "INSECURE",    "score_penalty": 40},
        "TLSv1.1": {"level": "DEPRECATED",  "score_penalty": 30},
        "TLSv1.2": {"level": "ACCEPTABLE",  "score_penalty": 10},
        "TLSv1.3": {"level": "RECOMMENDED", "score_penalty": 0},
    }
    return levels.get(
        tls_version,
        {"level": "UNKNOWN", "score_penalty": 20}
    )