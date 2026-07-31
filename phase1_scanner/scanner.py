# phase1_scanner/scanner.py
# The main controller — calls extractor, evaluates results,
# and returns the final structured scan result

import datetime
from phase1_scanner.extractor import extract_tls_data
from phase1_scanner.utils import get_tls_security_level, is_pqc_algorithm


def run_scan(hostname, port=443):
    """
    Runs a complete Phase 1 scan on a given hostname.

    Flow:
      1. Call extractor.py  → get raw TLS + cert data
      2. Evaluate TLS version security level
      3. Check for PQC algorithms
      4. Package everything into final JSON
      5. Return result → ready for Phase 2 CBOM Generator

    This is the only function called from outside this package.
    app.py calls run_scan() directly.
    """

    print(f"\n{'='*50}")
    print(f"  Q-Sentinel | Phase 1 Scanner")
    print(f"  Target : {hostname}:{port}")
    print(f"  Time   : {datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC")
    print(f"{'='*50}")

    # ── STEP 1: Run the extractor ──────────────────────────────────────
    print(f"\n[1/4] Connecting to {hostname}:{port}...")
    raw_data = extract_tls_data(hostname, port)

    # ── STEP 2: Check for errors ───────────────────────────────────────
    if raw_data["errors"]:
        print(f"[!]   Errors found: {raw_data['errors']}")
    else:
        print(f"[OK]  Connection successful")

    # ── STEP 3: Evaluate TLS version ──────────────────────────────────
    print(f"\n[2/4] Evaluating TLS configuration...")
    tls_version  = raw_data.get("tls_version", "Unknown")
    tls_security = get_tls_security_level(tls_version)

    print(f"[OK]  TLS Version   : {tls_version}")
    print(f"[OK]  Security Level: {tls_security['level']}")
    print(f"[OK]  Score Penalty : +{tls_security['score_penalty']}")

    # ── STEP 4: Read cipher suite ──────────────────────────────────────
    cipher       = raw_data.get("cipher_suite", "Unknown")
    key_exchange = raw_data.get("key_exchange",  "Unknown")
    print(f"[OK]  Cipher Suite  : {cipher}")
    print(f"[OK]  Key Exchange  : {key_exchange}")

    # ── STEP 5: Read certificate data ─────────────────────────────────
    print(f"\n[3/4] Reading certificate...")
    cert = raw_data.get("certificate", {})

    if "error" in cert:
        print(f"[!]   Certificate error: {cert['error']}")
    elif cert:
        print(f"[OK]  Subject       : {cert.get('subject_name','?')[:70]}")
        print(f"[OK]  Issuer        : {cert.get('issuer_name','?')[:70]}")
        print(f"[OK]  Valid Until   : {cert.get('not_valid_after','?')} "
              f"({cert.get('days_until_expiry','?')} days left)")
        print(f"[OK]  Key Algorithm : {cert.get('public_key_algorithm','?')} "
              f"{cert.get('key_size_bits','?')}-bit "
              f"[{cert.get('key_strength','?')}]")

    # ── STEP 6: PQC detection ──────────────────────────────────────────
    print(f"\n[4/4] Checking for Post-Quantum Cryptography...")
    pqc_detected = raw_data.get("pqc_detected", False)

    if pqc_detected:
        print(f"[OK]  PQC DETECTED — This asset uses quantum-safe algorithms")
    else:
        print(f"[!!]  NO PQC DETECTED — Vulnerable to quantum attacks (HNDL risk)")

    # ── STEP 7: Build the final result dictionary ──────────────────────
    # This is what gets returned to app.py and sent as JSON response
    scan_result = {

        "scan_metadata": {
            "host":      hostname,
            "port":      port,
            "scan_time": datetime.datetime.utcnow().isoformat(),
            "scanner":   "Q-Sentinel v1.0",
            "phase":     "Phase 1 - Cryptographic Asset Discovery",
            "status":    "ERROR" if raw_data["errors"] else "SUCCESS"
        },

        "tls_info": {
            "version":        tls_version,
            "security_level": tls_security["level"],
            "score_penalty":  tls_security["score_penalty"],
            "cipher_suite":   cipher,
            "key_exchange":   key_exchange,
        },

        "certificate": cert,

        "pqc_detected": pqc_detected,

        "errors": raw_data["errors"]
    }

    print(f"\n{'='*50}")
    print(f"  Scan Complete — Status: {scan_result['scan_metadata']['status']}")
    print(f"{'='*50}\n")

    return scan_result
