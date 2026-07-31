# phase1_scanner/extractor.py
# Opens a real TLS connection to a target host and extracts
# all certificate and cipher suite data

import ssl
import socket
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa, ec, dsa
from cryptography.hazmat.backends import default_backend

from phase1_scanner.utils import (
    format_timestamp,
    days_until_expiry,
    classify_key_size,
    is_pqc_algorithm
)


def extract_tls_data(hostname, port=443, timeout=10):
    """
    Connects to hostname:port over TLS and returns a dictionary
    containing TLS version, cipher suite, key exchange method,
    and full certificate data.

    This is the function that does the actual network scanning.
    """

    # This is our result — we fill it in as we go
    result = {
        "host":         hostname,
        "port":         port,
        "tls_version":  None,
        "cipher_suite": None,
        "key_exchange": None,
        "certificate":  {},
        "pqc_detected": False,
        "errors":       []
    }

    try:
        # ── STEP 1: Create SSL Context ─────────────────────────────────
        # SSLContext controls how Python makes the TLS connection
        # PROTOCOL_TLS_CLIENT = use the best TLS version available
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)

        # We turn off certificate verification for scanning only
        # This lets us scan any host without needing to trust its CA
        context.check_hostname = False
        context.verify_mode    = ssl.CERT_NONE

        # ── STEP 2: Open TCP connection then wrap it with TLS ──────────
        # create_connection opens a plain TCP socket first
        # wrap_socket then performs the TLS handshake on top of it
        with socket.create_connection(
            (hostname, port),
            timeout=timeout
        ) as raw_socket:

            with context.wrap_socket(
                raw_socket,
                server_hostname=hostname
            ) as tls_socket:

                # ── STEP 3: Read what was negotiated ───────────────────
                # After the TLS handshake we can read:
                # - Which TLS version was used
                # - Which cipher suite was agreed on
                tls_version = tls_socket.version()
                cipher_info = tls_socket.cipher()
                # cipher_info = ("ECDHE-RSA-AES256-GCM-SHA384", "TLSv1.2", 256)
                #                  cipher name                   protocol   bits

                result["tls_version"]  = tls_version
                result["cipher_suite"] = cipher_info[0] if cipher_info else "Unknown"
                result["key_exchange"] = extract_key_exchange(
                    cipher_info[0] if cipher_info else ""
                )

                # ── STEP 4: Get raw certificate bytes ──────────────────
                # binary_form=True gives us the raw DER bytes
                # which we then parse with the cryptography library
                raw_cert = tls_socket.getpeercert(binary_form=True)

        # ── STEP 5: Parse the certificate ─────────────────────────────
        if raw_cert:
            cert_data = parse_certificate(raw_cert)
            result["certificate"] = cert_data

            # Check if the certificate itself uses a PQC algorithm
            sig_algo = cert_data.get("signature_algorithm", "")
            result["pqc_detected"] = is_pqc_algorithm(sig_algo)

    except socket.timeout:
        result["errors"].append(
            f"Connection timed out after {timeout} seconds"
        )

    except socket.gaierror:
        result["errors"].append(
            f"Could not resolve hostname: {hostname}"
        )

    except ConnectionRefusedError:
        result["errors"].append(
            f"Connection refused on port {port}"
        )

    except Exception as e:
        result["errors"].append(
            f"Unexpected error: {str(e)}"
        )

    return result


def parse_certificate(raw_cert_bytes):
    """
    Takes raw DER certificate bytes and returns a clean dictionary
    with all fields required by the CERT-In CBOM specification.

    These fields map directly to Annexure-A in the SRS document.
    """
    try:
        # Load the cert using the cryptography library
        cert = x509.load_der_x509_certificate(
            raw_cert_bytes,
            default_backend()
        )

        # ── Subject Name ───────────────────────────────────────────────
        # WHO this certificate belongs to
        # Example: CN=pnbindia.in, O=Punjab National Bank, C=IN
        subject = cert.subject.rfc4514_string()

        # ── Issuer Name ────────────────────────────────────────────────
        # WHO signed and issued this certificate (the CA)
        # Example: CN=DigiCert SHA2 Secure Server CA
        issuer = cert.issuer.rfc4514_string()

        # ── Validity Dates ─────────────────────────────────────────────
        # When the cert becomes valid and when it expires
        not_before = cert.not_valid_before_utc.replace(tzinfo=None)
        not_after  = cert.not_valid_after_utc.replace(tzinfo=None)

        # ── Signature Algorithm ────────────────────────────────────────
        # The algorithm used to sign this certificate
        # Example: SHA256withRSA, ECDSA-with-SHA384
        try:
            sig_algorithm = (
                cert.signature_hash_algorithm.name
                + "With"
                + type(cert.public_key()).__name__
            )
        except Exception:
            sig_algorithm = str(cert.signature_algorithm_oid)

        # ── Public Key ─────────────────────────────────────────────────
        # Extract key algorithm and size
        public_key = cert.public_key()
        key_info   = extract_key_info(public_key)

        # ── Days Until Expiry ──────────────────────────────────────────
        days_left = days_until_expiry(not_after)

        # Return all fields — these match CERT-In CBOM Annexure-A
        return {
            "asset_type":           "certificate",
            "format":               "X.509",
            "extension":            ".crt",
            "subject_name":         subject,
            "issuer_name":          issuer,
            "not_valid_before":     format_timestamp(not_before),
            "not_valid_after":      format_timestamp(not_after),
            "days_until_expiry":    days_left,
            "signature_algorithm":  sig_algorithm,
            "serial_number":        str(cert.serial_number),
            "public_key_algorithm": key_info["algorithm"],
            "key_size_bits":        key_info["key_size"],
            "key_strength":         key_info["strength"],
        }

    except Exception as e:
        return {
            "error": f"Could not parse certificate: {str(e)}"
        }


def extract_key_info(public_key):
    """
    Reads a public key object and returns its algorithm and size.
    Handles the 3 most common key types: RSA, EC, DSA.
    """
    try:
        # RSA key — most common in banking systems
        if isinstance(public_key, rsa.RSAPublicKey):
            key_size = public_key.key_size
            return {
                "algorithm": "RSA",
                "key_size":  key_size,
                "strength":  classify_key_size("RSA", key_size)
            }

        # EC key — Elliptic Curve, used in modern TLS
        elif isinstance(public_key, ec.EllipticCurvePublicKey):
            key_size = public_key.key_size
            return {
                "algorithm": "EC",
                "key_size":  key_size,
                "strength":  classify_key_size("EC", key_size)
            }

        # DSA key — older, rarely used
        elif isinstance(public_key, dsa.DSAPublicKey):
            key_size = public_key.key_size
            return {
                "algorithm": "DSA",
                "key_size":  key_size,
                "strength":  classify_key_size("DSA", key_size)
            }

        else:
            return {
                "algorithm": type(public_key).__name__,
                "key_size":  0,
                "strength":  "UNKNOWN"
            }

    except Exception:
        return {
            "algorithm": "Unknown",
            "key_size":  0,
            "strength":  "ERROR"
        }


def extract_key_exchange(cipher_name):
    """
    Reads the cipher suite name and identifies the key exchange method.

    Why this matters:
    ECDHE and DHE provide Forward Secrecy — even if the private key
    is stolen later, past sessions cannot be decrypted.
    RSA key exchange has NO forward secrecy — dangerous for HNDL attacks.

    Example cipher name:
    TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
          ↑
          Key exchange method is here
    """
    cipher_upper = cipher_name.upper()

    if "ECDHE" in cipher_upper:
        return "ECDHE (Elliptic Curve Diffie-Hellman Ephemeral)"
    elif "DHE" in cipher_upper or "EDH" in cipher_upper:
        return "DHE (Diffie-Hellman Ephemeral)"
    elif "TLS_AES" in cipher_upper:
        # TLS 1.3 always uses ephemeral keys automatically
        return "X25519 / P-256 (TLS 1.3 Ephemeral)"
    elif "RSA" in cipher_upper:
        return "RSA (Static — No Forward Secrecy)"
    else:
        return f"Unknown ({cipher_name})"