import argparse
import os
import re
import hashlib
from datetime import datetime

import grpc
from py_ecc.optimized_bls12_381 import pairing, G1, FQ, G2, multiply

from common.cert import Certificate
from common.util import bytes_to_g1, bytes_to_g2_jac
from client.revoke import check_revocation_status, RevocationStatus


# Crypto helpers 

def hash_to_G2_point(msg: bytes):
    h = int.from_bytes(hashlib.sha256(msg).digest(), "big") % G2[0].field_modulus
    return multiply(G2, h)


def verify_cert_sig(cert: Certificate, sig_point, issuer_pk):
    msg_point = hash_to_G2_point(cert.to_tbs())
    lhs = pairing(sig_point, G1)
    rhs = pairing(msg_point, issuer_pk)
    return lhs == rhs


def extract_bls_pubkey(cert: Certificate):
    if not cert.subject_pub_pem.startswith(b"BLS-PUBKEY:"):
        raise RuntimeError(f"Cert {cert.subject_cn} pubkey is not BLS")
    pk_bytes = cert.subject_pub_pem[len(b"BLS-PUBKEY:") :]
    pt = bytes_to_g1(pk_bytes)
    return (pt[0], pt[1], FQ.one())  # Jacobian form


def verify_chain(cert_list, trust_anchor_pk=None):
    for i in range(len(cert_list) - 1):
        child, parent = cert_list[i], cert_list[i + 1]
        sig_point = bytes_to_g2_jac(child.signature)
        issuer_pk = extract_bls_pubkey(parent)
        if not verify_cert_sig(child, sig_point, issuer_pk):
            return False, f"FAIL: {child.subject_cn} not signed by {parent.subject_cn}"

    root = cert_list[-1]
    sig_point = bytes_to_g2_jac(root.signature)
    if trust_anchor_pk:
        if not verify_cert_sig(root, sig_point, trust_anchor_pk):
            return False, "FAIL: Root not signed by trusted anchor"
    else:
        issuer_pk = extract_bls_pubkey(root)
        if not verify_cert_sig(root, sig_point, issuer_pk):
            return False, "FAIL: Root self-signature invalid"
    return True, "Full chain verified"


def get_nodes_for_issuer(issuer_cn: str):
    m = re.search(r"Level(\d+)CA", issuer_cn)
    if not m:
        raise RuntimeError(f"Cannot parse issuer level from {issuer_cn}")
    issuer_level = int(m.group(1))
    env_key = f"LEVEL{issuer_level}_NODES"
    node_addresses = os.getenv(env_key, "").split(",")
    if not node_addresses or node_addresses == [""]:
        raise RuntimeError(f"No nodes found for {env_key}")
    pk_file = f"level{issuer_level}_master_pk.hex"
    with open(pk_file) as f:
        hexpk = f.read().strip()
    master_pk = bytes_to_g1(bytes.fromhex(hexpk))
    return issuer_level, node_addresses, master_pk


def is_valid_chain(cert_path: str, trust_anchor_pk, threshold: int = 2):
    """
    Full validator
    """
    with open(cert_path, "rb") as f:  
        certs = Certificate.from_pem(f.read())
    certs = certs if isinstance(certs, list) else [certs]

    now = datetime.utcnow()
    overall_ok = True
    messages = []

    # 1. Signature checks
    ok, msg = verify_chain(certs, trust_anchor_pk)
    if not ok:
        overall_ok = False
        messages.append(f"Signature check failed: {msg}")
    else:
        messages.append("Signatures valid")

    # 2. Validity dates
    for cert in certs:
        if not (cert.not_before <= now <= cert.not_after):
            overall_ok = False
            messages.append(f"{cert.subject_cn} expired/not yet valid "
                            f"({cert.not_before} → {cert.not_after})")
        else:
            messages.append(f"{cert.subject_cn} validity ok")

    # 3. Revocation (skip root)
    for cert in certs[:-1]:
        issuer_level, node_addresses, master_pk = get_nodes_for_issuer(cert.issuer_cn)
        status, revoked_count, total = check_revocation_status(cert.serial, node_addresses, threshold)
        if status == RevocationStatus.REVOKED:
            overall_ok = False
            messages.append(f"{cert.subject_cn} is revoked ({revoked_count}/{total} nodes)")
        elif status == RevocationStatus.UNKNOWN:
            overall_ok = False
            messages.append(f"Revocation status unknown for {cert.subject_cn}")
        else:
            messages.append(f"{cert.subject_cn} not revoked ({revoked_count}/{total} nodes)")

    summary = "Cert is valid" if overall_ok else "Cert is INVALID"
    return overall_ok, messages, summary


def main():
    ap = argparse.ArgumentParser(description="Validate a certificate chain fully")
    ap.add_argument("cert_path", help="Path to PEM file containing cert + chain")
    ap.add_argument("--threshold", type=int, default=2, help="Revocation threshold (t in t-of-n)")
    ap.add_argument("--trust-anchor", required=True, help="Path to master_pk.hex of trusted root")
    ap.add_argument("--verify-only", action="store_true",
                    help="Only verify signatures (skip revocation checks)")
    args = ap.parse_args()

    with open(args.trust_anchor) as f:
        hexpk = f.read().strip()
    trust_anchor_pk = bytes_to_g1(bytes.fromhex(hexpk))

    # Fast path- only verify signatures
    if args.verify_only:
        with open(args.cert_path, "rb") as f:
            certs = Certificate.from_pem(f.read())
        certs = certs if isinstance(certs, list) else [certs]
        ok, msg = verify_chain(certs, trust_anchor_pk)
        print(msg)
        return

    # Full validation
    ok, messages, summary = is_valid_chain(args.cert_path, trust_anchor_pk, args.threshold)
    print("\n".join(messages))
    print("----")
    print(summary)


if __name__ == "__main__":
    main()

