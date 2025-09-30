import os
import uuid
import grpc
import hashlib
import argparse
from typing import List, Tuple
from enum import Enum

import proto.ca_pb2 as pb
import proto.ca_pb2_grpc as pbg
from common.util import (
    hash_to_G2_point,
    g2_to_bytes_jac,
    bytes_to_g2_jac,
    lagrange_coeff,
    bytes_to_g1,
)
from py_ecc.optimized_bls12_381 import (
    G1, multiply, add, pairing
)
from common.cert import Certificate


class RevocationStatus(Enum):
    GOOD = "GOOD"
    REVOKED = "REVOKED"
    UNKNOWN = "UNKNOWN"


def detect_issuer_nodes_and_pk(cert_path: str):
    """Given a PEM cert, detect which CA group issued it and load master_pk + nodes."""
    with open(cert_path, "rb") as f:
        certs = Certificate.from_pem(f.read())
    cert = certs[0] if isinstance(certs, list) else certs

    issuer_cn = cert.issuer_cn
    print(f"[INFO] Cert {cert.subject_cn} issued by {issuer_cn}")

    import re
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

def request_revoke_partials(serial: str, node_addresses: List[str], threshold: int) -> List[Tuple[int, bytes]]:
    """
    Request partial revocation sigs
    """
    msg = f"REVOKE:{serial}".encode()
    print("Revoke digest:", hashlib.sha256(msg).hexdigest())
    parts = []
    for addr in node_addresses:
        print(f"→ contacting {addr} for revocation")
        ch = grpc.insecure_channel(addr)
        stub = pbg.CANodeStub(ch)
        try:
            resp = stub.SignRevokePartial(pb.RevokeRequest(serial=serial), timeout=3)
            print(f"  got response from {addr}: ok={resp.ok}, len={len(resp.partial_sig)}")
            if resp.ok:
                parts.append((resp.node_index, resp.partial_sig))
        except Exception as e:
            print(f"  node failed: {addr}, error={e}")
        if len(parts) >= threshold:
            break
    return parts

def aggregate_threshold(partials: List[Tuple[int, bytes]]):
    idx = [i for (i, _) in partials]
    print("Indices used for interpolation:", idx)
    lambdas = lagrange_coeff(idx)
    g2_pts = [bytes_to_g2_jac(sig_b) for (_, sig_b) in partials]
    agg = None
    for lam, P in zip(lambdas, g2_pts):
        scaled = multiply(P, lam)
        agg = scaled if agg is None else add(agg, scaled)
    return agg

def verify_revoke(serial: str, agg_sig_point, master_pk) -> bool:
    """
    Verify aggregated revoke proof
    """
    msg = f"REVOKE:{serial}".encode()
    msg_point = hash_to_G2_point(msg)
    lhs = pairing(agg_sig_point, G1)
    rhs = pairing(msg_point, master_pk)
    return lhs == rhs


def broadcast_revocation(serial: str, agg_sig_point, node_addresses: List[str]):
    """
    Broadcast aggregated proof
    """
    sig_bytes = g2_to_bytes_jac(agg_sig_point)
    for addr in node_addresses: 
        ch = grpc.insecure_channel(addr)
        stub = pbg.CANodeStub(ch)
        try:
            resp = stub.ApplyRevocation(pb.RevocationProof(
                serial=serial,
                threshold_sig=sig_bytes
            ), timeout=3)
            print(f"{addr} ApplyRevocation:", resp.ok, resp.msg)
        except Exception as e:
            print(f"{addr} ApplyRevocation failed:", e)


def check_revocation_status(serial: str, node_addresses: List[str], threshold: int):
    """
    OCSP Status
    """
    revoked_count, total = 0, len(node_addresses)   # total = all nodes
    responded = 0

    for addr in node_addresses:
        ch = grpc.insecure_channel(addr)
        stub = pbg.CANodeStub(ch)
        try:
            ocsp = stub.OCSP(pb.OCSPRequest(serial=serial), timeout=2)
            responded += 1
            if ocsp.status == pb.OCSPResponse.REVOKED:
                revoked_count += 1
        except Exception:
            pass

    if responded == 0:
        return RevocationStatus.UNKNOWN, revoked_count, total
    if revoked_count >= threshold:
        return RevocationStatus.REVOKED, revoked_count, total
    return RevocationStatus.GOOD, revoked_count, total
    

def perform_revocation(cert_path: str, threshold: int = 2):
    """
    High-level helper
    Perform threshold revocation of the given cert. Returns (ok, msg).
    """
    issuer_level, node_addresses, master_pk = detect_issuer_nodes_and_pk(cert_path)

    certs = Certificate.from_pem(open(cert_path, "rb").read())
    cert = certs[0] if isinstance(certs, list) else certs
    serial = cert.serial

    parts = request_revoke_partials(serial, node_addresses, threshold)
    if len(parts) < threshold:
        return False, "INSUFFICIENT PARTIALS for revocation"

    agg_sig_point = aggregate_threshold(parts)
    print("=== Threshold Revocation Proof ===")
    print(g2_to_bytes_jac(agg_sig_point).hex())

    ok = verify_revoke(serial, agg_sig_point, master_pk)
    print("verify:", ok)
    if not ok:
        return False, "Invalid aggregated revocation proof"

    broadcast_revocation(serial, agg_sig_point, node_addresses)
    status_enum, revoked_count, total = check_revocation_status(serial, node_addresses, threshold)
    return True, f"Revocation completed, final status: {status_enum.value} ({revoked_count}/{total} nodes)"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--revoke", help="Path to PEM file of cert to revoke")
    ap.add_argument("--ocsp", help="Path to PEM file of cert to query status")
    ap.add_argument("--threshold", type=int, default=int(os.getenv("THRESHOLD", "2")))
    args = ap.parse_args()

    if args.revoke:
        ok, msg = perform_revocation(args.revoke, args.threshold)
        print(msg)
        return

    if args.ocsp:
        issuer_level, node_addresses, master_pk = detect_issuer_nodes_and_pk(args.ocsp)
        certs = Certificate.from_pem(open(args.ocsp, "rb").read())
        cert = certs[0] if isinstance(certs, list) else certs
        status, revoked_count, total = check_revocation_status(cert.serial, node_addresses, args.threshold)
        print(f"OCSP status for {cert.subject_cn}: {status.value} ({revoked_count}/{total} nodes)")

        return

    ap.print_help()


if __name__ == "__main__":
    main()

