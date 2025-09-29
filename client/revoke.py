# client/revoke.py

import os
import uuid
import grpc
import hashlib
import sys
from typing import List, Tuple

import proto.ca_pb2 as pb
import proto.ca_pb2_grpc as pbg
from common.util import (
    hash_to_G2_point,
    g2_to_bytes_jac,
    bytes_to_g2_jac,
    lagrange_coeff
)
from py_ecc.optimized_bls12_381 import (
    curve_order as R, G1, multiply, add, pairing
)

# ---------- Env ----------
NODE_ADDRESSES = os.getenv("NODE_ADDRESSES", "ca1:50061,ca2:50062,ca3:50063").split(",")
THRESHOLD = int(os.getenv("THRESHOLD", "2"))

MASTER_PK_HEX = os.getenv("MASTER_PK")
if MASTER_PK_HEX is None:
    try:
        with open("./master_pk.hex") as f:
            MASTER_PK_HEX = f.read().strip()
    except FileNotFoundError:
        MASTER_PK_HEX = None

if MASTER_PK_HEX is None:
    raise RuntimeError("Missing MASTER_PK (env var or ./master_pk.hex)")

from common.util import bytes_to_g1
MASTER_PK = bytes_to_g1(bytes.fromhex(MASTER_PK_HEX))


# ---------- Request partial revocation sigs ----------
def request_revoke_partials(serial: str) -> List[Tuple[int, bytes]]:
    msg = f"REVOKE:{serial}".encode()
    print("Revoke digest:", hashlib.sha256(msg).hexdigest())
    parts = []
    for addr in NODE_ADDRESSES:
        ch = grpc.insecure_channel(addr)
        stub = pbg.CANodeStub(ch)
        try:
            resp = stub.SignRevokePartial(pb.RevokeRequest(serial=serial), timeout=3)
            print("got response from", addr, resp.ok, f"(len={len(resp.partial_sig)})")
            if resp.ok:
                parts.append((resp.node_index, resp.partial_sig))
        except Exception as e:
            print("node failed:", addr, e)
        if len(parts) >= THRESHOLD:
            break
    return parts


# ---------- Aggregate ----------
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


# ---------- Verify ----------
def verify_revoke(serial: str, agg_sig_point) -> bool:
    msg = f"REVOKE:{serial}".encode()
    msg_point = hash_to_G2_point(msg)
    lhs = pairing(agg_sig_point, G1)
    rhs = pairing(msg_point, MASTER_PK)
    return lhs == rhs


# ---------- Broadcast aggregated revocation proof ----------
def broadcast_revocation(serial: str, agg_sig_point):
    sig_bytes = g2_to_bytes_jac(agg_sig_point)
    for addr in NODE_ADDRESSES:
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


# ---------- Query OCSP from all nodes ----------
def query_ocsp(serial: str):
    revoked_count = 0
    for addr in NODE_ADDRESSES:
        ch = grpc.insecure_channel(addr)
        stub = pbg.CANodeStub(ch)
        try:
            ocsp = stub.OCSP(pb.OCSPRequest(serial=serial), timeout=2)
            status_str = "REVOKED" if ocsp.status == pb.OCSPResponse.REVOKED else "GOOD"
            print(f"{addr} reports status: {status_str}")
            if ocsp.status == pb.OCSPResponse.REVOKED:
                revoked_count += 1
        except Exception as e:
            print(f"{addr} OCSP failed:", e)

    if revoked_count >= THRESHOLD:
        print("Final status: REVOKED (t-of-n rule)")
    else:
        print("Final status: GOOD")


# ---------- Main ----------
def main():
    if len(sys.argv) != 2:
        print("Usage: python -m client.revoke <serial>")
        sys.exit(1)

    serial = sys.argv[1]
    parts = request_revoke_partials(serial)
    if len(parts) < THRESHOLD:
        print("INSUFFICIENT PARTIALS for revocation")
        return

    agg_sig_point = aggregate_threshold(parts)

    print("=== Threshold Revocation Proof ===")
    print(g2_to_bytes_jac(agg_sig_point).hex())

    ok = verify_revoke(serial, agg_sig_point)
    print("verify:", ok)
    if not ok:
        print("Invalid aggregated revocation proof — aborting")
        return

    # Broadcast final proof to all nodes
    broadcast_revocation(serial, agg_sig_point)

    # Query OCSP from all nodes (apply t-of-n rule)
    query_ocsp(serial)


if __name__ == "__main__":
    main()
