import os
import uuid
import grpc
import hashlib
from datetime import datetime, timedelta
from typing import List, Tuple

from common.crypto_utils import gen_rsa_keypair
from common.cert import Certificate
import proto.ca_pb2 as pb
import proto.ca_pb2_grpc as pbg

from py_ecc.optimized_bls12_381 import (
    curve_order as R,
    G1, G2, multiply, add, pairing,
    FQ, FQ2
)

# ---------- Demo params ----------
SEED_MASTER = b"thresh-demo-master"
SEED_A1     = b"thresh-demo-a1"

def H_to_scalar(seed: bytes) -> int:
    return int.from_bytes(hashlib.sha256(seed).digest(), "big") % R

MASTER_SK = H_to_scalar(SEED_MASTER)
A1        = H_to_scalar(SEED_A1)
MASTER_PK = multiply(G1, MASTER_SK)

# ---------- Hash-to-curve ----------
def hash_to_G2_point(msg: bytes):
    h = int.from_bytes(hashlib.sha256(msg).digest(), "big") % R
    return multiply(G2, h)

# ---------- Serialization ----------
L = 48

def fq_to_bytes(x) -> bytes:
    if isinstance(x, int):
        return x.to_bytes(L, "big")
    return int(x.n).to_bytes(L, "big")

def fq2_to_bytes(x: FQ2) -> bytes:
    return fq_to_bytes(x.coeffs[0]) + fq_to_bytes(x.coeffs[1])

def g2_to_bytes_jac(P) -> bytes:
    x, y, z = P
    return fq2_to_bytes(x) + fq2_to_bytes(y) + fq2_to_bytes(z)

def bytes_to_fq(b: bytes) -> FQ:
    return FQ(int.from_bytes(b, "big"))

def bytes_to_fq2(b: bytes) -> FQ2:
    return FQ2([bytes_to_fq(b[:L]), bytes_to_fq(b[L:2*L])])

def bytes_to_g2_jac(b: bytes):
    if len(b) != 6*L:
        raise ValueError(f"Expected 288 bytes, got {len(b)}")
    x = bytes_to_fq2(b[0:2*L])
    y = bytes_to_fq2(b[2*L:4*L])
    z = bytes_to_fq2(b[4*L:6*L])
    return (x, y, z)

# ---------- Lagrange coefficients ----------
def lagrange_coeff(indices: List[int]) -> List[int]:
    coeffs = []
    for j, xj in enumerate(indices):
        num, den = 1, 1
        for m, xm in enumerate(indices):
            if m == j:
                continue
            num = (num * (-xm % R)) % R
            den = (den * ((xj - xm) % R)) % R
        coeffs.append((num * pow(den, -1, R)) % R)
    return coeffs

# ---------- Env ----------
NODE_ADDRESSES = os.getenv("NODE_ADDRESSES", "ca1:50061,ca2:50062,ca3:50063").split(",")
THRESHOLD = int(os.getenv("THRESHOLD", "2"))
CN        = os.getenv("CN", "client1")

def request_partials(tbs: bytes) -> List[Tuple[int, bytes]]:
    print("TBS digest:", hashlib.sha256(tbs).hexdigest())
    parts = []
    for addr in NODE_ADDRESSES:
        ch = grpc.insecure_channel(addr)
        stub = pbg.CANodeStub(ch)
        try:
            resp = stub.SignPartial(pb.NodeSignReq(tbs_cert=tbs, req_id=str(uuid.uuid4())), timeout=3)
            print("got response from", addr, resp.ok, f"(len={len(resp.partial_sig)})")
            if resp.ok:
                parts.append((resp.node_index, resp.partial_sig))
        except Exception as e:
            print("node failed:", addr, e)
        if len(parts) >= THRESHOLD:
            break
    return parts

def aggregate_threshold(partials: List[Tuple[int, bytes]]):
    idx = [i for (i, _) in partials]
    lambdas = lagrange_coeff(idx)
    g2_pts = [bytes_to_g2_jac(sig_b) for (_, sig_b) in partials]
    agg = None
    for lam, P in zip(lambdas, g2_pts):
        scaled = multiply(P, lam)
        agg = scaled if agg is None else add(agg, scaled)
    return agg

def verify_cert_sig(cert: Certificate, agg_sig_point) -> bool:
    msg_point = hash_to_G2_point(cert.to_tbs())
    lhs = pairing(agg_sig_point, G1)
    rhs = pairing(msg_point, MASTER_PK)
    return lhs == rhs

def main():
    # Subject keypair + TBS cert
    _, pub_pem = gen_rsa_keypair()
    now = datetime.utcnow()
    cert = Certificate(
        serial=str(uuid.uuid4()),
        subject_cn=CN,
        issuer_cn="ThreshRoot",
        not_before=now,
        not_after=now + timedelta(days=365),
        subject_pub_pem=pub_pem,
    )
    tbs = cert.to_tbs()

    parts = request_partials(tbs)
    if len(parts) < THRESHOLD:
        print("INSUFFICIENT PARTIALS")
        return

    agg_sig_point = aggregate_threshold(parts)
    cert.signature = g2_to_bytes_jac(agg_sig_point)  # safe serialization

    pem = cert.to_pem()
    print("=== Threshold Cert (client-aggregated) ===")
    print(pem.decode())

    ok = verify_cert_sig(cert, agg_sig_point)
    print("verify:", ok)

if __name__ == "__main__":
    main()
