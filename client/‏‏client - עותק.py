import os
import uuid
import grpc
from datetime import datetime, timedelta
from typing import List, Tuple

from blspy import PrivateKey, AugSchemeMPL, G1Element, G2Element

from common.crypto_utils import gen_rsa_keypair
from common.cert import Certificate
import proto.ca_pb2 as pb
import proto.ca_pb2_grpc as pbg

from py_ecc.bls import G2ProofOfPossession as bls
from py_ecc.optimized_bls12_381 import add, multiply
from py_ecc.bls.point_compression import decompress_G2, compress_G2

# Configuration from environment
NODE_ADDRESSES = os.getenv("NODE_ADDRESSES", "ca1:50061,ca2:50062,ca3:50063").split(",")
THRESHOLD = int(os.getenv("THRESHOLD", "2"))
CN = os.getenv("CN", "client1")

# Must match server's demo DKG master public key construction
from hashlib import sha256
SEED = b"demo-seed-do-not-use"
BLS12_381_ORDER = 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001

# hash → int → reduce mod group order → back to 32 bytes
master_int = int.from_bytes(sha256(SEED).digest(), "big") % BLS12_381_ORDER
master_s = master_int.to_bytes(32, "big")

MASTER_PK = PrivateKey.from_bytes(master_s).get_g1()

def lagrange_coeff(indices: List[int], at: int = 0) -> List[int]:
    """Compute Lagrange basis l_j(0) over Z_r for given indices"""
    try:
        r = PrivateKey.ORDER
    except AttributeError:
        # fallback to constant for BLS12-381
        r = 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001

    coeffs = []
    for j, xj in enumerate(indices):
        num, den = 1, 1
        for m, xm in enumerate(indices):
            if m == j:
                continue
            num = (num * (-xm % r)) % r
            den = (den * ((xj - xm) % r)) % r
        coeffs.append((num * pow(den, -1, r)) % r)
    return coeffs


def request_partials(tbs: bytes) -> List[Tuple[int, bytes]]:
    """Request partial signatures from CA nodes until threshold is met"""
    print("TBS digest:", sha256(tbs).hexdigest())
    parts = []
    for addr in NODE_ADDRESSES:
        ch = grpc.insecure_channel(addr)
        stub = pbg.CANodeStub(ch)
        try:
            resp = stub.SignPartial(
                pb.NodeSignReq(tbs_cert=tbs, req_id=str(uuid.uuid4())),
                timeout=3
            )
            print("got response from", addr, resp.ok)
            if resp.ok:
                parts.append((resp.node_index, resp.partial_sig))
        except Exception as e:
            print("node failed:", addr, e)
        if len(parts) >= THRESHOLD:
            break
    return parts



def aggregate_threshold(partials):
    """
    partials: List[(node_index:int, sig_bytes:bytes)]
    Returns: aggregated signature as compressed G2 bytes (96 bytes)
    """
    idx = [i for (i, _) in partials]
    lambdas = lagrange_coeff(idx, 0)

    # decompress to G2 points
    g2_points = [decompress_G2(sig_b) for (_, sig_b) in partials]

    # scale each partial by its Lagrange λ_i and add
    agg = None
    for lam, P in zip(lambdas, g2_points):
        scaled = multiply(P, lam)          # scalar * point (works in py_ecc)
        agg = scaled if agg is None else add(agg, scaled)

    # return compressed 96-byte signature
    return compress_G2(agg)


def verify_cert_sig(cert: Certificate, sig: G2Element) -> bool:
    """Verify BLS threshold signature against master public key"""
    try:
        return AugSchemeMPL.verify(MASTER_PK, cert.to_tbs(), sig)
    except Exception:
        return False


def main():
    # Generate subject keypair and CSR
    priv_pem, pub_pem = gen_rsa_keypair()

    # Build TBS certificate locally
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

    # Collect partial signatures
    parts = request_partials(tbs)
    if len(parts) < THRESHOLD:
        print("INSUFFICIENT PARTIALS")
        return

    # Aggregate into full threshold signature
    sig = aggregate_threshold(parts)

    # Attach aggregated signature and export cert
    cert.signature = bytes(sig)
    pem = cert.to_pem()

    print("=== Threshold Cert (client-aggregated) ===")
    print(pem.decode())
    print("verify:", verify_cert_sig(cert, sig))


if __name__ == "__main__":
    main()
