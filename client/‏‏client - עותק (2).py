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

from py_ecc.bls import G2ProofOfPossession as bls
from py_ecc.optimized_bls12_381 import curve_order, G1, multiply


# Config
NODE_ADDRESSES = os.getenv("NODE_ADDRESSES", "ca1:50061,ca2:50062,ca3:50063").split(",")
THRESHOLD = int(os.getenv("THRESHOLD", "2"))
CN = os.getenv("CN", "client1")

MASTER_SK = 123456789 % curve_order
MASTER_PK = multiply(G1, MASTER_SK)  # public key in G1


def lagrange_coeff(indices: List[int], at: int = 0) -> List[int]:
    r = curve_order
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
    print("TBS digest:", hashlib.sha256(tbs).hexdigest())
    parts = []
    for addr in NODE_ADDRESSES:
        ch = grpc.insecure_channel(addr)
        stub = pbg.CANodeStub(ch)
        try:
            resp = stub.SignPartial(
                pb.NodeSignReq(tbs_cert=tbs, req_id=str(uuid.uuid4())), timeout=3
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
    Combine partial signatures using Lagrange coefficients at 0.
    Each partial is 96-byte compressed (BLS.Sign).
    """
    idx = [i for (i, _) in partials]
    lambdas = lagrange_coeff(idx, 0)

    # Deserialize each partial
    sigs = [bls.Signature.from_bytes(s) for (_, s) in partials]

    # Scale each partial by lambda and add
    agg = None
    for lam, sig in zip(lambdas, sigs):
        scaled = sig * lam
        agg = scaled if agg is None else agg + scaled

    return bytes(agg)


def verify_cert_sig(cert, agg_sig_bytes):
    try:
        return bls.Verify(MASTER_PK, cert.to_tbs(), agg_sig_bytes)
    except Exception as e:
        print("verify failed:", e)
        return False


def main():
    priv_pem, pub_pem = gen_rsa_keypair()
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

    sig = aggregate_threshold(parts)
    cert.signature = sig
    pem = cert.to_pem()

    print("=== Threshold Cert (client-aggregated) ===")
    print(pem.decode())
    print("verify:", verify_cert_sig(cert, sig))


if __name__ == "__main__":
    main()
