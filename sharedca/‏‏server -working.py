import os
import grpc
import hashlib
from concurrent import futures

from py_ecc.optimized_bls12_381 import (
    curve_order as R,
    G2, multiply,
    FQ, FQ2
)

import proto.ca_pb2 as pb
import proto.ca_pb2_grpc as pbg

# ---------- Deterministic demo params (use DKG in real system) ----------
SEED_MASTER = b"thresh-demo-master"
SEED_A1     = b"thresh-demo-a1"

def H_to_scalar(seed: bytes) -> int:
    return int.from_bytes(hashlib.sha256(seed).digest(), "big") % R

MASTER_SK = H_to_scalar(SEED_MASTER)
A1        = H_to_scalar(SEED_A1)

def f_eval(i: int) -> int:
    # simple poly: f(x) = MASTER_SK + A1 * x  (t=2 threshold demo)
    return (MASTER_SK + A1 * i) % R

# ---------- Hash-to-curve (simple demo) ----------
def hash_to_G2_point(msg: bytes):
    h = int.from_bytes(hashlib.sha256(msg).digest(), "big") % R
    return multiply(G2, h)

# ---------- Serialization ----------
L = 48  # bytes per FQ element

def fq_to_bytes(x) -> bytes:
    """Serialize FQ or int to 48 bytes."""
    if isinstance(x, int):
        return x.to_bytes(L, "big")
    return int(x.n).to_bytes(L, "big")

def fq2_to_bytes(x: FQ2) -> bytes:
    return fq_to_bytes(x.coeffs[0]) + fq_to_bytes(x.coeffs[1])

def g2_to_bytes_jac(P) -> bytes:
    """Serialize G2 Jacobian point (x,y,z) to 288 bytes."""
    x, y, z = P
    return fq2_to_bytes(x) + fq2_to_bytes(y) + fq2_to_bytes(z)

# ---------- Server config ----------
NODE_ID   = int(os.getenv("NODE_ID", "1"))
GRPC_PORT = os.getenv("GRPC_PORT", "50061")

class CANodeServicer(pbg.CANodeServicer):
    def __init__(self):
        self.index = NODE_ID
        self.sk_i  = f_eval(self.index)  # integer share
        self.crl   = {}

    def SignPartial(self, request, context):
        try:
            msg_point = hash_to_G2_point(request.tbs_cert)     # G2 point
            sig_point = multiply(msg_point, self.sk_i)         # partial in G2
            sig_bytes = g2_to_bytes_jac(sig_point)             # 288 bytes
            return pb.NodeSignResp(ok=True, msg="ok", partial_sig=sig_bytes, node_index=self.index)
        except Exception as e:
            print(f"[Node {self.index}] SignPartial failed:", e)
            return pb.NodeSignResp(ok=False, msg=str(e), partial_sig=b"", node_index=self.index)

    def Revoke(self, request, context):
        self.crl[request.serial] = True
        return pb.RevokeResponse(ok=True, msg="revoked")

    def CRL(self, request, context):
        return pb.CRLResponse(revoked_serials=list(self.crl.keys()), threshold_sig=b"")

    def OCSP(self, request, context):
        status = pb.OCSPResponse.GOOD
        if request.serial in self.crl: status = pb.OCSPResponse.REVOKED
        return pb.OCSPResponse(status=status, threshold_sig=b"")

def serve():
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=10))
    pbg.add_CANodeServicer_to_server(CANodeServicer(), server)
    server.add_insecure_port(f"[::]:{GRPC_PORT}")
    print(f"CA-Node {NODE_ID} listening on {GRPC_PORT}")
    server.start()
    server.wait_for_termination()

if __name__ == "__main__":
    serve()
