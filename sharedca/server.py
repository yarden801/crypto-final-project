import os, json, hashlib, grpc
from concurrent import futures
from py_ecc.optimized_bls12_381 import (
    G1, G2, multiply, curve_order as R, FQ, FQ2, pairing
)
import proto.ca_pb2 as pb
import proto.ca_pb2_grpc as pbg
from common.util import bytes_to_g2_jac, bytes_to_g1

L = 48

def fq_to_bytes(x): return int(x if isinstance(x, int) else x.n).to_bytes(L, "big")
def fq2_to_bytes(x): return fq_to_bytes(x.coeffs[0]) + fq_to_bytes(x.coeffs[1])
def g2_to_bytes_jac(P): 
    x, y, z = P
    return fq2_to_bytes(x) + fq2_to_bytes(y) + fq2_to_bytes(z)

def hash_to_G2_point(msg: bytes):
    h = int.from_bytes(hashlib.sha256(msg).digest(), "big") % R
    return multiply(G2, h)

CONFIG_PATH = os.getenv("CONFIG_PATH", "node_config/node1.json")
with open(CONFIG_PATH) as f:
    cfg = json.load(f)

NODE_ID   = cfg["node_id"]
SK_SHARE  = cfg["share"]
LEVEL     = cfg.get("level", 1)  # default 1 if missing
THRESHOLD = cfg["threshold"]

# Load correct master public key for this level
with open(f"level{LEVEL}_master_pk.hex") as f:
    MASTER_PK = bytes_to_g1(bytes.fromhex(f.read().strip()))

GRPC_PORT = os.getenv("GRPC_PORT", f"5006{NODE_ID}")

class CANodeServicer(pbg.CANodeServicer):
    def __init__(self):
        self.index = NODE_ID
        self.sk_i  = SK_SHARE
        self.crl   = {}

    def SignPartial(self, request, context):
        try:
            msg_point = hash_to_G2_point(request.tbs_cert)
            sig_point = multiply(msg_point, self.sk_i)
            sig_bytes = g2_to_bytes_jac(sig_point)
            return pb.NodeSignResp(ok=True, msg="ok", partial_sig=sig_bytes, node_index=self.index)
        except Exception as e:
            return pb.NodeSignResp(ok=False, msg=str(e), partial_sig=b"", node_index=self.index)

    def SignRevokePartial(self, request, context):
        try:
            serial = request.serial
            msg = f"REVOKE:{serial}".encode()
            msg_point = hash_to_G2_point(msg)
            sig_point = multiply(msg_point, self.sk_i)
            sig_bytes = g2_to_bytes_jac(sig_point)
            self.crl[serial] = True
            return pb.NodeSignResp(ok=True, msg="ok", partial_sig=sig_bytes, node_index=self.index)
        except Exception as e:
            print(f"[Node {self.index}] SignRevokePartial failed:", e)
            return pb.NodeSignResp(ok=False, msg=str(e), partial_sig=b"", node_index=self.index)

    def Revoke(self, request, context):
        self.crl[request.serial] = True
        return pb.RevokeResponse(ok=True, msg="revoked")

    def CRL(self, request, context):
        return pb.CRLResponse(revoked_serials=list(self.crl.keys()), threshold_sig=b"")

    def OCSP(self, request, context):
        status = pb.OCSPResponse.GOOD
        if request.serial in self.crl:
            status = pb.OCSPResponse.REVOKED
        return pb.OCSPResponse(status=status, threshold_sig=b"")

    def ApplyRevocation(self, request, context):
        try:
            agg = bytes_to_g2_jac(request.threshold_sig)
            msg = f"REVOKE:{request.serial}".encode()
            msg_point = hash_to_G2_point(msg)
            if pairing(agg, G1) == pairing(msg_point, MASTER_PK):
                self.crl[request.serial] = True
                return pb.RevokeResponse(ok=True, msg="revocation applied")
            else:
                return pb.RevokeResponse(ok=False, msg="invalid threshold revocation proof")
        except Exception as e:
            return pb.RevokeResponse(ok=False, msg=str(e))

def serve():
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=10))
    pbg.add_CANodeServicer_to_server(CANodeServicer(), server)
    server.add_insecure_port(f"[::]:{GRPC_PORT}")
    print(f"CA-Node {NODE_ID} (level {LEVEL}) listening on {GRPC_PORT}")
    server.start()
    server.wait_for_termination()

if __name__ == "__main__":
    serve()
