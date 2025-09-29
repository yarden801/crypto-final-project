import os
import grpc
from concurrent import futures
from typing import Dict
from hashlib import sha256

from blspy import PrivateKey, G2Element

import proto.ca_pb2 as pb
import proto.ca_pb2_grpc as pbg


# === Config from environment ===
NODE_ID = int(os.getenv("NODE_ID", "2")) 
GRPC_PORT = int(os.getenv("GRPC_PORT", "50061"))

# Demo key setup (deterministic from seed; not secure)
SEED = b"demo-seed-do-not-use"
BLS12_381_ORDER = 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001
master_int = int.from_bytes(sha256(SEED).digest(), "big") % BLS12_381_ORDER
master_s = master_int.to_bytes(32, "big")
MASTER_PK = PrivateKey.from_bytes(master_s).get_g1()


def f_eval(i: int) -> int:
    """
    Very simple polynomial eval for demo: f(i) = master_int * i (mod r).
    In real DKG, this would be a Shamir secret share.
    """
    return (master_int * i) % BLS12_381_ORDER


class CANodeServicer(pbg.CANodeServicer):
    def __init__(self):
        # each node i holds sk_i = f(i)
        self.index = NODE_ID
        s_i = f_eval(self.index)
        self.sk_i = PrivateKey.from_bytes(s_i.to_bytes(32, "big"))
        # CRL replicated in-memory for demo
        self.crl: Dict[str, bool] = {}
        self.issuer_cn = "ThreshRoot"

    def SignPartial(self, request, context):
        try:
            # partial signature: sig_i = H(m)^{s_i}
            from blspy import AugSchemeMPL
            sig_i = AugSchemeMPL.sign(self.sk_i, request.tbs_cert)
            return pb.NodeSignResp(
                ok=True, msg="ok", partial_sig=bytes(sig_i), node_index=self.index
            )
        except Exception as e:
            print(f"[Node {self.index}] SignPartial failed: {e}")
            return pb.NodeSignResp(
                ok=False, msg=str(e), partial_sig=b"", node_index=self.index
            )


    def Revoke(self, request, context):
        self.crl[request.serial] = True
        return pb.RevokeResponse(ok=True, msg="revoked")

    def CRL(self, request, context):
        # For demo, we don't threshold-sign the CRL here
        return pb.CRLResponse(revoked_serials=list(self.crl.keys()), threshold_sig=b"")

    def OCSP(self, request, context):
        status = pb.OCSPResponse.GOOD
        if request.serial in self.crl:
            status = pb.OCSPResponse.REVOKED
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
