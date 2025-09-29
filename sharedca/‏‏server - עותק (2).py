import os
import grpc
from concurrent import futures
from py_ecc.bls import G2ProofOfPossession as bls
from py_ecc.optimized_bls12_381 import curve_order

import proto.ca_pb2 as pb
import proto.ca_pb2_grpc as pbg

# Demo master secret (replace with real DKG in production)
MASTER_SK = 123456789 % curve_order


def f_eval(i: int) -> int:
    """
    Shamir-like polynomial f(i) with f(0) = MASTER_SK.
    For simplicity: f(x) = MASTER_SK + a1*x mod r
    """
    a1 = 987654321 % curve_order
    return (MASTER_SK + a1 * i) % curve_order


NODE_ID = int(os.getenv("NODE_ID", "1"))
GRPC_PORT = os.getenv("GRPC_PORT", "50061")


class CANodeServicer(pbg.CANodeServicer):
    def __init__(self):
        self.index = NODE_ID
        self.sk_i = f_eval(self.index)  # integer share
        self.crl = {}

    def SignPartial(self, request, context):
        try:
            # Partial signature with this node’s share
            sig_bytes = bls.Sign(self.sk_i, request.tbs_cert)

            return pb.NodeSignResp(
                ok=True,
                msg="ok",
                partial_sig=sig_bytes,  # already 96 bytes
                node_index=self.index,
            )
        except Exception as e:
            print(f"[Node {self.index}] SignPartial failed:", e)
            import traceback; traceback.print_exc()
            return pb.NodeSignResp(
                ok=False,
                msg=str(e),
                partial_sig=b"",
                node_index=self.index,
            )

    def Revoke(self, request, context):
        self.crl[request.serial] = True
        return pb.RevokeResponse(ok=True, msg="revoked")

    def CRL(self, request, context):
        return pb.CRLResponse(revoked_serials=list(self.crl.keys()), ca_signature=b"")

    def OCSP(self, request, context):
        status = pb.OCSPResponse.GOOD
        if request.serial in self.crl:
            status = pb.OCSPResponse.REVOKED
        return pb.OCSPResponse(status=status, ca_signature=b"")


def serve():
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=10))
    pbg.add_CANodeServicer_to_server(CANodeServicer(), server)
    server.add_insecure_port(f"[::]:{GRPC_PORT}")
    print(f"CA-Node {NODE_ID} listening on {GRPC_PORT}")
    server.start()
    server.wait_for_termination()


if __name__ == "__main__":
    serve()

