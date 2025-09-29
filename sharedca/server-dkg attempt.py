import os, grpc
from concurrent import futures
import proto.ca_pb2 as pb
import proto.ca_pb2_grpc as pbg
from py_ecc.optimized_bls12_381 import multiply
from common.util import hash_to_G2_point, g2_to_bytes_jac, g1_to_bytes
import time

from sharedca.dkg import DKGState

NODE_ID = int(os.getenv("NODE_ID", "1"))
ALL_NODES = os.getenv("NODE_ADDRESSES", "ca1:50061,ca2:50062,ca3:50063").split(",")
THRESHOLD = int(os.getenv("THRESHOLD", "2"))

# ---------------- DKG Servicer ---------------- #
class DKGServicer(pbg.DKGServicer):
    def __init__(self, dkg_state):
        self.dkg = dkg_state

    def SendShare(self, request, context):
        if request.to_node == NODE_ID:
            self.dkg.store_share(request.from_node, request.share)
        return pb.Ack(ok=True, msg="share received")

    def BroadcastCommit(self, request, context):
        self.dkg.store_commit(request.from_node, request.commits)
        return pb.Ack(ok=True, msg="commit received")

    def Finalize(self, request, context):
        sk_i, mpk = self.dkg.finalize()
        return pb.FinalizeResp(
            ok=True, msg="done",
            sk_share=sk_i.to_bytes(32, "big"),
            mpk=g1_to_bytes(mpk)
        )

# ---------------- CA Servicer ---------------- #
class CANodeServicer(pbg.CANodeServicer):
    def __init__(self, sk_i, mpk):
        self.sk_i = sk_i
        self.mpk = mpk
        self.crl = {}

    def SignPartial(self, request, context):
        try:
            msg_point = hash_to_G2_point(request.tbs_cert)
            sig_point = multiply(msg_point, self.sk_i)
            sig_bytes = g2_to_bytes_jac(sig_point)
            return pb.NodeSignResp(ok=True, msg="ok", partial_sig=sig_bytes, node_index=NODE_ID)
        except Exception as e:
            return pb.NodeSignResp(ok=False, msg=str(e), partial_sig=b"", node_index=NODE_ID)

    def Revoke(self, request, context):
        self.crl[request.serial] = True
        return pb.RevokeResponse(ok=True, msg="revoked")

    def CRL(self, request, context):
        return pb.CRLResponse(revoked_serials=list(self.crl.keys()), ca_signature=b"")


# ---------------- Bootstrap ---------------- #
def run_server():
    # Step 1: run DKG (simplified, synchronous for demo)
    dkg = DKGState(NODE_ID, len(ALL_NODES), THRESHOLD)

    # In real deployment: exchange shares/commits over gRPC between nodes
    # For demo: assume DKG is already done
    
    time.sleep(30)
    sk_i, mpk = dkg.finalize()
    print(f"[Node {NODE_ID}] Got share: {sk_i}, MPK: {mpk}")

    # Step 2: run CA server
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=10))
    pbg.add_CANodeServicer_to_server(CANodeServicer(sk_i, mpk), server)
    port = ALL_NODES[NODE_ID-1].split(":")[1]
    server.add_insecure_port(f"[::]:{port}")
    print(f"CA-Node {NODE_ID} listening on port {port}")
    server.start()
    server.wait_for_termination()


if __name__ == "__main__":
    run_server()
