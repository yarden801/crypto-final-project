import os


MASTER_PK = PrivateKey.from_bytes(master_s.to_bytes(32,'big')).get_g1()


class CANodeServicer(pbg.CANodeServicer):
    def __init__(self):
        # each node i holds sk_i = f(i)
        self.index = NODE_ID
        s_i = f_eval(self.index)
        self.sk_i = PrivateKey.from_bytes(s_i.to_bytes(32,'big'))
        # CRL replicated in-memory for demo
        self.crl: Dict[str,bool] = {}
        self.issuer_cn = "ThreshRoot"


    def SignPartial(self, request, context):
        try:
            # partial signature: sig_i = H(m)^{s_i}
            # blspy: sign directly on bytes
            sig_i: G2Element = self.sk_i.sign_prehashed(request.tbs_cert)
            return pb.NodeSignResp(ok=True, msg="ok", partial_sig=bytes(sig_i), node_index=self.index)
            except Exception as e:
            return pb.NodeSignResp(ok=False, msg=str(e), partial_sig=b"", node_index=self.index)


    def Revoke(self, request, context):
        self.crl[request.serial] = True
        return pb.RevokeResponse(ok=True, msg="revoked")


    def CRL(self, request, context):
        # for demo we don't threshold-sign the CRL here; client can collect t partials on a CRL digest similarly
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

