import os
import uuid
import grpc
from datetime import datetime, timedelta
from typing import List, Tuple


from blspy import (PrivateKey, AugSchemeMPL, G1Element, G2Element)


from common.crypto_utils import gen_rsa_keypair
from common.cert import Certificate
import proto.ca_pb2 as pb
import proto.ca_pb2_grpc as pbg


NODE_ADDRESSES = os.getenv("NODE_ADDRESSES","ca1:50061,ca2:50062,ca3:50063").split(",")
THRESHOLD = int(os.getenv("THRESHOLD","2"))
CN = os.getenv("CN","client1")


# must match server's demo DKG master public key construction
from hashlib import sha256
SEED = b"demo-seed-do-not-use"
master_s = int.from_bytes(sha256(SEED).digest(), 'big') % PrivateKey.SUBGROUP_ORDER
MASTER_PK: G1Element = PrivateKey.from_bytes(master_s.to_bytes(32,'big')).get_g1()




def lagrange_coeff(indices: List[int], at: int=0) -> List[int]:
  # compute Lagrange basis l_j(0) over Z_r for given indices
  r = PrivateKey.SUBGROUP_ORDER
  coeffs = []
  for j,xj in enumerate(indices):
    num, den = 1, 1
    for m,xm in enumerate(indices):
    if m==j: continue
      num = (num * (-xm % r)) % r
      den = (den * ((xj - xm) % r)) % r
    coeffs.append((num * pow(den, -1, r)) % r)
  return coeffs




def request_partials(tbs: bytes) -> List[Tuple[int, bytes]]:
  parts = []
    for addr in NODE_ADDRESSES:
      ch = grpc.insecure_channel(addr)
      stub = pbg.CANodeStub(ch)
      try:
        resp = stub.SignPartial(pb.NodeSignReq(tbs_cert=tbs, req_id=str(uuid.uuid4())), timeout=3)
        if resp.ok:
          parts.append((resp.node_index, resp.partial_sig))
      except Exception as e:
        print("node failed:", addr, e)
      if len(parts) >= THRESHOLD:
        break
  return parts




def aggregate_threshold(partials: List[Tuple[int, bytes]]) -> G2Element:
  # BLS threshold aggregation with Lagrange at 0
  idx = [i for (i,_) in partials]
  lambdas = lagrange_coeff(idx, 0)
  sigs = [G2Element.from_bytes(s) for (_,s) in partials]
  # exponentiate each partial by its lambda and add (group law)
  # blspy doesn't expose scalar*sig directly; use pairing-scheme provided Multiply
  agg = None
  for lam, sig in zip(lambdas, sigs):
    comp = sig * lam # scalar multiplication supported on G2Element in blspy 2.x
    agg = comp if agg is None else agg + comp
  return agg




def verify_cert_sig(cert: Certificate, sig: G2Element) -> bool:
# verify BLS signature on tbs against MASTER_PK
  try:
    return AugSchemeMPL.verify(MASTER_PK, cert.to_tbs(), sig)
  except Exception:
    return False



def main():
  # generate subject keypair and CSR
  priv_pem, pub_pem = gen_rsa_keypair()
  # build TBS certificate locally
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
  # attach aggregated threshold signature
  cert.signature = bytes(sig)
  pem = cert.to_pem()
  print("
  === Threshold Cert (client-aggregated) ===
  ", pem.decode())
  print("verify:", verify_cert_sig(cert, sig))


if __name__ == "__main__":
  main()
