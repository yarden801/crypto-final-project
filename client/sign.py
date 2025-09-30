import os, uuid, grpc, hashlib, argparse
from datetime import datetime, timedelta
from typing import List, Tuple


from common.cert import Certificate
import proto.ca_pb2 as pb
import proto.ca_pb2_grpc as pbg
from client.is_valid import verify_cert_sig
from common.util import bytes_to_g1, bytes_to_g2_jac, g2_to_bytes_jac, gen_rsa_keypair


from py_ecc.optimized_bls12_381 import (
    curve_order as R,
    G1, G2, multiply, add, pairing, normalize, FQ
)

# ---------- Hash helpers ----------
def H_to_scalar(seed: bytes) -> int:
    return int.from_bytes(hashlib.sha256(seed).digest(), "big") % R

def hash_to_G2_point(msg: bytes):
    h = int.from_bytes(hashlib.sha256(msg).digest(), "big") % R
    return multiply(G2, h)

# ---------- Lagrange interpolation ----------
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

# ---------- Threshold aggregation ----------
def aggregate_threshold(partials: List[Tuple[int, bytes]]):
    idx = [i for (i, _) in partials]
    lambdas = lagrange_coeff(idx)
    g2_pts = [bytes_to_g2_jac(sig_b) for (_, sig_b) in partials]
    agg = None
    for lam, P in zip(lambdas, g2_pts):
        scaled = multiply(P, lam)
        agg = scaled if agg is None else add(agg, scaled)
    return agg

# ---------- Networking ----------
def request_partials(tbs: bytes, node_addresses: List[str], threshold:int) -> List[Tuple[int,bytes]]:
    print("TBS digest:", hashlib.sha256(tbs).hexdigest())
    parts=[]
    for addr in node_addresses:
        print(f"→ contacting {addr}")
        ch=grpc.insecure_channel(addr)
        stub=pbg.CANodeStub(ch)
        try:
            resp=stub.SignPartial(pb.NodeSignReq(tbs_cert=tbs, req_id=str(uuid.uuid4())), timeout=3)
            print(f"  got response from {addr}: ok={resp.ok}, msg={resp.msg}, len={len(resp.partial_sig)}")
            if resp.ok: 
                parts.append((resp.node_index, resp.partial_sig))
        except Exception as e:
            print(f"  node failed: {addr}, error={e}")
        if len(parts)>=threshold: 
            break
    return parts
    
def dump_cert(cert: Certificate):
    print(f"Serial:       {cert.serial}")
    print(f"Subject CN:   {cert.subject_cn}")
    print(f"Issuer CN:    {cert.issuer_cn}")
    print(f"Not Before:   {cert.not_before}")
    print(f"Not After:    {cert.not_after}")
    print(f"Subject PK:   {cert.subject_pub_pem[:60]}...")  # print first bytes
    print(f"Signature:    {cert.signature[:60]}..." if cert.signature else "None")
    print(f"Is CA:        {getattr(cert, 'is_ca', False)}")
    print("")


# ---------- Main ----------
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--level", type=int, default="1", help="Cert level (1=root, 2=intermediate, 3=leaf, ...)")
    ap.add_argument("--cn", type=str, default="client1", help="Common Name for subject")
    ap.add_argument("--threshold", type=int, default=int(os.getenv("THRESHOLD", "2")))
    ap.add_argument("--ca", action="store_true", help="Mark this cert as a CA certificate")
    ap.add_argument("--verify", action="store_true", help="Verify the resulting cert + chain after issuance")

    args = ap.parse_args()
    
    level = args.level
    cn    = args.cn
    threshold = args.threshold

    if level == 1:
        issuer_cn = "self"
        parent_level = None
        node_addresses = os.getenv(f"LEVEL{level}_NODES")
        if not node_addresses:
            raise RuntimeError(f"Missing env LEVEL{level}_NODES")
        node_addresses = node_addresses.split(",")
    else:
        issuer_cn = f"Level{level-1}CA"
        parent_level = level-1
        parent_env = os.getenv(f"LEVEL{parent_level}_NODES")
        if not parent_env:
            raise RuntimeError(f"Missing env LEVEL{parent_level}_NODES")
        node_addresses = parent_env.split(",")

    # Load issuer chain if not root
    chain = []
    if level > 1:
        parent_pem_path = f"certs/level{level-1}_*.pem"
        import glob
        matches = sorted(glob.glob(parent_pem_path))
        if not matches:
            raise RuntimeError(f"No parent certs found at {parent_pem_path}. Run level {level-1} first.")
        parent_file = matches[0]

        with open(parent_file, "rb") as f:
            parent_chain = Certificate.from_pem(f.read())
        chain = parent_chain  # parent + its chain

    # Subject keypair + TBS cert
    now = datetime.utcnow()

    if args.ca:
        with open(f"level{level}_master_pk.hex") as f:
            pk_bytes = bytes.fromhex(f.read().strip())
        pub_pem = b"BLS-PUBKEY:" + pk_bytes
    else:
        _, pub_pem = gen_rsa_keypair()

    issuer_cn = f"Level{level-1}CA" if level > 1 else cn
    cert = Certificate(
        serial=str(uuid.uuid4()),
        subject_cn=cn,
        issuer_cn=issuer_cn,
        not_before=now,
        not_after=now + timedelta(days=365),
        subject_pub_pem=pub_pem,
        is_ca=args.ca
    )

    tbs = cert.to_tbs()

    # Collect partials
    parts = request_partials(tbs, node_addresses, threshold)
    if len(parts) < threshold:
        print("INSUFFICIENT PARTIALS")
        return

    agg_sig_point = aggregate_threshold(parts)
    cert.signature = g2_to_bytes_jac(agg_sig_point)

    # Save bundled PEM (this cert + chain)
    os.makedirs("certs", exist_ok=True)
    pem = cert.to_pem(chain=chain)
    path = f"certs/level{level}_{cn}.pem"
    with open(path, "wb") as f:
        f.write(pem)

    print("=== Threshold Cert (aggregated) ===")
    print(pem.decode())
    
    print("=== Certificate fields ===")
    dump_cert(cert)
    if chain:
        print("=== Chain ===")
        for c in (chain if isinstance(chain, list) else [chain]):
            dump_cert(c)

    print(" Certificate saved to", path)

    # Verify against issuer
    if chain:
        parent = chain[0]
        
        if not parent.is_ca:
            raise RuntimeError(f"Issuer {parent.subject_cn} is not a CA cert!")

        if parent.subject_pub_pem.startswith(b"BLS-PUBKEY:"):
            pk_bytes = parent.subject_pub_pem[len(b"BLS-PUBKEY:"):]
            issuer_pk = bytes_to_g1(pk_bytes)
        else:
            raise RuntimeError("Issuer pubkey is not BLS; got: " + parent.subject_pub_pem[:30].decode(errors="ignore"))

        ok = verify_cert_sig(cert, agg_sig_point, issuer_pk)
        print("verify against issuer:", ok)
        

if __name__ == "__main__":
    main()
