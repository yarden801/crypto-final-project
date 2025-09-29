# setup.py
import os, json, hashlib, random
from py_ecc.optimized_bls12_381 import G1, multiply, curve_order as R, normalize

# --- Secret generation ---
def H_to_scalar(seed: bytes) -> int:
    return int.from_bytes(hashlib.sha256(seed).digest(), "big") % R

MASTER_SK = H_to_scalar(b"thresh-demo-master")
MASTER_PK = multiply(G1, MASTER_SK)
L = 48

def g1_to_bytes_inline(P):
    # normalize Jacobian → affine
    x, y = normalize(P)
    return int(x.n).to_bytes(L, "big") + int(y.n).to_bytes(L, "big")

# inside setup.py after computing MASTER_PK
with open("master_pk.hex", "w") as f:
    f.write(g1_to_bytes_inline(MASTER_PK).hex())

# --- Shamir secret sharing ---
def shamir_split(secret, n, t):
    coeffs = [secret] + [random.randrange(R) for _ in range(t-1)]
    shares = []
    for i in range(1, n+1):
        accum, x = 0, 1
        for coeff in coeffs:
            accum = (accum + coeff * x) % R
            x = (x * i) % R
        shares.append((i, accum))
    return shares

# Example: 3 nodes, threshold=2
shares = shamir_split(MASTER_SK, n=3, t=2)

# Write config files for each node
os.makedirs("node_config", exist_ok=True)
for i, s in shares:
    cfg = {
        "node_id": i,
        "share": s,
        "master_pk": [int(c) for c in MASTER_PK],  # serialize as ints
        "threshold": 2,
    }
    with open(f"node_config/node{i}.json", "w") as f:
        json.dump(cfg, f)
print("Setup done. Distributed shares written to node_config/")
