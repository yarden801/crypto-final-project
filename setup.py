# setup.py
import os, json, hashlib, random, sys, argparse
from py_ecc.optimized_bls12_381 import G1, multiply, curve_order as R, normalize
from generate_compose import generate_compose   # <--- import generator

L = 48

def H_to_scalar(seed: bytes) -> int:
    return int.from_bytes(hashlib.sha256(seed).digest(), "big") % R

def g1_to_bytes_inline(P):
    # normalize Jacobian → affine
    x, y = normalize(P)
    return int(x.n).to_bytes(L, "big") + int(y.n).to_bytes(L, "big")

def shamir_split(secret, n, t):
    """Return n Shamir shares (i, s_i) with threshold t."""
    coeffs = [secret] + [random.randrange(R) for _ in range(t-1)]
    shares = []
    for i in range(1, n+1):
        accum, x = 0, 1
        for coeff in coeffs:
            accum = (accum + coeff * x) % R
            x = (x * i) % R
        shares.append((i, accum))
    return shares

parser = argparse.ArgumentParser(description="Setup configs and docker-compose for distributed CA system")
parser.add_argument("--num-levels", type=int, default=2, help="Number of levels (default: 2)")
parser.add_argument("--nodes-per-level", type=int, default=3, help="Nodes per level (default: 3)")
parser.add_argument("--threshold", type=int, default=2, help="Signature threshold (default: 2)")


args = parser.parse_args()

NUM_LEVELS = args.num_levels
NODES_PER_LEVEL = args.nodes_per_level
THRESHOLD = args.threshold

os.makedirs("node_config", exist_ok=True)

for level in range(1, NUM_LEVELS+1):
    seed = f"thresh-demo-master-level{level}".encode()
    master_sk = H_to_scalar(seed)
    master_pk = multiply(G1, master_sk)

    with open(f"level{level}_master_pk.hex", "w") as f:
        f.write(g1_to_bytes_inline(master_pk).hex())

    shares = shamir_split(master_sk, n=NODES_PER_LEVEL, t=THRESHOLD)

    for i, s in shares:
        cfg = {
            "node_id": i,
            "share": s,
            "threshold": THRESHOLD,
            "level": level,
            "master_pk": [int(c) for c in master_pk],
        }
        os.makedirs(f"node_config/level{level}", exist_ok=True)
        with open(f"node_config/level{level}/node{i}.json", "w") as f:
            json.dump(cfg, f, indent=2)

print(f"Setup done. Generated {NUM_LEVELS} levels, {NODES_PER_LEVEL} nodes per level.")

compose_content = generate_compose(NUM_LEVELS, NODES_PER_LEVEL, THRESHOLD)
with open("docker-compose.yml", "w") as f:
    f.write(compose_content + "\n")

print("docker-compose.yml written.")

