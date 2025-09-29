import random
from py_ecc.optimized_bls12_381 import G1, multiply, add, eq, curve_order as R, FQ
from common.util import g1_to_bytes, bytes_to_g1

def gen_poly(t):
    return [random.randrange(1, R) for _ in range(t)]

def eval_poly(coeffs, x):
    res = 0
    for k, a in enumerate(coeffs):
        res = (res + a * pow(x, k, R)) % R
    return res

def verify_share(share: int, j: int, commits: list) -> bool:
    """
    Verify share s_ij against commitments for node i.
    share   : integer s_ij
    j       : index of receiving node
    commits : list of G1 commitments [C0, C1, ..., Ct-1]
    """
    lhs = multiply(G1, share)   # G1^s_ij
    rhs = None
    for k, Ck in enumerate(commits):
        term = multiply(Ck, pow(j, k, R))  # Ck^(j^k)
        rhs = term if rhs is None else add(rhs, term)
    print(f"[DEBUG] Node {self.node_id} verifying share from Node {from_node}: {share}")
    return eq(lhs, rhs)
class DKGState:
    def __init__(self, node_id, total_nodes, threshold):
        self.node_id = node_id
        self.total_nodes = total_nodes
        self.threshold = threshold
        self.poly = gen_poly(threshold)   # random polynomial
        self.commits = {}                 # commitments from others
        self.received_shares = {}
        self.complaints = set()

        # Compute my commitments
        self.my_commits = [multiply(G1, coeff) for coeff in self.poly]

        # Store my own commitments so finalize() can see them
        self.commits[self.node_id] = self.my_commits


    def receive_commitments(self, from_node, commits):
        self.commits[from_node] = commits

    def receive_share(self, from_node, share):
        # Verify share against commitments
        if from_node not in self.commits:
            print(f"[Node {self.node_id}] No commitments from Node {from_node}")
            self.complaints.add(from_node)
            return
        if verify_share(share, self.node_id, self.commits[from_node]):
            self.received_shares[from_node] = share
        else:
            print(f"[Node {self.node_id}] INVALID share from Node {from_node}")
            self.complaints.add(from_node)

    def finalize(self):
        # Check for missing shares
        for i in range(1, self.total_nodes+1):
            if i == self.node_id: 
                continue
            if i not in self.received_shares:
                print(f"[Node {self.node_id}] Missing share from Node {i}")
                self.complaints.add(i)

        # Only keep honest nodes
        honest_nodes = [i for i in range(1, self.total_nodes+1) if i not in self.complaints]

        # Aggregate local secret share
        self.local_sk = sum([self.received_shares.get(i, 0) for i in honest_nodes]) % R

        # Aggregate MPK from commitments of honest nodes
        self.mpk = sum([self.commits[i][0] for i in honest_nodes], (FQ(0), FQ(1), FQ(0)))
        return self.local_sk, self.mpk
