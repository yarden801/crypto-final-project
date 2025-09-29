# common/util.py
from py_ecc.optimized_bls12_381 import FQ, FQ2, G1, curve_order as R
import hashlib
from py_ecc.optimized_bls12_381 import G2, multiply



L = 48

def g1_to_bytes(P) -> bytes:
    """Serialize G1 Jacobian point (x, y, z) into 96 bytes (affine)."""
    x, y, z = P
    # Convert to affine
    if z == FQ.zero():
        raise ValueError("Point at infinity not supported")
    z_inv = z.inv()
    x_aff = x * z_inv
    y_aff = y * z_inv
    return fq_to_bytes(x_aff) + fq_to_bytes(y_aff)
    

def fq_to_bytes(x) -> bytes:
    return int(x if isinstance(x, int) else x.n).to_bytes(L, "big")

def fq2_to_bytes(x: FQ2) -> bytes:
    return fq_to_bytes(x.coeffs[0]) + fq_to_bytes(x.coeffs[1])

def g2_to_bytes_jac(P) -> bytes:
    x, y, z = P
    return fq2_to_bytes(x) + fq2_to_bytes(y) + fq2_to_bytes(z)

def bytes_to_fq(b: bytes) -> FQ:
    return FQ(int.from_bytes(b, "big"))

def bytes_to_fq2(b: bytes) -> FQ2:
    return FQ2([bytes_to_fq(b[:L]), bytes_to_fq(b[L:2*L])])

def bytes_to_g2_jac(b: bytes):
    if len(b) != 6*L:
        raise ValueError(f"Expected 288 bytes, got {len(b)}")
    x = bytes_to_fq2(b[0:2*L])
    y = bytes_to_fq2(b[2*L:4*L])
    z = bytes_to_fq2(b[4*L:6*L])
    return (x, y, z)

#def bytes_to_g1(b: bytes):
    #if len(b) != 2*L:
     #   raise ValueError("Expected 96 bytes for G1 point")
    #x = bytes_to_fq(b[0:L])
    #y = bytes_to_fq(b[L:2*L])
    #return (x, y, FQ.one())

    
def bytes_to_g1(b: bytes):
    print("got here")
    if len(b) != 96:
        raise ValueError("Expected 96 bytes for G1 point")
    x = FQ(int.from_bytes(b[0:48], "big"))
    y = FQ(int.from_bytes(b[48:96], "big"))
    return (x, y, FQ.one())

def hash_to_G2_point(msg: bytes):
    h = int.from_bytes(hashlib.sha256(msg).digest(), "big") % R
    return multiply(G2, h)
    

# ---------- Lagrange interpolation ----------
def lagrange_coeff(indices):
    """Compute Lagrange coefficients for interpolation at x=0."""
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
