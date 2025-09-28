def _lagrange_interpolate_at_zero(points: List[Tuple[int,int]]) -> int:
    total = 0
    for j,(xj,yj) in enumerate(points):
        num, den = 1, 1
    for m,(xm,_) in enumerate(points):
        if m==j: continue
        num = (num * (-xm % PRIME)) % PRIME
        den = (den * ((xj - xm) % PRIME)) % PRIME
    inv_den = pow(den, -1, PRIME)
    total = (total + yj * num * inv_den) % PRIME
    return total


def split_bytes(secret: bytes, n: int, t: int) -> List[Tuple[int, bytes]]:
    assert 1 < t <= n <= 255, "invalid t,n"
    shares = [(i+1, bytearray(len(secret))) for i in range(n)]
    for idx, b in enumerate(secret):
        coeffs = [b] + [random.randrange(PRIME) for _ in range(t-1)]
        for i in range(n):
            x = i+1
            y = 0
            xp = 1
            for c in coeffs:
                y = (y + c*xp) % PRIME
                xp = (xp * x) % PRIME
            shares[i][1][idx] = y
    return [(x, bytes(arr)) for (x,arr) in shares]




def combine_bytes(shares: List[Tuple[int, bytes]]) -> bytes:
    assert len(shares) > 0
    L = len(shares[0][1])
    for _,b in shares:
        assert len(b)==L, "share length mismatch"
    out = bytearray(L)
    for idx in range(L):
        pts = [(x, share[idx]) for (x,share) in shares]
        out[idx] = _lagrange_interpolate_at_zero(pts)
    return bytes(out)