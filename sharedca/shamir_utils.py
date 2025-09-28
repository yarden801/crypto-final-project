```python
from functools import reduce
from operator import mul


def lagrange_interpolate_zero(shares, prime):
    result = 0
    for j, (xj, yj) in enumerate(shares):
    lj = 1
    for m, (xm, _) in enumerate(shares):
    if m != j:
    lj *= xm * pow(xm - xj, -1, prime)
    lj %= prime
    result += yj * lj
    result %= prime
    return result
```