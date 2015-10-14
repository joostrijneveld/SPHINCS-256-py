import os
from HORST import HORST
from SPHINCS import SPHINCS


def test_horst():
    n = 256
    m = 512
    tau = 8  # smaller than actual SPHINCS-256, for fast testing
    M = os.urandom(m // 8)
    seed = os.urandom(n // 8)
    masks = [os.urandom(n // 8) for _ in range(2*tau)]
    horst = HORST(n=n, m=m, k=m / tau, tau=tau,
                  F=SPHINCS().F, H=SPHINCS().H, Gt=SPHINCS().Glambda)
    pk = horst.keygen(seed, masks)
    sig = horst.sign(M, seed, masks)
    assert pk == horst.verify(M, sig, masks)
