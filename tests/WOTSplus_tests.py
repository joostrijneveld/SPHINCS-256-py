import os
from WOTSplus import WOTSplus
from SPHINCS import SPHINCS

def test_WOTSplus():
    n = 256
    m = os.urandom(n // 8)
    seed = os.urandom(n // 8)
    masks = [os.urandom(n // 8) for _ in range(16)]
    wots = WOTSplus(n=n, w=16, F=SPHINCS().F, Gl=SPHINCS().Glambda)
    pk = wots.keygen(seed, masks)
    sig = wots.sign(m, seed, masks)
    assert pk == wots.verify(m, sig, masks)
