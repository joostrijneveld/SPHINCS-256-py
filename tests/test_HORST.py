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
    horst = HORST(n=n, m=m, k=m // tau, tau=tau,
                  F=SPHINCS().F, H=SPHINCS().H, Gt=SPHINCS().Glambda)
    pk = horst.keygen(seed, masks)
    sig = horst.sign(M, seed, masks)
    assert pk == horst.verify(M, sig, masks)


def test_message_indices():
    n = 256
    m = 512
    tau = 16
    M = bytes([1] * (m // 8))
    horst = HORST(n=n, m=m, k=m // tau, tau=tau,
                  F=SPHINCS().F, H=SPHINCS().H, Gt=SPHINCS().Glambda)
    assert all(x == 257 for x in horst.message_indices(bytes([1] * (m // 8))))
    incr = horst.message_indices(bytes(range(m // 8)))
    assert incr == [256,   770,   1284,  1798,  2312,  2826,  3340,  3854,
                    4368,  4882,  5396,  5910,  6424,  6938,  7452,  7966,
                    8480,  8994,  9508,  10022, 10536, 11050, 11564, 12078,
                    12592, 13106, 13620, 14134, 14648, 15162, 15676, 16190]
