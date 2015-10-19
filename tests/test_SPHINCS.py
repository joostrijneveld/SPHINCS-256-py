import os
from SPHINCS import SPHINCS


def test_address_ref():
    a1 = SPHINCS.address(level=1, subtree=42, leaf=13)
    assert a1 == bytes([0xA1, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x68])
    a2 = SPHINCS.address(level=3, subtree=231, leaf=7)
    assert a2 == bytes([0x73, 0x0E, 0x00, 0x00, 0x00, 0x00, 0x00, 0x38])
    a3 = SPHINCS.address(level=15, subtree=21, leaf=2)
    assert a3 == bytes([0x5F, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10])


def test_SPHINCS():
    sphincs = SPHINCS(n=256, m=512, h=8, d=2, w=4, tau=8, k=64)
    M = os.urandom(256)
    sk, pk = sphincs.keygen()
    sig = sphincs.sign(M, sk)
    assert sphincs.verify(M, sig, pk)
