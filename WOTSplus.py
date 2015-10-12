import sys
from math import ceil, floor, log2
from ChaCha import ChaCha
from bytes_utils import xor, chunkbytes


class WOTSplus(object):

    def __init__(self, n, w, F):
        self.n = n
        self.w = w
        self.l1 = ceil(n / log2(w))
        self.l2 = floor(log2(self.l1 * (w - 1)) / log2(w)) + 1
        self.l = self.l1 + self.l2
        self.F = F

    def chains(self, x, masks, starts, ends):
        x = list(x)
        for i in range(self.l):
            for j in range(starts[i], ends[i]):
                x[i] = self.F(xor(x[i], masks[j]))
        return x

    def int_to_basew(self, x, base):
        for _ in range(self.l1):
            yield x % base
            x //= base

    def chainlengths(self, m):
        M = int.from_bytes(m, byteorder=sys.byteorder)
        M = list(self.int_to_basew(M, self.w))
        C = sum(self.w - 1 - M[i] for i in range(self.l1))
        C = list(self.int_to_basew(C, self.w))
        return M + C

    def keygen(self, seed, masks):
        sk = ChaCha(rounds=12, key=seed).keystream(self.l * self.n // 8)
        sk = chunkbytes(sk, self.n // 8)
        return self.chains(sk, masks, [0]*self.l, [self.w-1]*self.l)

    def sign(self, m, seed, masks):
        sk = ChaCha(rounds=12, key=seed).keystream(self.l * self.n // 8)
        sk = chunkbytes(sk, self.n // 8)
        B = self.chainlengths(m)
        return self.chains(sk, masks, [0]*self.l, B)

    def verify(self, m, sig, masks):
        B = self.chainlengths(m)
        return self.chains(sig, masks, B, [self.w-1]*self.l)
