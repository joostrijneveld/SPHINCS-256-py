import itertools
from trees import hash_tree, auth_path, construct_root, root
from bytes_utils import xor, chunkbytes


class HORST(object):

    def __init__(self, n, m, k, tau, F, H, Gt):
        """Initialize HORST

        n -- length of hashes (in bits)
        m -- length of the message hash (in bits)
        k -- number of revealed secret-key elements per signature
        tau -- number of tree layers (2 ** tau is the number of sk elements)
        F -- function used hash the leaf nodes
        Gt -- PRG to generate the chain bases, based on seed and no. of bytes
        """
        assert k*tau == m
        self.n = n
        self.m = m
        self.k = k
        self.tau = tau
        self.t = 1 << tau
        self.F = F
        self.H = H
        # minimising k(tau - x + 1) + 2^{x} implies maximising 'k*x - 2^{x}'
        self.x = max((k * x - (1 << x), x) for x in range(tau))[1]
        self.Gt = lambda seed: Gt(seed=seed, n=self.t * self.n // 8)

    def message_indices(self, m):
        M = chunkbytes(m, self.tau // 8)
        # the reference implementation uses 'idx = m[2*i] + (m[2*i+1]<<8)'
        # which suggests using little-endian byte order
        M = [int.from_bytes(Mi, byteorder='little') for Mi in M]
        return M

    def keygen(self, seed, masks):
        assert len(seed) == self.n // 8
        assert len(masks) == 2 * self.tau
        sk = self.Gt(seed)
        sk = chunkbytes(sk, self.n // 8)
        L = list(map(self.F, sk))
        H = lambda x, y, i: self.H(xor(x, masks[2*i]), xor(y, masks[2*i+1]))
        return root(hash_tree(H, L))

    def sign(self, m, seed, masks):
        assert len(m) == self.m // 8
        assert len(seed) == self.n // 8
        assert len(masks) == 2 * self.tau
        sk = self.Gt(seed)
        sk = chunkbytes(sk, self.n // 8)
        L = list(map(self.F, sk))
        H = lambda x, y, i: self.H(xor(x, masks[2*i]), xor(y, masks[2*i+1]))
        tree = hash_tree(H, L)
        trunk = list(itertools.islice(tree, 0, self.tau - self.x))
        sigma_k = next(tree)
        M = self.message_indices(m)
        # the SPHINCS paper suggests to put sigma_k at the end of sigma
        # but the reference code places it at the front
        return [(sk[Mi], auth_path(trunk, Mi)) for Mi in M] + [sigma_k]

    def verify(self, m, sig, masks):
        assert len(m) == self.m // 8
        assert len(masks) == 2 * self.tau
        M = self.message_indices(m)
        H = lambda x, y, i: self.H(xor(x, masks[2*i]), xor(y, masks[2*i+1]))
        sigma_k = sig[-1]
        for (sk, path), Mi in zip(sig, M):
            leaf = self.F(sk)
            r = construct_root(H, path, leaf, Mi)
            # there is an error in the SPHINCS paper for this formula, as it
            # states that y_i = floor(M_i / 2^tau - x)
            # rather than y_i = floor(M_i / 2^{tau - x})
            yi = Mi // (1 << (self.tau - self.x))
            if r != sigma_k[yi]:
                return False
        Qtop = masks[2*(self.tau - self.x):]
        H = lambda x, y, i: self.H(xor(x, Qtop[2*i]), xor(y, Qtop[2*i+1]))
        return root(hash_tree(H, sigma_k))
