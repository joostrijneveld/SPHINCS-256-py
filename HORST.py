import sys
from trees import hash_tree, auth_path, construct_root
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
        self.Gt = Gt

    def message_indices(self, m):
        M = chunkbytes(m, self.tau // 8)
        M = [int.from_bytes(Mi, byteorder=sys.byteorder) for Mi in M]
        return M

    def keygen(self, seed, masks):
        sk = self.Gt(seed, self.t * self.n // 8)
        sk = chunkbytes(sk, self.n // 8)
        L = list(map(self.F, sk))
        H = lambda x, y, i: self.H(xor(x, masks[2*i]), xor(y, masks[2*i+1]))
        tree = list(hash_tree(H, L))
        return tree[-1][0]  # pk is the root node

    def sign(self, m, seed, masks):
        sk = self.Gt(seed, self.t * self.n // 8)
        sk = chunkbytes(sk, self.n // 8)
        L = list(map(self.F, sk))
        H = lambda x, y, i: self.H(xor(x, masks[2*i]), xor(y, masks[2*i+1]))
        tree = list(hash_tree(H, L))
        M = self.message_indices(m)
        return [(sk[i], auth_path(tree, i)) for i in M]

    def verify(self, m, sig, masks):
        M = self.message_indices(m)
        H = lambda x, y, i: self.H(xor(x, masks[2*i]), xor(y, masks[2*i+1]))
        root = None
        for (sk, path), Mi in zip(sig, M):
            leaf = self.F(sk)
            r = construct_root(H, path, leaf, Mi)
            if root is None:
                root = r
            elif root != r:
                return False
        return root
