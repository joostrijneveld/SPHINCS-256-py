#!/usr/bin/env python3
"""Python implementation of the SPHINCS signature scheme

Usage:
    SPHINCS.py keygen [--secret-key FILE] [--public-key FILE]
    SPHINCS.py sign [-m FILE|--message FILE] [--secret-key FILE] [-s FILE|--signature FILE]
    SPHINCS.py verify [-m FILE|--message FILE] [-s FILE|--signature FILE] [--public-key FILE]
    SPHINCS.py (-h|--help)

Options:
    -s FILE, --signature FILE    Specify a signature file.
    -m FILE, --message FILE      Specify a message file.
             --secret-key FILE   Specify a secret-key file.
             --public-key FILE   Specify a public-key file.
    -h --help                    Show this help screen.
"""

import sys
import docopt
import os
from math import ceil, log

from ChaCha import ChaCha
from WOTSplus import WOTSplus
from HORST import HORST
from bytes_utils import xor
from blake import BLAKE
from trees import l_tree, hash_tree, auth_path, construct_root, root


class SPHINCS(object):

    def __init__(self, n=256, m=512, h=60, d=12, w=16, tau=16, k=32):
        """Initializes SPHINCS (default to SPHINCS-256)

        Currently other parameters than SPHINCS-256 can be buggy
        n -- length of hash in WOTS / HORST (in bits)
        m -- length of message hash (in bits)
        h -- height of the hyper-tree
        d -- layers of the hyper-tree
        w -- Winternitz parameter used for WOTS signature
        tau -- layers in the HORST tree (2^tau is no. of secret-key elements)
        k -- number of revealed secret-key elements per HORST signature
        """
        self.n = n
        self.m = m
        self.h = h
        self.d = d
        self.w = w
        self.tau = tau
        self.t = 1 << tau
        self.k = k

        self.Hdigest = lambda r, m: BLAKE(512).digest(r + m)
        self.Fa = lambda a, k: BLAKE(256).digest(k + a)
        self.Frand = lambda m, k: BLAKE(512).digest(k + m)

        C = bytes("expand 32-byte to 64-byte state!", 'latin-1')
        perm = ChaCha().permuted
        self.Glambda = lambda seed, n: ChaCha(key=seed).keystream(n)
        self.F = lambda m: perm(m + C)[:32]
        self.H = lambda m1, m2: perm(xor(perm(m1 + C), m2 + bytes(32)))[:32]

        self.wots = WOTSplus(n=n, w=w, F=self.F, Gl=self.Glambda)
        self.horst = HORST(n=n, m=m, k=k, tau=tau,
                           F=self.F, H=self.H, Gt=self.Glambda)

    @classmethod
    def address(self, level, subtree, leaf):
        t = level | (subtree << 4) | (leaf << 59)
        return int.to_bytes(t, length=8, byteorder='little')

    def wots_leaf(self, address, SK1, masks):
        seed = self.Fa(address, SK1)
        pk_A = self.wots.keygen(seed, masks)
        H = lambda x, y, i: self.H(xor(x, masks[2*i]), xor(y, masks[2*i+1]))
        return root(l_tree(H, pk_A))

    def wots_path(self, a, SK1, Q, subh):
        ta = dict(a)
        leafs = []
        for subleaf in range(1 << subh):
            ta['leaf'] = subleaf
            leafs.append(self.wots_leaf(self.address(**ta), SK1, Q))
        Qtree = Q[2 * ceil(log(self.wots.l, 2)):]
        H = lambda x, y, i: self.H(xor(x, Qtree[2*i]), xor(y, Qtree[2*i+1]))
        tree = list(hash_tree(H, leafs))
        return auth_path(tree, a['leaf']), root(tree)

    def keygen(self):
        SK1 = os.urandom(self.n // 8)
        SK2 = os.urandom(self.n // 8)
        p = max(self.w-1, 2 * (self.h + ceil(log(self.wots.l, 2))), 2*self.tau)
        Q = [os.urandom(self.n // 8) for _ in range(p)]
        PK1 = self.keygen_pub(SK1, Q)
        return (SK1, SK2, Q), (PK1, Q)

    def keygen_pub(self, SK1, Q):
        addresses = [self.address(self.d - 1, 0, i)
                     for i in range(1 << (self.h//self.d))]
        leafs = [self.wots_leaf(A, SK1, Q) for A in addresses]
        Qtree = Q[2 * ceil(log(self.wots.l, 2)):]
        H = lambda x, y, i: self.H(xor(x, Qtree[2*i]), xor(y, Qtree[2*i+1]))
        PK1 = root(hash_tree(H, leafs))
        return PK1

    def sign(self, M, SK):
        SK1, SK2, Q = SK
        R = self.Frand(M, SK2)
        R1, R2 = R[:self.n // 8], R[self.n // 8:]
        D = self.Hdigest(R1, M)
        i = int.from_bytes(R2, byteorder='big')
        i >>= self.n - self.h
        subh = self.h // self.d
        a = {'level': self.d,
             'subtree': i >> subh,
             'leaf': i & ((1 << subh) - 1)}
        a_horst = self.address(**a)
        seed_horst = self.Fa(a_horst, SK1)
        sig_horst, pk_horst = self.horst.sign(D, seed_horst, Q)
        pk = pk_horst
        sig = [i, R1, sig_horst]
        for level in range(self.d):
            a['level'] = level
            a_wots = self.address(**a)
            seed_wots = self.Fa(a_wots, SK1)
            wots_sig = self.wots.sign(pk, seed_wots, Q)
            sig.append(wots_sig)
            path, pk = self.wots_path(a, SK1, Q, subh)
            sig.append(path)
            a['leaf'] = a['subtree'] & ((1 << subh) - 1)
            a['subtree'] >>= subh
        return tuple(sig)

    def verify(self, M, sig, PK):
        i, R1, sig_horst, *sig = sig
        PK1, Q = PK
        Qtree = Q[2 * ceil(log(self.wots.l, 2)):]
        D = self.Hdigest(R1, M)
        pk = pk_horst = self.horst.verify(D, sig_horst, Q)
        if pk_horst is False:
            return False
        subh = self.h // self.d
        H = lambda x, y, i: self.H(xor(x, Q[2*i]), xor(y, Q[2*i+1]))
        Ht = lambda x, y, i: self.H(xor(x, Qtree[2*i]), xor(y, Qtree[2*i+1]))
        for _ in range(self.d):
            wots_sig, wots_path, *sig = sig
            pk_wots = self.wots.verify(pk, wots_sig, Q)
            leaf = root(l_tree(H, pk_wots))
            pk = construct_root(Ht, wots_path, leaf, i & 0x1f)
            i >>= subh
        return PK1 == pk

    def pack(self, x):
        if type(x) is bytes:
            return x
        if type(x) is int:  # needed for index i
            return int.to_bytes(x, length=(self.h+7)//8, byteorder='little')
        return b''.join([self.pack(a) for a in iter(x)])

    def unpack(self, sk=None, pk=None, sig=None, byteseq=None):
        n = self.n // 8
        if sk:
            return sk[:n], sk[n:2*n], self.unpack(byteseq=sk[2*n:])
        elif pk:
            return pk[:n], self.unpack(byteseq=pk[n:])
        elif byteseq:
            return [byteseq[i:i+n] for i in range(0, len(byteseq), n)]
        elif sig:
            def prefix(x, n):
                return x[:n], x[n:]
            i, sig = prefix(sig, (self.h+7)//8)
            i = int.from_bytes(i, byteorder='little')
            R1, sig = prefix(sig, n)
            sig_horst = []
            for _ in range(self.k):
                sk, sig = prefix(sig, n)
                auth, sig = prefix(sig, (self.tau - self.horst.x)*n)
                sig_horst.append((sk, self.unpack(byteseq=auth)))
            sigma_k, sig = prefix(sig, (1 << self.horst.x) * n)
            sig_horst.append(self.unpack(byteseq=sigma_k))
            wots = []
            for _ in range(self.d):
                wots_sig, sig = prefix(sig, self.wots.l*n)
                path, sig = prefix(sig, self.h//self.d*n)
                wots.append(self.unpack(byteseq=wots_sig))
                wots.append(self.unpack(byteseq=path))
            return (i, R1, sig_horst) + tuple(wots)

if __name__ == "__main__":
    args = docopt.docopt(__doc__)
    sphincs256 = SPHINCS()

    for f in ['--signature', '--message', '--secret-key', '--public-key']:
        if args[f] is None or args[f] == '-':
            args[f] = None
    if args['keygen']:
        ihandles, ohandles = [], ['--secret-key', '--public-key']
    elif args['sign']:
        ihandles, ohandles = ['--message', '--secret-key'], ['--signature']
    elif args['verify']:
        ihandles, ohandles = ['--message', '--public-key', '--signature'], []

    fh = {}
    for f in ihandles:
        if args[f] is None:
            fh[f[2:]] = sys.stdin.buffer
        else:
            fh[f[2:]] = open(args[f], 'rb')
    for f in ohandles:
        if args[f] is None:
            fh[f[2:]] = sys.stdout.buffer
        else:
            fh[f[2:]] = open(args[f], 'wb')

    if args['keygen']:
        print("Generating keys..", file=sys.stderr)
        sk, pk = sphincs256.keygen()
        fh['secret-key'].write(sphincs256.pack(sk))
        fh['public-key'].write(sphincs256.pack(pk))
        print('Wrote keys', file=sys.stderr)
    elif args['sign']:
        message = fh['message'].read()
        sk = sphincs256.unpack(sk=fh['secret-key'].read())
        print("Signing..", file=sys.stderr)
        signature = sphincs256.sign(message, sk)
        fh['signature'].write(sphincs256.pack(signature))
        print('Wrote signature', file=sys.stderr)
    elif args['verify']:
        message = fh['message'].read()
        sig = sphincs256.unpack(sig=fh['signature'].read())
        pk = sphincs256.unpack(pk=fh['public-key'].read())
        print("Verifying..", file=sys.stderr)
        if sphincs256.verify(message, sig, pk):
            print('Verification succeeded', file=sys.stderr)
        else:
            print('Verification failed', file=sys.stderr)

    for f in fh.values():
        f.close()
