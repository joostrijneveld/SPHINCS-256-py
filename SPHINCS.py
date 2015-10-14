#!/usr/bin/env python3
"""Python implementation of the SPHINCS signature scheme

Usage:
    SPHINCS.py keygen [-o FILE|--output FILE]
    SPHINCS.py sign [-i FILE|--input FILE] [-o FILE|--output FILE]
    SPHINCS.py verify [-i FILE|--input FILE]
    SPHINCS.py (-h|--help)

Options:
    -o FILE, --output FILE  Specify an output file.
    -i FILE, --input FILE   Specify an input file.
    -h --help               Show this help screen.
"""

import sys
import docopt

from ChaCha import ChaCha
from bytes_utils import xor


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

        C = bytes("expand 32-byte to 64-byte state!", 'latin-1')

        perm = ChaCha().permuted
        self.F = lambda m: perm(m + C)[:32]
        self.H = lambda m1, m2: perm(xor(perm(m1 + C), m2 + bytes(32)))[:32]
        self.Glambda = lambda seed, n: ChaCha(key=seed).keystream(n)

    def keygen(self):
        return bytes()

    def sign(self, m):
        return bytes()

    def verify(self, sm):
        return 0

if __name__ == "__main__":
    args = docopt.docopt(__doc__)
    sphincs256 = SPHINCS()

    for f in ['--input', '--output']:
        if args[f] is None or args[f] == '-':
            args[f] = None

    if args['--input'] is None:
        ifile = sys.stdin.buffer
    else:
        ifile = open(args['--input'], 'rb')
    if args['--output'] is None:
        ofile = sys.stdout.buffer
    else:
        ofile = open(args['--output'], 'wb')

    if args['keygen']:
        keys = sphincs256.keygen()
        ofile.write(keys)
        print('Wrote keys', file=sys.stderr)
    elif args['sign']:
        message = ifile.read()
        signature = sphincs256.sign(message)
        ofile.write(signature)
        print('Wrote signature', file=sys.stderr)
    elif args['verify']:
        message_signature = ifile.read()
        if verify(message_signature):
            print('Verification succeeded', file=sys.stderr)
        else:
            print('Verification failed', file=sys.stderr)

    ifile.close()
    ofile.close()
