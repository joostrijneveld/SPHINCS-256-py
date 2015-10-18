from bytes_utils import ints_from_4bytes, ints_to_4bytes

sigma = "expand 32-byte k"
tau = "expand 16-byte k"


class ChaCha(object):

    def __init__(self, key=None, iv=None, rounds=12):
        assert rounds & 1 == 0
        self.rounds = rounds
        if key is None:
            key = bytes(32)
        if iv is None:
            iv = bytes(8)
        assert len(key) in [16, 32]
        assert len(iv) == 8
        self.state = []
        if len(key) == 32:
            c = bytes(sigma, 'latin-1')
            self.state += ints_from_4bytes(c)
            self.state += ints_from_4bytes(key)
        elif len(key) == 16:
            c = bytes(tau, 'latin-1')
            self.state += ints_from_4bytes(c)
            self.state += ints_from_4bytes(key)
            self.state += ints_from_4bytes(key)
        self.state += [0, 0]
        self.state += ints_from_4bytes(iv)

    def permuted(self, a):
        """Takes 16 integers or 64 bytes, returns the ChaCha-permuted bytes

        Note that this is more elaborate than in the reference code.
        This should make it easier to use the ChaCha-permutation on its own.
        """  # TODO find a nice way to split this without duplication
        assert (len(a) == 16 and all(type(i) is int for i in a) or
                len(a) == 64 and type(a) in [bytes, bytearray])
        if len(a) == 64:
            x = list(ints_from_4bytes(a))
        else:
            x = list(a)

        def ROL32(x, n):
            return ((x << n) & 0xFFFFFFFF) | (x >> (32 - n))

        def quarterround(x, a, b, c, d):
            x[a] = (x[a] + x[b] & 0xFFFFFFFF); x[d] = ROL32(x[d] ^ x[a], 16)
            x[c] = (x[c] + x[d] & 0xFFFFFFFF); x[b] = ROL32(x[b] ^ x[c], 12)
            x[a] = (x[a] + x[b] & 0xFFFFFFFF); x[d] = ROL32(x[d] ^ x[a], 8)
            x[c] = (x[c] + x[d] & 0xFFFFFFFF); x[b] = ROL32(x[b] ^ x[c], 7)

        for i in range(0, self.rounds, 2):
            quarterround(x, 0, 4,  8, 12)
            quarterround(x, 1, 5,  9, 13)
            quarterround(x, 2, 6, 10, 14)
            quarterround(x, 3, 7, 11, 15)
            quarterround(x, 0, 5, 10, 15)
            quarterround(x, 1, 6, 11, 12)
            quarterround(x, 2, 7,  8, 13)
            quarterround(x, 3, 4,  9, 14)

        if len(a) == 16:
            for i in range(16):
                x[i] = (x[i] + a[i] & 0xFFFFFFFF)

        return b''.join(ints_to_4bytes(x))

    def keystream(self, N=64):
        """Returns N bytes of keystream starting from the current state

        Note that if N is not a multiple of 64, some keystream is discarded."""
        output = bytes()
        for n in range(N, 0, -64):
            output += self.permuted(self.state)[:min(n, 64)]
            self.state[12] += 1
            if self.state[12] & 0xFFFFFFFF == 0:
                self.state[13] += 1
        return output
