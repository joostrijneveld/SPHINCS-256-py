import sys


def ints_from_4bytes(a):
    chunks = [a[i:i+4] for i in range(0, len(a), 4)]
    for chunk in chunks:
        yield int.from_bytes(chunk, byteorder=sys.byteorder)


def ints_to_4bytes(x):
    for v in x:
        yield int.to_bytes(v, length=4, byteorder=sys.byteorder)
