def xor(b1, b2):
    """Expects two bytes objects of equal length, returns their XOR"""
    assert len(b1) == len(b2)
    return bytes([x ^ y for x, y in zip(b1, b2)])


def chunkbytes(a, n):
    return [a[i:i+n] for i in range(0, len(a), n)]


def ints_from_4bytes(a):
    for chunk in chunkbytes(a, 4):
        yield int.from_bytes(chunk, byteorder='little')


def ints_to_4bytes(x):
    for v in x:
        yield int.to_bytes(v, length=4, byteorder='little')
