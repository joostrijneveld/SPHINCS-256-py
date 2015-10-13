from math import log2, ceil


def hash_tree(H, leafs):
    assert (len(leafs) & len(leafs) - 1) == 0  # test for full binary tree
    return l_tree(H, leafs)  # binary hash trees are special cases of L-Trees


def l_tree(H, leafs):
    layer = list(leafs)
    yield layer
    for i in range(ceil(log2(len(leafs)))):
        next_layer = [H(l, r, i) for l, r in zip(layer[0::2], layer[1::2])]
        if len(layer) & 1:  # if there is a node left on this layer
            next_layer.append(layer[-1])
        layer = next_layer
        yield layer
