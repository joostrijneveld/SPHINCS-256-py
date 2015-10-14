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


def auth_path(tree, idx):
    for layer in tree[:-1]:  # leave away the top layer
        idx += 1 if (idx & 1 == 0) else -1  # neighbor node
        yield layer[idx]
        idx >>= 1  # parent node


def construct_root(H, auth_path, leaf, idx):
    node = leaf
    for i, neighbor in enumerate(auth_path):
        if idx & 1 == 0:
            node = H(node, neighbor, i)
        else:
            node = H(neighbor, node, i)
        idx >>= 1
    return node
