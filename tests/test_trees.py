from trees import l_tree, hash_tree, auth_path, construct_root


def test_sum_tree():
    sum_tree = list(hash_tree(lambda x, y, i: x + y, range(16)))
    assert sum_tree[-1][0] == sum(range(16))


def test_sum_l_tree():
    sum_tree = list(l_tree(lambda x, y, i: x + y, range(20)))
    assert sum_tree[-1][0] == sum(range(20))


def test_left_tree():
    min_tree = list(l_tree(lambda x, y, i: x, range(20)))
    assert min_tree[-1][0] == min(range(20))


def test_right_tree():
    max_tree = list(l_tree(lambda x, y, i: y, range(20)))
    assert max_tree[-1][0] == max(range(20))


def test_auth_path():
    tree = list(hash_tree(lambda x, y, i: x >> 1, range(15, 31)))
    assert list(auth_path(tree, 5)) == [19, 10, 3, 2]


def test_construct_root():
    H = lambda x, y, i: x - y
    minus_tree = list(hash_tree(H, range(16)))
    for i in range(16):
        leaf = minus_tree[0][i]
        path = auth_path(minus_tree, i)
        assert construct_root(H, path, leaf, i) == minus_tree[-1][0]
