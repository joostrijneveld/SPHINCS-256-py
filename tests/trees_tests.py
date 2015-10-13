from trees import l_tree, hash_tree

def test_sum_tree():
    sum_tree = list(hash_tree(lambda x, y, i: x + y, range(16)))
    assert sum_tree[-1][0] == sum(range(16))

def test_sum_l_tree():
    sum_tree = list(l_tree(lambda x, y, i: x + y, range(20)))
    assert sum_tree[-1][0] == sum(range(20))

def test_left_tree():
    sum_tree = list(l_tree(lambda x, y, i: x, range(20)))
    assert sum_tree[-1][0] == min(range(20))

def test_right_tree():
    sum_tree = list(l_tree(lambda x, y, i: y, range(20)))
    assert sum_tree[-1][0] == max(range(20))
