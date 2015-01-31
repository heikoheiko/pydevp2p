# -*- coding: utf-8 -*-
from devp2p import kademlia
import random
from rlp import int_to_big_endian
import math
import json

random.seed(42)


def random_pubkey():
    pk = int_to_big_endian(random.getrandbits(kademlia.k_id_size))
    return '\x00' * (kademlia.k_id_size / 8 - len(pk)) + pk


def random_node():
    return kademlia.Node(random_pubkey())


def routing_table(num_nodes=1000):
    node = random_node()
    routing = kademlia.RoutingTable(node)
    for r in [random_node() for i in range(num_nodes)]:
        routing.add_node(r)
    return routing


def test_node():
    node = random_node()
    l = [node]
    assert node in l
    l.remove(node)
    assert node not in l
    assert not l


def test_non_overlap():
    routing = routing_table(1000)
    # buckets must not overlap
    max_id = 0
    for i, b in enumerate(routing.buckets):
        if i > 0:
            assert b.start > max_id
        assert b.end > max_id
        max_id = b.end
    assert b.end < 2 ** kademlia.k_id_size


def test_neighbours():
    routing = routing_table(1000)
    node = random_node()
    nearest_bucket = routing.buckets_by_distance(node)[0]
    assert nearest_bucket.in_range(node)

    # change node id, to something in this bucket.
    node_a = nearest_bucket.nodes[0]
    node_b = random_node()
    node_b.id = node_a.id + 1
    assert nearest_bucket.in_range(node_b)
    assert node_a in routing.buckets_by_distance(node_a)[0]
    assert node_a == routing.neighbours(node_b)[0]


def test_cache():
    routing = routing_table(10000)
    bucket = routing.buckets[0]
    assert len(bucket) == kademlia.k_bucket_size
    r = bucket.replacement_cache[-1]
    n = bucket.tail
    bucket.remove_node(n)
    assert bucket.tail == r


def test_wellformedness():
    """
    fixme: come up with a definition for RLPx
    """
    pass


def show_buckets():
    routing = routing_table(1000)
    for i, b in enumerate(routing.buckets):
        d = b.depth
        print '  ' * d,
        print 'bucket:%d, num nodes:%d depth:%d' % \
            (i, len(b), kademlia.k_id_size - int(math.log(b.start ^ routing.node.id, 2)))
    print 'routing.node is in bucket', routing.buckets.index(routing.bucket_by_node(routing.node))


def create_json_bucket_test():
    doc = \
        """
    'node_ids': hex encoded ids in order in which they were added to the routing table
    'buckets' : buckets sorted asc by range
    """
    num_nodes = 100
    data = dict(node_ids=[], buckets=[], comment=doc)
    node = random_node()
    routing = kademlia.RoutingTable(node)
    data['local_node_id'] = hex(node.id)
    for r in [random_node() for i in range(num_nodes)]:
        routing.add_node(r)
        data['node_ids'].append(hex(r.id))

    for b in routing.buckets:
        jb = dict(start=hex(b.start), end=hex(b.end), node_ids=[hex(n.id) for n in b.nodes])
        data['buckets'].append(jb)

    return json.dumps(data, indent=2)


if __name__ == '__main__':
    print create_json_bucket_test()
