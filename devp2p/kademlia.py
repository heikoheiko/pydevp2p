# -*- coding: utf-8 -*-
"""


Node discovery and network formation are implemented via a kademlia-like protocol.
The major differences are that packets are signed, node ids are the public keys, and
DHT-related features are excluded. The FIND_VALUE and STORE packets are not implemented.
The parameters necessary to implement the protocol are a
bucket size of 16 (denoted k in Kademlia),
concurrency of 3 (denoted alpha in Kademlia),
and 8 bits per hop (denoted b in Kademlia) for routing.
The eviction check interval is 75 milliseconds,
request timeouts are 300ms, and
the idle bucket-refresh interval is 3600 seconds.

Aside from the previously described exclusions, node discovery closely follows system
and protocol described by Maymounkov and Mazieres.

How many peers to connect to?

160/8?

"""
k_b = 8  # 8 bits per hop

k_bucket_size = 16
k_eviction_check_interval = 75 / 1000.
k_request_timeout = 300 / 1000.
k_idle_bucket_refresh_interval = 3600
k_id_size = 512
k_max_node_id = 2 ** k_id_size - 1

from pyethereum import rlp
import operator
from collections import OrderedDict
import time


class Node(object):

    def __init__(self, pubkey, multiaddr):
        assert len(pubkey) == 64 and isinstance(pubkey, str)
        self.pubkey = pubkey
        self.id = rlp.big_endian_to_int(pubkey)
        self.multiaddr = multiaddr  # https://github.com/jbenet/multiaddr

    def distance(self, other):
        return self.id ^ other.id

    def __eq__(self, other):
        return self.multiaddr == other.multiaddr and self.pubkey == other.pubkey

    def __repr__(self):
        return 'Node(%s)' % self.pubkey.encode('hex')[:8]


class KBucket(object):

    """
    Each k-bucket is kept sorted by time last seen—least-recently seen node at the head,
    most-recently seen at the tail. For small values of i, the k-buckets will generally
    be empty (as no appro- priate nodes will exist). For large values of i, the lists can
    grow up to size k, where k is a system-wide repli- cation parameter.
    k is chosen such that any given k nodes are very unlikely to fail within an hour of
    each other (for example k = 20).

    When a Kademlia node receives any message (re- quest or reply) from another node,
    it updates the appropriate k-bucket for the sender’s node ID. If the sending node
    already exists in the recipient’s k- bucket, the recipient moves it to the tail of the list.

    If the node is not already in the appropriate k-bucket and the bucket has fewer than k
    entries, then the recipient just inserts the new sender at the tail of the list.

    If the  appropriate k-bucket is full, however, then the recipient pings the k-bucket’s
    least-recently seen node to decide what to do.

    If the least-recently seen node fails to respond, it is evicted from the k-bucket and
    the new sender inserted at the tail.

    Otherwise, if the least-recently seen node responds, it is moved to the tail of the list,
    and the new sender’s contact is discarded.

    k-buckets effectively implement a least-recently seen eviction policy, except that
    live nodes are never removed from the list.
    """

    k = k_bucket_size

    def __init__(self, start, end):
        self.start = start
        self.end = end
        self.nodes = []
        self.replacement_cache = []
        self.update()

    @property
    def range(self):
        return self.start, self.end

    def update(self):
        self.last_updated = time.time()

    @property
    def midpoint(self):
        return self.start + (self.end - self.start) / 2

    def distance(self, node):
        return self.midpoint ^ node.id

    def nodes_by_distance(self, node):
        return sorted(self.nodes, key=operator.methodcaller('distance', node))

    def split(self):
        lower = KBucket(self.start, self.midpoint)
        upper = KBucket(self.midpoint + 1, self.end)
        for node in self.nodes:
            bucket = lower if node.id <= self.midpoint else upper
            bucket.add_node(node)
        return lower, upper

    def remove_node(self, node):
        if node not in self.nodes:
            return
        self.nodes.remove(node)
        if self.replacement_cache:
            newnode = self.replacement_cache.pop()
            self.nodes.append(newnode)  # fix me ping!?

    def in_range(self, node):
        return self.start <= node.id <= self.end

    def add_node(self, node):
        """
        add node to the tail of the bucket
        """
        if node in self.nodes:  # move to tail
            self.nodes.remove(node)
            self.nodes.append(node)
        elif len(self) < self.k:
            self.nodes.append(node)
        else:
            self.replacement_cache.append(node)
            return False
        return True

    @property
    def head(self):
        "least recently seen"
        return self.nodes[0]

    @property
    def tail(self):
        "last recently seen"
        return self.nodes[-1]

    @property
    def depth(self):
        """
        depth is the prefix shared by all nodes in bucket
        i.e. the number of shared leading bits
        """
        def to_binary(x):  # left padded bit representation
            b = bin(x)[2:]
            return '0' * (k_id_size - len(b)) + b

        bits = [to_binary(n.id) for n in self.nodes]
        for i in range(k_id_size):
            if len(set(b[:i] for b in bits)) != 1:
                return i - 1
        raise Exception

    def depth_different(self):
        """
        depth of a node is i-k_id_size, where i is the smallest index of a none empty bucket
        """
        lowest_id = sorted(self.nodes, key=operator.attrgetter('id'))[0]
        nbits = len(bin(lowest_id)[2:])
        return k_id_size - nbits

    def __contains__(self, node):
        return node in self.nodes

    def __len__(self):
        return len(self.nodes)


class RoutingTable(object):

    def __init__(self, node):
        self.node = node
        self.buckets = [KBucket(0, k_max_node_id)]

    def split_bucket(self, bucket):
        a, b = bucket.split()
        index = self.buckets.index(bucket)
        self.buckets[index] = a
        self.buckets.insert(index + 1, b)

    @property
    def idle_buckets(self):
        one_hour_ago = time.time() - 3600
        return [b for b in self.buckets if b.last_updated < one_hour_ago]

    def remove_node(self, node):
        self.bucket_by_node(node).remove_node(node)

    def add_node(self, node):
        bucket = self.bucket_by_node(node)

        # this will succeed unless the bucket is full
        if bucket.add_node(node):
            return True
        # Per section 4.2 of paper, split if the bucket has the node in its range
        # or if the depth is not congruent to 0 mod k_b
        if bucket.in_range(self.node) or bucket.depth % k_b != 0:
            self.split_bucket(bucket)
            return self.add_node(node)

        return False  # protocol should ping bucket head and evict if there is no response

    def bucket_by_node(self, node):
        for bucket in self.buckets:
            if node.id < bucket.end:
                assert node.id >= bucket.start
                return bucket
        raise Exception

    def buckets_by_distance(self, node):
        return sorted(self.buckets, key=operator.methodcaller('distance', node))

    def __contains__(self, node):
        return node in self.bucket_by_node(node)

    def neighbours(self, node, k=k_bucket_size):
        nodes = []
        for bucket in self.buckets_by_distance(node):
            for n in bucket.nodes_by_distance(node):
                if n is not node:
                    nodes.append(n)
                    if len(nodes) == k:
                        break
        return nodes


if __name__ == '__main__':
    # test, that asserts, that no two nodes in two buckets are closer to each other
    # than nodes within a bucket, except for ...
    pass
