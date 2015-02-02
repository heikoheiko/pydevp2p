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
"""

import rlp
import operator
import time
import slogging
log = slogging.get_logger('kademlia')


k_b = 8  # 8 bits per hop

k_bucket_size = 16
k_eviction_check_interval = 750 / 1000.  # ping timeout, evict if it fails
k_request_timeout = 300 / 1000.          # timeout of finde_node lookups
k_idle_bucket_refresh_interval = 3600    # ping all nodes in bucket if bucket was idle
k_find_concurrency = 3                   # parallel find node lookups
k_id_size = 512
k_max_node_id = 2 ** k_id_size - 1


class Node(object):

    def __init__(self, pubkey):
        assert len(pubkey) == 64 and isinstance(pubkey, str)
        self.pubkey = pubkey
        self.id = rlp.big_endian_to_int(pubkey)

    def distance(self, other):
        return self.id ^ other.id

    def __eq__(self, other):
        return self.pubkey == other.pubkey

    def __repr__(self):
        return '<Node(%s)>' % self.pubkey[:4].encode('hex')

    @classmethod
    def from_id(cls, id):
        pubk = rlp.int_to_big_endian(id)
        pubk = (64 - len(pubk)) * '\0' + pubk
        return cls(pubk)


class KBucket(object):

    """
    Each k-bucket is kept sorted by time last seen—least-recently seen node at the head,
    most-recently seen at the tail. For small values of i, the k-buckets will generally
    be empty (as no appro- priate nodes will exist). For large values of i, the lists can
    grow up to size k, where k is a system-wide replication parameter.
    k is chosen such that any given k nodes are very unlikely to fail within an hour of
    each other (for example k = 20).
    """
    k = k_bucket_size

    def __init__(self, start, end):
        self.start = start
        self.end = end
        self.nodes = []
        self.replacement_cache = []
        self.last_updated = time.time()

    @property
    def range(self):
        return self.start, self.end

    @property
    def midpoint(self):
        return self.start + (self.end - self.start) // 2

    def distance(self, node):
        return self.midpoint ^ node.id

    def nodes_by_distance(self, node):
        return sorted(self.nodes, key=operator.methodcaller('distance', node))

    @property
    def should_split(self):
        depth = self.depth
        return self.is_full and (depth % k_b != 0 and depth != k_id_size)

    def split(self):
        "split at the median id"

        splitid = self.midpoint
        lower = KBucket(self.start, splitid)
        upper = KBucket(splitid + 1, self.end)
        # distribute nodes
        for node in self.nodes:
            bucket = lower if node.id <= splitid else upper
            bucket.add_node(node)
        # distribute replacement nodes
        for node in self.replacement_cache:
            bucket = lower if node.id <= splitid else upper
            bucket.replacement_cache.append(node)

        return lower, upper

    def remove_node(self, node):
        if node not in self.nodes:
            return
        self.nodes.remove(node)

    def in_range(self, node):
        return self.start <= node.id <= self.end

    @property
    def is_full(self):
        return len(self) == k_bucket_size

    def add_node(self, node):
        """
        If the sending node already exists in the recipient’s k- bucket,
        the recipient moves it to the tail of the list.

        If the node is not already in the appropriate k-bucket
        and the bucket has fewer than k entries,
        then the recipient just inserts the new sender at the tail of the list.

        If the  appropriate k-bucket is full, however,
        then the recipient pings the k-bucket’s least-recently seen node to decide what to do.

        on success: return None
        on bucket full: return least recently seen Node for eviction check

        """
        self.last_updated = time.time()
        if node in self.nodes:  # already exists
            self.nodes.remove(node)
            self.nodes.append(node)
        elif len(self) < self.k:  # add if fewer than k entries
            self.nodes.append(node)
        else:  # bucket is full
            return self.head

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

        if len(self.nodes) < 2:
            return k_id_size

        bits = [to_binary(n.id) for n in self.nodes]
        for i in range(k_id_size):
            if len(set(b[:i] for b in bits)) != 1:
                return i - 1
        raise Exception

    def __contains__(self, node):
        return node in self.nodes

    def __len__(self):
        return len(self.nodes)


class RoutingTable(object):

    def __init__(self, node):
        self.this_node = node
        self.buckets = [KBucket(0, k_max_node_id)]

    def split_bucket(self, bucket):
        a, b = bucket.split()
        index = self.buckets.index(bucket)
        self.buckets[index] = a
        self.buckets.insert(index + 1, b)

    @property
    def idle_buckets(self):
        one_hour_ago = time.time() - k_idle_bucket_refresh_interval
        return [b for b in self.buckets if b.last_updated < one_hour_ago]

    @property
    def not_full_buckets(self):
        return [b for b in self.buckets if len(b) < k_bucket_size]

    def remove_node(self, node):
        self.bucket_by_node(node).remove_node(node)

    def add_node(self, node):
        #log.debug('add_node', node=node)
        bucket = self.bucket_by_node(node)
        eviction_candidate = bucket.add_node(node)
        if eviction_candidate:  # bucket is full
            #log.debug('bucket is full', node=node, eviction_candidate=eviction_candidate)
            # split if the bucket has the local node in its range
            # or if the depth is not congruent to 0 mod k_b
            depth = bucket.depth
            if bucket.in_range(self.this_node) or (depth % k_b != 0 and depth != k_id_size):
                #log.debug('splitting bucket')
                self.split_bucket(bucket)
                return self.add_node(node)  # retry
            # nothing added, ping eviction_candidate
            return eviction_candidate
        return None  # successfully added to not full bucket

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

    def __len__(self):
        return sum(len(b) for b in self.buckets)

    def __iter__(self):
        for b in self.buckets:
            for n in b.nodes:
                yield n

    def neighbours(self, node, k=k_bucket_size):
        """
        sorting by bucket.midpoint does not work in edge cases
        build a short list of k * 2 nodes and sort and shorten it
        """
        assert isinstance(node, Node)
        nodes = []
        for bucket in self.buckets_by_distance(node):
            for n in bucket.nodes_by_distance(node):
                if n is not node:
                    nodes.append(n)
                    if len(nodes) == k * 2:
                        break
        return sorted(nodes, key=operator.methodcaller('distance', node))[:k]


class WireInterface(object):

    """
    defines the methods used by KademliaProtocol
    """

    def send_ping(self, node):
        "returns pingid"

    def send_pong(self, node, id):
        pass

    def send_find_node(self, nodeid):
        pass

    def send_neighbours(self, node, neigbours):
        pass


class KademliaProtocol(object):

    def __init__(self, node, wire):
        assert isinstance(node, Node)  # the local node
        assert isinstance(wire, WireInterface)
        self.this_node = node
        self.wire = wire
        self.routing = RoutingTable(node)
        self._expected_pongs = dict()  # pingid -> (timeout, node, replacement_node)
        self._find_requests = dict()  # nodeid -> timeout

    def bootstrap(self, nodes):
        assert isinstance(nodes, list)
        for node in nodes:
            self.routing.add_node(node)
            self.ping(node)
        self.find_node(self.this_node.id)

    def update(self, node, pingid=None):
        """
        When a Kademlia node receives any message (request or reply) from another node,
        it updates the appropriate k-bucket for the sender’s node ID.

        If the sending node already exists in the recipient’s k- bucket,
        the recipient moves it to the tail of the list.

        If the node is not already in the appropriate k-bucket
        and the bucket has fewer than k entries,
        then the recipient just inserts the new sender at the tail of the list.

        If the  appropriate k-bucket is full, however,
        then the recipient pings the k-bucket’s least-recently seen node to decide what to do.

        If the least-recently seen node fails to respond,
        it is evicted from the k-bucket and the new sender inserted at the tail.

        Otherwise, if the least-recently seen node responds,
        it is moved to the tail of the list, and the new sender’s contact is discarded.

        k-buckets effectively implement a least-recently seen eviction policy,
        except that live nodes are never removed from the list.
        """
        assert isinstance(node, Node)
        log.debug('in update', remoteid=node)

        if node == self.this_node:
            log.debug('node is', remoteid=node)
            return

        if pingid and pingid not in self._expected_pongs:
            log.debug('unexpected pong', remoteid=node)
            return

        # check for timed out pings and eventually evict them
        for _pingid, (timeout, _node, replacement) in self._expected_pongs.items():
            if time.time() > timeout:
                log.debug('deleting timedout node', remoteid=_node)
                del self._expected_pongs[_pingid]
                self.routing.remove_node(_node)
                if replacement:
                    log.debug('adding replacement', remoteid=replacement)
                    self.update(replacement)
                    return
                if _node == node:  # prevent node from being added later
                    return

        # if we had registered this node for eviction test
        if pingid in self._expected_pongs:
            timeout, _node, replacement = self._expected_pongs[pingid]
            log.debug('received expect pong', remoteid=node)
            if replacement:
                log.debug('adding replacement to cache', remoteid=replacement)
                self.routing.bucket_by_node(replacement).replacement_cache.append(replacement)
            del self._expected_pongs[pingid]

        # add node
        eviction_candidate = self.routing.add_node(node)
        if eviction_candidate:
            log.debug('could not add', remoteid=node, pinging=eviction_candidate)
            # protocol should ping bucket head and evict if there is no response
            self.ping(eviction_candidate, replacement=node)
        else:
            log.debug('added', remoteid=node)

        # check for not full buckets and ping replacements
        for bucket in self.routing.not_full_buckets:
            for node in bucket.replacement_cache:
                self.ping(node)

        # check idle buckets
        for bucket in self.routing.idle_buckets:
            for node in self.nodes:
                self.ping(node)

        # check and removed timedout find requests
        for nodeid, timeout in self._find_requests.items():
            if time.time() > timeout:
                del self._find_requests[nodeid]

    def ping(self, node, replacement=None):
        """
        successful pings should lead to an update
        if bucket is not full
        elif least recently seen, does not respond in time
        """
        pingid = self.wire.send_ping(node)
        assert pingid
        timeout = time.time() + k_eviction_check_interval
        log.debug('set node to expect pong', remoteid=node)
        self._expected_pongs[pingid] = (timeout, node, replacement)

    def recv_ping(self, node, id):
        assert isinstance(node, Node)
        self.update(node)
        self.wire.send_pong(node, id)

    def recv_pong(self, node, pingid):
        log.debug('recv pong', remoteid=node, pingid=pingid.encode('hex')[:4])
        self.update(node, pingid)

    def _query_neighbours(self, nodeid):
        node = Node.from_id(nodeid)
        for n in self.routing.neighbours(node)[:k_find_concurrency]:
            self.wire.send_find_node(n, node.pubkey)

    def find_node(self, nodeid):
        assert isinstance(nodeid, long)
        self._find_requests[nodeid] = time.time() + k_request_timeout
        self._query_neighbours(nodeid)
        # FIXME, should we return the closest node

    def recv_neighbours(self, node, neighbours):
        """
        if one of the neighbours is closer than the closest known neighbour
            if not timed out
                query closest node for neighbours
        add all nodes to the list
        """
        log.debug('recv neighbours', remoteid=node, num=len(neighbours))
        assert isinstance(neighbours, list)
        # we don't map requests to responses, thus forwarding to all FIXME
        for nodeid, timeout in self._find_requests.items():
            target = Node.from_id(nodeid)
            closest = sorted(neighbours, key=operator.methodcaller('distance', target))[0]
            if time.time() < timeout:
                closest_known = self.routing.neighbours(target)[0]
                if closest.distance(target) < closest_known.distance(target):
                    self.wire.send_find_node(closest, target.pubkey)

        # add all nodes to the list
        for node in neighbours:
            self.ping(node)

    def recv_find_node(self, node, targetid):
        assert isinstance(node, Node)
        assert len(targetid) == 512 / 8
        assert isinstance(targetid, str)
        found = self.routing.neighbours(Node(targetid))
        log.debug('recv find_node', remoteid=node, found=len(found))
        self.wire.send_neighbours(node, found)
