import time
import networkx as nx
import matplotlib.pyplot as plt
import devp2p.kademlia
from test_kademlia_protocol import test_many
from collections import OrderedDict
import random

random.seed(42)


class ConnectableNodeBase(object):

    """
    to implement your conenction strategy override
        .select_targets (must)
        .connect_peers
    """
    k_max_node_id = devp2p.kademlia.k_max_node_id

    def __init__(self, proto, network, min_peers=5, max_peers=10):
        self.proto = proto
        self.network = network
        self.min_peers = min_peers
        self.max_peers = max_peers
        self.connections = []
        self.id = proto.this_node.id
        # list of dict(address=long, tolerance=long, connected=bool)
        # address is the id : long
        self.targets = list()

    def distance(self, other):
        return self.id ^ other.id

    def receive_connect(self, other):
        if len(self.connections) == self.max_peers:
            return False
        else:
            assert other not in self.connections
            self.connections.append(other)
            return True

    def receive_disconnect(self, other):
        assert other in self.connections
        self.connections.remove(other)

    def find_targets(self):
        "call find node to fill buckets with addresses close to the target"
        for t in self.targets:
            self.proto.find_node(t['address'])
            self.network.process()

    def connect_peers(self):
        """
        override to deal with situations where
            - you enter the method and have not enough slots to conenct your targets
            - your targets don't want to connect you
            - targets are not within the tolerace
            ...
        """
        assert self.targets
        # connect closest node to target id
        for t in self.targets:
            if len(self.connections) >= self.max_peers:
                break
            for knode in self.proto.routing.neighbours(devp2p.kademlia.Node.from_id(t['address'])):
                assert isinstance(knode, devp2p.kademlia.Node)
                # assure within tolerance
                if knode.id_distance(t['address']) < t['tolerance']:
                    # make sure we are not connected yet
                    remote = self.network[knode.id]
                    if remote not in self.connections:
                        if remote.receive_connect(self):
                            t['connected'] = True
                            self.connections.append(remote)
                            break

    def setup_targets(self):
        """
        calculate select target distances, addresses and tolerances
        """
        for i in range(self.min_peers):
            self.targets.append(dict(address=0, tolerance=0, connected=False))
            # NOT IMPLEMENTED HERE


class ConnectableNodeRandom(ConnectableNodeBase):

    def setup_targets(self):
        """
        connects random nodes
        """
        for i in range(self.min_peers):
            distance = random.randint(0, self.k_max_node_id)
            address = (self.id + distance) % (self.k_max_node_id + 1)
            tolerance = self.k_max_node_id / self.min_peers
            self.targets.append(dict(address=address, tolerance=tolerance, connected=False))


class ConnectableNodeRandomClose(ConnectableNodeBase):

    def setup_targets(self):
        """
        connects random nodes in the neighbourhood only
        """
        neighbourhood_distance = self.k_max_node_id / 10.
        for i in range(self.min_peers):
            distance = random.randint(0, neighbourhood_distance)
            address = (self.id + distance) % (self.k_max_node_id + 1)
            tolerance = self.k_max_node_id / self.min_peers
            self.targets.append(dict(address=address, tolerance=tolerance, connected=False))


def analyze(network):
    G = nx.Graph()

    def weight(a, b):
        # same node is weight == 1
        return 1 - a.distance(b) / devp2p.kademlia.k_max_node_id

    for node in network.values():
        for r in node.connections:
            G.add_edge(node, r, weight=weight(node, r))

    num_peers = [len(n.connections) for n in network.values()]
    metrics = OrderedDict(num_nodes=len(network))
    metrics['max_peers'] = max(num_peers)
    metrics['min_peers'] = min(num_peers)
    metrics['avg_peers'] = sum(num_peers) / len(num_peers)
    print 'calculating diameter'
    metrics['diameter '] = nx.diameter(G)
    print 'calcualting edge_connectivity'
    metrics['edge_connectivity'] = nx.edge_connectivity(G)
    print 'calculating avg_shortest_path'
    metrics['avg_shortest_path'] = nx.average_shortest_path_length(G)

    text = ''
    for k, v in metrics.items():
        text += '%s: %.2f\n' % (k, v)

    print 'layouting'
    pos = nx.spring_layout(G)
    plt.figure(figsize=(8, 8))
    nx.draw(G, pos, node_size=20, alpha=0.5, node_color="blue", with_labels=False)
    plt.text(0.02, 0.02, text, transform=plt.gca().transAxes)
    plt.axis('equal')
    outfile = 'network_graph.png'
    plt.savefig(outfile)
    print 'saved visualization to', outfile
    plt.ion()
    plt.show()
    while True:
        time.sleep(0.1)


def main(num_nodes=20):
    node_class = ConnectableNodeBase
    node_class = ConnectableNodeRandomClose

    print 'bootstrapping discovery protocols'
    kademlia_protocols = test_many(num_nodes)

    # create ConnectableNode instances
    print 'executing connection strategy'
    network = OrderedDict()  # node.id -> Node
    # .process executes all messages on the network
    network.process = lambda: kademlia_protocols[0].wire.process(kademlia_protocols)

    # wrap protos in connectable nodes and map via network
    for p in kademlia_protocols:
        cn = node_class(p, network)
        network[cn.id] = cn

    # setup targets
    for cn in network.values():
        cn.setup_targets()

    # lookup targets
    for cn in network.values():
        cn.find_targets()

    # connect peers
    for cn in network.values():
        cn.connect_peers()

    # analyze data
    # for i, cn in enumerate(network.values()):
    #     print i, len(cn.connections)
    analyze(network)  # slow for large networks


if __name__ == '__main__':
    # import pyethereum.slogging
    # pyethereum.slogging.configure(config_string=':debug')
    import sys
    if not len(sys.argv) == 2:
        print 'usage:%s <num_nodes>' % sys.argv[0]
        sys.exit(1)
    num_nodes = int(sys.argv[1])
    main(num_nodes)


"""
todos:
    colorize nodes being closest to 0, 1/4, 1/2, 3/4 of the id space
    minimal base class

    report simulation settings
    support alanlytics about nodes added to an established network
"""
