from devp2p import discovery
from devp2p import kademlia
from devp2p import crypto
from devp2p.app import BaseApp
import gevent
import random

random.seed(42)

###############################


def test_address():
    Address = discovery.Address

    ipv4 = '127.98.19.21'
    ipv6 = '5aef:2b::8'
    port = 1

    a4 = Address(ipv4, port)
    aa4 = Address(ipv4, port)
    assert a4 == aa4
    a6 = Address(ipv6, port)
    aa6 = Address(ipv6, port)
    assert a6 == aa6

    b_a4 = a4.to_binary()
    assert a4 == Address.from_binary(*b_a4)

    b_a6 = a6.to_binary()
    assert len(b_a6) == 2
    assert a6 == Address.from_binary(*b_a6)

    e_a4 = a4.to_endpoint()
    assert a4 == Address.from_endpoint(e_a4)

    e_a6 = a6.to_endpoint()
    assert a6 == Address.from_endpoint(e_a6)

    assert len(b_a6[0]) == 16
    assert len(b_a4[0]) == 4
    assert isinstance(b_a6[1], str)
    assert len(b_a6[1]) == 2
    assert len(b_a4[1]) == 2


#############################

class AppMock(object):
    pass


class NodeDiscoveryMock(object):

    messages = []  # [(to_address, from_address, message), ...] shared between all instances

    def __init__(self, host, port, seed):
        self.address = discovery.Address(host, port)

        config = dict(p2p=dict())
        config_p2p = config['p2p']
        config_p2p['listen_host'] = host
        config_p2p['listen_port'] = port
        config_p2p['privkey_hex'] = crypto.sha3(seed).encode('hex')

        app = AppMock()
        app.config = config
        self.protocol = discovery.DiscoveryProtocol(app=app, transport=self)

    def send(self, address, message):
        assert isinstance(address, discovery.Address)
        assert address != self.address
        self.messages.append((address, self.address, message))

    def receive(self, address, message):
        assert isinstance(address, discovery.Address)
        self.protocol.receive(address, message)

    def poll(self):
        # try to receive a message
        for i, (to_address, from_address, message) in enumerate(self.messages):
            if to_address == self.address:
                del self.messages[i]
                self.receive(from_address, message)


def test_packing():
    """
    https://github.com/ethereum/go-ethereum/blob/develop/crypto/secp256k1/secp256.go#L299
    https://github.com/ethereum/go-ethereum/blob/develop/p2p/discover/udp.go#L343
    """

    # get two DiscoveryProtocol instances
    alice = NodeDiscoveryMock(host='127.0.0.1', port=1, seed='alice').protocol
    bob = NodeDiscoveryMock(host='127.0.0.1', port=1, seed='bob').protocol

    for cmd_id in alice.cmd_id_map.values():
        payload = ['a', ['b', 'c']]
        message = alice.pack(cmd_id, payload)
        r_pubkey, r_cmd_id, r_payload, mdc = bob.unpack(message)
        assert r_cmd_id == cmd_id
        assert r_payload == payload
        assert len(r_pubkey) == len(alice.pubkey)
        assert r_pubkey == alice.pubkey


def test_ping_pong():
    alice = NodeDiscoveryMock(host='127.0.0.1', port=1, seed='alice')
    bob = NodeDiscoveryMock(host='127.0.0.2', port=2, seed='bob')

    bob_node = alice.protocol.get_node(bob.protocol.pubkey, bob.address)
    alice.protocol.kademlia.ping(bob_node)
    assert len(NodeDiscoveryMock.messages) == 1
    # inspect message in queue
    msg = NodeDiscoveryMock.messages[0][2]
    remote_pubkey, cmd_id, payload, mdc = bob.protocol.unpack(msg)
    assert cmd_id == alice.protocol.cmd_id_map['ping']
    bob.poll()  # receives ping, sends pong
    assert len(NodeDiscoveryMock.messages) == 1
    alice.poll()  # receives pong
    assert len(NodeDiscoveryMock.messages) == 0


# ############ test with real UDP ##################

def get_app(port, seed):
    config = dict(p2p=dict())
    config_p2p = config['p2p']
    config_p2p['listen_host'] = '127.0.0.1'
    config_p2p['listen_port'] = port
    config_p2p['privkey_hex'] = crypto.sha3(seed).encode('hex')
    config_p2p['bootstrap_nodes'] = []
    # create app
    app = BaseApp(config)
    discovery.NodeDiscovery.register_with_app(app)
    return app


def test_ping_pong_udp():
    alice_app = get_app(30000, 'alice')
    alice_app.start()
    alice_discovery = alice_app.services.discovery
    bob_app = get_app(30001, 'bob')
    bob_app.start()
    bob_discovery = bob_app.services.discovery

    gevent.sleep(0.1)
    bob_node = alice_discovery.protocol.get_node(bob_discovery.protocol.pubkey,
                                                 bob_discovery.address)
    assert bob_node not in alice_discovery.protocol.kademlia.routing
    alice_discovery.protocol.kademlia.ping(bob_node)
    assert bob_node not in alice_discovery.protocol.kademlia.routing
    gevent.sleep(0.1)
    bob_app.stop()
    alice_app.stop()
    assert bob_node in alice_discovery.protocol.kademlia.routing


def test_bootstrap_udp():
    """
    startup num_apps udp server and node applications
    """

    # set timeout to something more tolerant
    kademlia.k_request_timeout = 10000.

    num_apps = 6
    apps = []
    for i in range(num_apps):
        app = get_app(30002 + i, 'app%d' % i)
        app.start()
        apps.append(app)

    gevent.sleep(0.1)
    sleep_delay = 1  # we need to wait for the packets to be delivered

    kproto = lambda app: app.services.discovery.protocol.kademlia
    this_node = lambda app: kproto(app).this_node

    boot_node = this_node(apps[0])
    assert boot_node.address

    for app in apps[1:]:
        print 'test bootstrap from=%s to=%s' % (this_node(app), boot_node)
        kproto(app).bootstrap([boot_node])
        gevent.sleep(sleep_delay)

    gevent.sleep(sleep_delay * 2)

    for app in apps[1:]:
        print 'test find_node from=%s' % (this_node(app))
        kproto(app).find_node(this_node(app).id)
        gevent.sleep(sleep_delay)

    gevent.sleep(sleep_delay * 2)

    for app in apps:
        app.stop()

    # now all nodes should know each other
    for i, app in enumerate(apps):
        num = len(kproto(app).routing)
        print num
        if i < len(apps) / 2:  # only the first half has enough time to get all updates
            assert num >= num_apps - 1


def main():
    "test connecting nodes"

    # stop on every unhandled exception!
    gevent.get_hub().SYSTEM_ERROR = BaseException  # (KeyboardInterrupt, SystemExit, SystemError)

    app = get_app(30304, 'theapp')
    # app.config['p2p']['listen_host'] = '127.0.0.1'
    app.config['p2p']['listen_host'] = '0.0.0.0'

    print "this node is"
    proto = app.services.discovery.protocol.kademlia
    this_node = proto.this_node
    print this_node.pubkey.encode('hex')

    # add external node

    go_local = 'enode://6ed2fecb28ff17dec8647f08aa4368b57790000e0e9b33a7b91f32c41b6ca9ba21600e9a8c44248ce63a71544388c6745fa291f88f8b81e109ba3da11f7b41b9@127.0.0.1:30303'

    go_bootstrap = 'enode://6cdd090303f394a1cac34ecc9f7cda18127eafa2a3a06de39f6d920b0e583e062a7362097c7c65ee490a758b442acd5c80c6fce4b148c6a391e946b45131365b@54.169.166.226:30303'

    cpp_bootstrap = 'enode://24f904a876975ab5c7acbedc8ec26e6f7559b527c073c6e822049fee4df78f2e9c74840587355a068f2cdb36942679f7a377a6d8c5713ccf40b1d4b99046bba0@5.1.83.226:30303'

    n1 = 'enode://1d799d32547761cf66250f94b4ac1ebfc3246ce9bd87fbf90ef8d770faf48c4d96290ea0c72183d6c1ddca3d2725dad018a6c1c5d1971dbaa182792fa937e89d@162.247.54.200:1024'
    n2 = 'enode://1976e20d6ec2de2dd4df34d8e949994dc333da58c967c62ca84b4d545d3305942207565153e94367f5d571ef79ce6da93c5258e88ca14788c96fbbac40f4a4c7@52.0.216.64:30303'
    n3 = 'enode://14bb48727c8a103057ba06cc010c810e9d4beef746c54d948b681218195b3f1780945300c2534d422d6069f7a0e378c450db380f8efff8b4eccbb48c0c5bb9e8@179.218.168.19:30303'

    nb = 'enode://1976e20d6ec2de2dd4df34d8e949994dc333da58c967c62ca84b4d545d3305942207565153e94367f5d571ef79ce6da93c5258e88ca14788c96fbbac40f4a4c7@52.0.216.64:30303'

    node_uri = cpp_bootstrap

    r_node = discovery.Node.from_uri(node_uri)
    print "remote node is", r_node
    # add node to the routing table

    print "START & TEST BOOTSTRAP"
    app.config['p2p']['bootstrap_nodes'] = [node_uri]
    app.start()

    gevent.sleep(2.)
    print "TEST FIND_NODE"
    for i in range(10):
        nodeid = kademlia.random_nodeid()
        assert isinstance(nodeid, type(this_node.id))
        proto.find_node(nodeid)
    gevent.sleep(1.)

    pinged = lambda: set(n for t, n, r in proto._expected_pongs.values())

    for i in range(10):
        print 'num nodes', len(proto.routing)
        gevent.sleep(1)
        # proto.find_node(this_node.id)
        # for node in proto.routing:
        proto.ping(r_node)
        # proto.find_node(this_node.id)

    print 'nodes in routing'
    for node in proto.routing:
        print node.to_uri()
    print 'nodes we are waiting for pongs'

    for node in pinged():
        print node.to_uri()


if __name__ == '__main__':
    import ethereum.slogging

    ethereum.slogging.configure(config_string=':debug')
    main()


"""
unexpected pongs from cpp client

case:
    bootstrap pubkey does not match



versions would be good
i get a ping reply by 2 nodes



"""
