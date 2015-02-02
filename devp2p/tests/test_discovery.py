import ConfigParser
from devp2p import discovery
from devp2p import crypto
from devp2p.app import BaseApp
import gevent

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
    assert a6 == Address.from_binary(*b_a6)
    assert len(b_a6[0]) == 16
    assert len(b_a4[0]) == 4
    assert len(b_a6[1]) == 1
    assert len(b_a4[1]) == 1


#############################

class AppMock(object):
    pass


class NodeDiscoveryMock(object):

    messages = []  # [(to_address, from_address, message), ...] shared between all instances

    def __init__(self, host, port, seed):
        self.address = discovery.Address(host, port)

        config = ConfigParser.ConfigParser()
        config.add_section('p2p')
        config.set('p2p', 'listen_host', host)
        config.set('p2p', 'listen_port', str(port))
        config.set('p2p', 'privkey_hex', crypto.sha3(seed).encode('hex'))

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
    # get two DiscoveryProtocol instances
    alice = NodeDiscoveryMock(host='127.0.0.1', port=1, seed='alice').protocol
    bob = NodeDiscoveryMock(host='127.0.0.1', port=1, seed='bob').protocol

    for cmd_id in alice.cmd_id_map.values():
        payload = ['a', ['b', 'c']]
        message = alice.pack(cmd_id, payload)
        r_pubkey, r_cmd_id, r_payload, mdc = bob.unpack(message)
        assert r_cmd_id == cmd_id
        assert r_pubkey == alice.pubkey
        assert r_payload == payload


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


############## test with real UDP ##################

def get_app(port, seed):
    config = ConfigParser.ConfigParser()
    config.add_section('p2p')
    config.set('p2p', 'listen_host', '127.0.0.1')
    config.set('p2p', 'listen_port', str(port))
    config.set('p2p', 'privkey_hex', crypto.sha3(seed).encode('hex'))
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

    bob_node = alice_discovery.protocol.get_node(bob_discovery.protocol.pubkey,
                                                 bob_discovery.address)
    alice_discovery.protocol.kademlia.ping(bob_node)
    gevent.sleep(0.1)
    bob_app.stop()
    alice_app.stop()


def test_bootstrap_udp():
    """
    startup num_apps udp server and node applications
    """
    num_apps = 10
    apps = []
    for i in range(num_apps):
        app = get_app(30002 + i, 'app%d' % i)
        app.start()
        apps.append(app)

    def kademlia(i):
        return apps[i].services.discovery.protocol.kademlia

    boot_node = kademlia(0).this_node
    assert boot_node.address

    for i, app in enumerate(apps):
        kademlia(i).ping(boot_node)

    for i, app in enumerate(apps):
        kademlia(i).bootstrap([boot_node])
    total_0 = sum(len(kademlia(i).routing) for i, app in enumerate(apps))

    for i, app in enumerate(apps):
        kademlia(i).bootstrap([boot_node])
    total_1 = sum(len(kademlia(i).routing) for i, app in enumerate(apps))

    gevent.sleep(0.1)

    for app in apps:
        app.stop()

    print('total entries round #0: {0}'.format(total_0))
    print('total entries round #1: {0}'.format(total_1))
