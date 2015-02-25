import ConfigParser
from devp2p import discovery
from devp2p import kademlia
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


def node_by_uri(uri):
    scheme = 'enode://'
    assert uri.startswith(scheme) and '@' in uri and ':' in uri
    pubkey, ip_port = uri[len(scheme):].split('@')
    ip, port = ip_port.split(':')
    return discovery.Node(pubkey.decode('hex'), discovery.Address(ip, int(port)))


def main():
    "test connecting nodes"
    app = get_app(30303, 'theapp')
    #app.config.set('p2p', 'listen_host', '127.0.0.1')
    app.config.set('p2p', 'listen_host', '0.0.0.0')
    app.start()

    print "this node is"
    proto = app.services.discovery.protocol.kademlia
    this_node = proto.this_node
    print this_node.pubkey.encode('hex')

    gevent.sleep(0.5)

    # add external node

    local = 'enode://ab16b8c7fc1febb74ceedf1349944ffd4a04d11802451d02e808f08cb3b0c1c1a9c4e1efb7d309a762baa4c9c8da08890b3b712d1666b5b630d6c6a09cbba171@127.0.0.1:40404'

    go_bootstrap = 'enode://6cdd090303f394a1cac34ecc9f7cda18127eafa2a3a06de39f6d920b0e583e062a7362097c7c65ee490a758b442acd5c80c6fce4b148c6a391e946b45131365b@54.169.166.226:30303'

    cpp_bootstrap = 'enode://4a44599974518ea5b0f14c31c4463692ac0329cb84851f3435e6d1b18ee4eae4aa495f846a0fa1219bd58035671881d44423876e57db2abd57254d0197da0ebe@5.1.83.226:30303'

    r_node = node_by_uri(go_bootstrap)
    print "remote node is", r_node
    # add node to the routing table
    kademlia.k_request_timeout = 20.
    print "TEST PING BOOTSTRAPPING NODE"
    proto.ping(r_node)
    gevent.sleep(2.)
    print "TEST BOOTSTRAP"
    proto.bootstrap([r_node])
    gevent.sleep(2.)
    print "TEST FIND_NODE"
    proto.find_node(this_node.id)
    gevent.sleep(1.)

    while len(proto.routing) < 5:
        print 'num nodes', len(proto.routing)
        print 'TEST FIND MORE NODES (kill me)'
        proto.find_node(this_node.id)
        gevent.sleep(1)


if __name__ == '__main__':
    import pyethereum.slogging
    pyethereum.slogging.configure(config_string=':debug')
    main()
