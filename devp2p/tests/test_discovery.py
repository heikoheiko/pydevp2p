import ConfigParser
from devp2p import discovery
from devp2p import crypto
from devp2p.app import BaseApp
import gevent


class AppMock(object):
    pass


class NodeDiscoveryMock(object):

    messages = []  # [(to_address, from_address, message), ...] shared between all instances

    def __init__(self, host, port, seed):
        self.address = discovery.Address('udp', host, port)

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
    alice.protocol.send_ping(bob_node)
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
    alice_discovery.protocol.send_ping(bob_node)
    print 'waiting'
    gevent.sleep(0.1)
    print 'finished'
