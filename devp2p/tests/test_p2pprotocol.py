from devp2p.protocol import P2PProtocol

# notify peer of successfulll handshake!
# so other protocols get registered
# so other protocols can do their handshake


class PeerMock(object):
    packets = []
    config = dict(p2p=dict(listen_port=3000, nodeid='\x00' * 64), client_version='devp2p 0.1.1')
    capabilities = [('p2p', 2), ('eth', 57)]
    stopped = False
    hello_received = False

    def receive_hello(self, version, client_version, capabilities, listen_port, nodeid):
        for name, version in capabilities:
            assert isinstance(name, str)
            assert isinstance(version, int)
        self.hello_received = True

    def send_packet(self, packet):
        print 'sending', packet
        self.packets.append(packet)

    def stop(self):
        self.stopped = True


def test_protocol():
    peer = PeerMock()
    proto = P2PProtocol(peer=peer)

    # ping pong
    proto.send_ping()
    ping_packet = peer.packets.pop()
    proto._receive_ping(ping_packet)
    pong_packet = peer.packets.pop()
    proto._receive_pong(pong_packet)
    assert not peer.packets

    # hello (fails same nodeid)
    proto.send_hello()
    hello_packet = peer.packets.pop()
    proto._receive_hello(hello_packet)
    disconnect_packet = peer.packets.pop()  # same nodeid
    assert peer.stopped
    peer.stopped = False

    # hello (works)
    proto.send_hello()
    hello_packet = peer.packets.pop()
    peer.config['p2p']['nodeid'] = '\x01' * 64  # change nodeid
    proto._receive_hello(hello_packet)
    assert not peer.packets
    assert not peer.stopped
    assert peer.hello_received

    # disconnect
    proto.send_disconnect(reason=proto.disconnect.reason.disconnect_requested)
    disconnect_packet = peer.packets.pop()
    proto._receive_disconnect(disconnect_packet)
    assert not peer.packets
    assert peer.stopped


def test_callback():
    peer = PeerMock()
    proto = P2PProtocol(peer=peer)

    # setup callback
    r = []

    def cb(_proto, data):
        assert _proto == proto
        r.append(data)
    proto.receive_pong_callbacks.append(cb)

    # trigger
    proto.send_ping()
    ping_packet = peer.packets.pop()
    proto._receive_ping(ping_packet)
    pong_packet = peer.packets.pop()
    proto._receive_pong(pong_packet)
    assert not peer.packets
    assert len(r) == 1
    assert r[0] == dict()
