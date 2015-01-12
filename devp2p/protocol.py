import time
import gevent
import struct
import json
from gevent import Greenlet
from pyethereum.utils import big_endian_to_int as idec
import serialization
import slogging
log = slogging.get_logger('protocol.p2p').warn

# packetize

header_length = 5


def decode_packet_header(message):
    header = message[:header_length]
    payload_len, cmd_id = struct.unpack('>BL', header)
    return payload_len, cmd_id


def encode_packet(cmd_id, data):
    payload = json.dumps(data)
    header = struct.pack('>BL', len(payload), cmd_id)
    assert len(header) == header_length
    return header + payload


class BaseProtocol(object):
    """
    Component which translates between
        messages from the p2p wire
        and services

    Keeps necessary state for the peer
        e.g. last ping, sent/received hashes, ...


    """
    name = ''
    cmd_map = {} # cmd_name: cmd_id

    def __init__(self, peer, cmd_offset=0):
        self.peer = peer
        self.cmd_offset = cmd_offset
        self.cmd_map = dict((k, v + cmd_offset) for k, v in self.cmd_map.items())
        self.rev_cmd_map = dict((v, k) for k, v in self.cmd_map.items())

    def handle_message(self, cmd_id, payload):
        data = json.loads(payload)
        cmd_name = 'receive_%s' % self.rev_cmd_map[cmd_id]
        cmd = getattr(self, cmd_name)
        cmd(data)

    def stop(self):
        "called when peer disconnects, use to cleanup"
        pass


class ETHProtocol(BaseProtocol):
    name = 'eth'
    cmd_map = dict(status=0)
    status_sent = False
    status_received = False

    def send_status(self):
        data = dict(head_number=1,
                    eth_version=49)
        packet = encode_packet(self.cmd_map['status'], data)
        self.peer._send_packet(packet)
        self.status_sent = True

    def receive_status(self, data):
        # tell peermanager about spoken protocols
        if not self.status_sent:
            self.send_status()
        self.status_received = True


class SHHProtocol(BaseProtocol):
    name = 'shh'
    cmd_map = dict(gossip=0)

    def send_gossip(self, gossip=''):
        data = dict(gossip=gossip)
        packet = encode_packet(self.cmd_map['gossip'], data)
        self.peer._send_packet(packet)

    def receive_gossip(self, data):
        pass


class ConnectionMonitor(Greenlet):
    ping_interval = 1.
    response_delay_threshold = 2.
    max_samples = 10

    def __init__(self, p2pprotocol):
        Greenlet.__init__(self)
        self.p2pprotocol = p2pprotocol
        self.samples = []
        self.last_request = time.time()
        self.last_response = time.time()

    def __repr__(self):
        return '<ConnectionMonitor(r)>'

    def track_request(self):
        self.last_request = time.time()

    def track_response(self):
        self.last_response = time.time()
        dt = self.last_response - self.last_request
        self.samples.append(dt)
        if len(self.samples) > self.max_samples:
            self.samples.pop(0)

    @property
    def last_response_elapsed(self):
        return time.time() - self.last_response

    @property
    def latency(self, num_samples=0):
        if not self.samples:
            return None
        num_samples = min(num_samples or self.max_samples, len(self.samples))
        return sum(self.samples[:num_samples])/num_samples

    def _run(self):
        log('p2p.peer.monitor.started', monitor=self)
        while True:
            log('p2p.peer.monitor.pinging', monitor=self)
            self.p2pprotocol.send_ping()
            gevent.sleep(self.ping_interval)
            log('p2p.peer.monitor.latency', monitor=self, latency=self.latency)
            if self.last_response_elapsed > self.response_delay_threshold:
                log('p2p.peer.monitor.unresponsive_peer', monitor=self)
                self.stop()

    def stop(self):
        self.kill()


class P2PProtocol(BaseProtocol):
    name = 'p2p'
    version = 2

    # IF CHANGED, DO: git tag 0.6.<ETHEREUM_PROTOCOL_VERSION>
    CLIENT_VERSION = 'Ethereum(py)/%s/%s' % (sys.platform, '0.7.0')
    # the node s Unique Identifier and is the 512-bit hash that serves to
    # identify the node.
    NODE_ID = sha3('test')  # set in config
    NETWORK_ID = 0
    SYNCHRONIZATION_TOKEN = 0x22400891

    cmd_map = dict(hello=0, ping=1, pong=2, disconnect=3, getpeers=4, peers=5)

    def __init__(self, peer, cmd_offset, is_inititator=False):
        """
        initiater sends initial hello
        """
        super(P2PProtocol, self).__init__(peer, cmd_offset)
        self.is_inititator = is_inititator
        self.hello_received = False
        self.connection_monitor = ConnectionMonitor(self)
        self._handshake()

    def stop(self):
        self.connection_monitor.stop()

    @property
    def peermanager(self):
        return self.peer.peermanager

    @property
    def config(self):
        return self.peermanager.app.config

    @property
    def nodeid(self):
        return self.config.get('network', 'node_id')

    def _handshake(self):
        if self.is_inititator:
            self.send_hello()

    def _send_packet(self, cmd_name, data):
        assert isinstance(list, data)
        cmd_id = self.cmd_map['cmd_name'] + self.cmd_offset
        msg = serialization.Serializer.dump_packet([cmd_id] + data)
        self.peer.send(msg)

    def send_ping(self):
        log('p2p.send_ping', peer=self.peer)
        self._send_packet('ping', [])
        self.connection_monitor.track_request()

    def receive_ping(self, data):
        log('p2p.receive_ping', peer=self.peer)
        self.send_pong()

    def send_pong(self):
        log('p2p.send_pong', peer=self.peer)
        self._send_packet('pong')

    def receive_pong(self, data):
        log('p2p.receive_pong', peer=self.peer)
        self.connection_monitor.track_response()

    def send_disconnect(self, reason=''):
        log('p2p.send_disconnect', peer=self.peer, reason=reason)
        data = []
        if reason:
            data.append(serialization.Serializer.disconnect_reasons_map[reason])  # FIXME
        self._send_packet('disconnect', data)
        self.peer.stop()

    def receive_disconnect(self, data):
        reason = serialization.Serializer.disconnect_reasons_map_by_id[idec(data[0])]
        log('p2p.receive_disconnect', peer=self.peer, reason=reason)
        self.peer.stop()


    def send_getpeers(self):
        return self._send_packet('getpeers')

    def receive_getpeers(self):
        self.send_peers()


    def send_peers(self):
        '''
        :param peers: a sequence of (ip, port, pid)
        :return: None if no peers
        '''
        data = []
        for peer in self.peermanager.peers:
            ip, port = peer.ip_port
            assert ip.count('.') == 3
            ip = ''.join(chr(int(x)) for x in ip.split('.'))
            data.append([ip, port, peer.nodeid])
        return self._send_packet('peers', data)

    def receive_peers(self, data):
        pass # FIXME


    def send_hello(self):
        """
        0x01 Hello: [0x01: P, protocolVersion: P, clientVersion: B, [cap0: B, cap1: B, ...]
        listenPort: P, id: B_64]

        protocolVersion: The underlying network protocol. 0
        clientVersion: The underlying client. A user-readable string.
        capN: A peer-network capability code, readable ASCII and 3 letters. Currently only "eth
        and "shh" are known.
        listenPort: The port on which the peer is listening for an incoming connection.
        id: The identity and public key of the peer.
        """
        log('p2p.send_hello', peer=self.peer)
        capabilities = [(p.name, p.version) for p in self.peer.protocols]

        data = [
            self.version,
            self.CLIENT_VERSION,
            capabilities,
            self.config.getint('network', 'listen_port'),
            self.nodeid
            ]
        self._send_packet('hello', data)


    def _recv_hello(self, data):
        log('p2p.receive_hello', peer=self.peer)
        # 0x01 Hello: [0x01: P, protocolVersion: P, clientVersion: B, [cap0: B,
        # cap1: B, ...], listenPort: P, id: B_64]
        _decode = (idec, str, list, idec, str)
        try:
            data = [_decode[i](x) for i, x in enumerate(data)]
            network_protocol_version, client_version = data[0], data[1]
            capabilities, listen_port, node_id = data[2], data[3], data[4]
            self.capabilities = [(p, ord(v)) for p, v in capabilities]
        except (IndexError, ValueError) as e:
            log('could not decode hello', peer=self, error=e)
            return self.send_Disconnect(reason='Incompatible network protocols')

        assert node_id
        if node_id == self.nodeid:
            log.critical('connected myself')
            return self.send_Disconnect(reason='Incompatible network protocols')

        self.capabilities = [(p, ord(v)) for p, v in capabilities]
        log('received hello',
            peer=self,
            network_protocol_version=network_protocol_version,
            node_id=node_id.encode('hex'),
            client_version=client_version,
            capabilities=self.capabilities)

        if network_protocol_version != self.version:
            log('incompatible network protocols',
                peer=self,
                expected=self.version,
                received=network_protocol_version)
            return self.send_Disconnect(reason='Incompatible network protocols')

        self.hello_received = True
        self.peer.client_version = client_version
        self.peer.nodeid = node_id
        self.peer.listen_port = listen_port  # replace connection port with listen port

        if not self.is_inititator:
            self.send_hello()

        # tell peermanager about spoken protocols
        self.peer.peermanager.on_hello_received(self, data)
        self.connection_monitor.start()

