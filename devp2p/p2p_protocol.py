import time
import gevent
from rlp import sedes
from multiplexer import Packet
from protocol import BaseProtocol
import slogging


log = slogging.get_logger('protocol.p2p')


class P2PProtocol(BaseProtocol):

    """
    DEV P2P Wire Protocol
    https://github.com/ethereum/wiki/wiki/%C3%90%CE%9EVp2p-Wire-Protocol
    """
    protocol_id = 0
    name = 'p2p'
    version = 3
    max_cmd_id = 15

    def __init__(self, peer, service):
        # required by P2PProtocol
        self.config = peer.config
        assert hasattr(peer, 'capabilities')
        assert callable(peer.stop)
        assert callable(peer.receive_hello)
        super(P2PProtocol, self).__init__(peer, service)

    class ping(BaseProtocol.command):
        cmd_id = 1

        def receive(self, proto, data):
            proto.send_pong()

    class pong(BaseProtocol.command):
        cmd_id = 2

    class hello(BaseProtocol.command):
        cmd_id = 0

        structure = [
            ('version', sedes.big_endian_int),
            ('client_version', sedes.binary),
            ('capabilities', sedes.CountableList(sedes.List([sedes.binary, sedes.big_endian_int]))),
            ('listen_port', sedes.big_endian_int),
            ('nodeid', sedes.binary)
        ]

        def create(self, proto):
            return dict(version=proto.version,
                        client_version=proto.config['client_version'],
                        capabilities=proto.peer.capabilities,
                        listen_port=proto.config['p2p']['listen_port'],
                        nodeid=proto.config['p2p']['nodeid'],
                        )

        def receive(self, proto, data):
            log.debug('receive_hello', peer=proto.peer, version=data['version'])
            reasons = proto.disconnect.reason
            if data['nodeid'] == proto.config['p2p']['nodeid']:
                log.debug('connected myself')
                return proto.send_disconnect(reason=reasons.connected_to_self)
            if data['version'] != proto.version:
                log.debug('incompatible network protocols', peer=proto.peer,
                          expected=proto.version, received=data['version'])
                return proto.send_disconnect(reason=reasons.incompatibel_p2p_version)

            proto.peer.receive_hello(**data)

    @classmethod
    def get_hello_packet(cls, peer):
        "special: we need this packet before the protcol can be initalized"
        res = dict(version=cls.version,
                   client_version=peer.config['client_version'],
                   capabilities=peer.capabilities,
                   listen_port=peer.config['p2p']['listen_port'],
                   nodeid=peer.config['p2p']['nodeid'])
        payload = cls.hello.encode_payload(res)
        return Packet(cls.protocol_id, cls.hello.cmd_id, payload=payload)

    class disconnect(BaseProtocol.command):
        cmd_id = 3
        structure = [('reason', sedes.big_endian_int)]

        class reason(object):
            disconnect_requested = 0
            tcp_sub_system_error = 1
            bad_protocol = 2         # e.g. a malformed message, bad RLP, incorrect magic number
            useless_peer = 3
            too_many_peers = 4
            already_connected = 5
            incompatibel_p2p_version = 6
            null_node_identity_received = 7
            client_quitting = 8
            unexpected_identity = 9  # i.e. a different identity to a previous connection or
            #                          what a trusted peer told us
            connected_to_self = 10
            timeout = 11             # i.e. nothing received since sending last ping
            other = 16               # Some other reason specific to a subprotocol

        def reason_name(self, id):
            return [k for k, v in self.reason.__dict__.items() if v == id][0]

        def create(self, proto, reason=reason.client_quitting):
            assert self.reason_name(reason)
            log.debug('send_disconnect', peer=proto.peer, reason=self.reason_name(reason))
            # proto.peer.stop()  # FIXME
            return dict(reason=reason)

        def receive(self, proto, data):
            log.debug('receive_disconnect', peer=proto.peer,
                      reason=self.reason_name(data['reason']))
            proto.peer.stop()


log = slogging.get_logger('p2p.ctxmonitor')


class ConnectionMonitor(gevent.Greenlet):
    ping_interval = 1.
    response_delay_threshold = 2.
    max_samples = 10

    def __init__(self, peer, service):
        assert isinstance(self, P2PProtocol)
        super(ConnectionMonitor, self).__init__(peer, service)
        self.samples = []
        self.last_request = time.time()
        self.last_response = time.time()

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
        return sum(self.samples[:num_samples]) / num_samples

    def _run(self):
        log.debug('started', monitor=self)
        while True:
            log.debug('pinging', monitor=self)
            self.send_ping()
            gevent.sleep(self.ping_interval)
            log.debug('latency', monitor=self, latency=self.latency)
            if self.last_response_elapsed > self.response_delay_threshold:
                log.debug('unresponsive_peer', monitor=self)
                self.stop()
