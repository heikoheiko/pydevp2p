import gevent
from collections import OrderedDict
from protocol import BaseProtocol, P2PProtocol
import multiplexer
from muxsession import MultiplexedSession
import slogging

log = slogging.get_logger('peer')


class Peer(gevent.Greenlet):

    mux = None

    def __init__(self, peermanager, connection, remote_pubkey=None):
        super(Peer, self).__init__()
        self.peermanager = peermanager
        self.connection = connection
        self.config = peermanager.config
        self.protocols = OrderedDict()

        log.debug('peer init', peer=self)

        # create and register p2p protocol
        p2p_proto = P2PProtocol(self)
        self.register_protocol(p2p_proto)
        hello_packet = p2p_proto.create_hello()

        # create multiplexed encrypted session
        privkey = self.config['p2p']['privkey']
        self.mux = MultiplexedSession(privkey, hello_packet,
                                      token_by_pubkey=dict(), remote_pubkey=remote_pubkey)
        self.mux.add_protocol(p2p_proto.protocol_id)
        # learned and set on handshake
        self.nodeid = None
        self.client_version = None
        self.listen_port = None

    def __repr__(self):
        return '<Peer(%r) thread=%r>' % (self.connection.getpeername(), id(gevent.getcurrent()))

    @property
    def ip_port(self):
        return self.connection.getpeername()

    # protocols (distinguish between available and active protocols)
    def register_protocol(self, protocol):
        assert isinstance(protocol, BaseProtocol)
        assert protocol.name not in self.protocols
        log.debug('registering protocol', protocol=protocol.name, peer=self)
        self.protocols[protocol.name] = protocol
        if self.mux:
            self.mux.add_protocol(protocol.protocol_id)

    def deregister_protocol(self, protocol):
        assert isinstance(protocol, BaseProtocol)
        del self.protocols[protocol.name]

    def has_protocol(self, name):
        assert isinstance(name, str)
        return name in self.protocols

    def receive_hello(self, version, client_version, capabilities, listen_port, nodeid):
        for name, version in capabilities:
            assert isinstance(name, str)
            assert isinstance(version, int)

    @property
    def capabilities(self):
        "used by protocol hello"   # FIXME, peermanager needs to know!
        return [(p.name, p.version) for p in self.protocols.values()]

    # sending p2p messages

    def send_packet(self, packet):
        # rewrite cmd id / future FIXME  to packet.protocol_id
        for i, protocol in enumerate(self.protocols.values()):
            if packet.protocol_id > i:
                packet.cmd_id += protocol.max_cmd_id
        packet.protocol_id = 0
        # done rewrite
        self.mux.add_packet(packet)

    # receiving p2p messages

    def _handle_packet(self, packet):
        assert isinstance(packet, multiplexer.Packet)
        log.debug('handling packet', cmd_id=packet.cmd_id, peer=self)
        # packet.protocol_id not yet used. old adaptive cmd_ids instead
        # future FIXME  to packet.protocol_id

        # get protocol and protocol.cmd_id from packet.cmd_id
        max_id = 0
        found = False
        for protocol in self.protocols.values():
            if packet.cmd_id < max_id + protocol.max_cmd_id:
                found = True
                packet.cmd_id -= max_id  # rewrite cmd_id
                break
            max_id += protocol.max_cmd_id
        if not found:
            raise Exception('no protocol for id %s' % packet.cmd_id)
        # done get protocol
        protocol.receive_packet(packet)

    def send(self, data):
        if data:
            log.debug('send', size=len(data))
            self.connection.sendall(data)  # check if gevent chunkes and switchs contexts
            log.debug('send sent', size=len(data))

    def _run(self):
        """
        Loop through queues

        fixme: option to wait for any finished event
             gevent.wait(objects=None, timeout=None, count=None)
             and wrap connection.wait_ready in an event

        mux.evt
        and spawn a wait_read which triggers an event

        """
        default_timeout = 0.01
        while True:
            # read egress data from the multiplexer queue
            emsg = self.mux.get_message()
            if emsg:
                self.send(emsg)
                timeout = 0
            else:
                timeout = default_timeout
            try:
                try:
                    gevent.socket.wait_read(self.connection.fileno(), timeout=timeout)
                except gevent.socket.timeout:
                    pass
                imsg = self.connection.recv(4096)
                if not imsg:
                    log.debug('loop_socket.not_data', peer=self)
                    self.stop()
                    break
                self.mux.add_message(imsg)
            except gevent.timeout:
                pass
            packet = self.mux.get_packet()
            if packet:
                self._handle_packet(packet)

    def stop(self):
        log.debug('stopped', thread=gevent.getcurrent())
        for p in self.protocols.values():
            p.stop()
        self.peermanager.peers.remove(self)
        self.kill()
