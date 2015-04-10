import gevent
import operator
from collections import OrderedDict
from protocol import BaseProtocol
from p2p_protocol import P2PProtocol
from service import WiredService
import multiplexer
from muxsession import MultiplexedSession
import slogging
import gevent.socket

log = slogging.get_logger('peer')


class Peer(gevent.Greenlet):

    remote_node = None
    remote_client_version = ''
    wait_read_timeout = 0.001

    def __init__(self, peermanager, connection, remote_pubkey=None):  # FIXME node vs remote_pubkey
        super(Peer, self).__init__()
        self.peermanager = peermanager
        self.connection = connection
        self.config = peermanager.config
        self.protocols = OrderedDict()

        log.debug('peer init', peer=self)

        # create multiplexed encrypted session
        privkey = self.config['node']['privkey_hex'].decode('hex')
        hello_packet = P2PProtocol.get_hello_packet(self)
        self.mux = MultiplexedSession(privkey, hello_packet,
                                      token_by_pubkey=dict(), remote_pubkey=remote_pubkey)

        # register p2p protocol
        assert issubclass(self.peermanager.wire_protocol, P2PProtocol)
        self.connect_service(self.peermanager)

    def __repr__(self):
        try:
            pn = self.connection.getpeername()
        except gevent.socket.error:
            pn = ('not ready',)
        return '<Peer%r %s>' % (pn, self.remote_client_version)

    @property
    def ip_port(self):
        return self.connection.getpeername()

    def connect_service(self, service):
        assert isinstance(service, WiredService)
        protocol_class = service.wire_protocol
        assert issubclass(protocol_class, BaseProtocol)
        # create protcol instance which connects peer with serivce
        protocol = protocol_class(self, service)
        # register protocol
        assert protocol_class not in self.protocols
        log.debug('registering protocol', protocol=protocol.name, peer=self)
        self.protocols[protocol_class] = protocol
        self.mux.add_protocol(protocol.protocol_id)
        protocol.start()

    def has_protocol(self, protocol):
        assert issubclass(protocol, BaseProtocol)
        return protocol in self.protocols

    def receive_hello(self, version, client_version, capabilities, listen_port, nodeid):
        # register in common protocols
        log.info('reveived hello', version=version,
                 client_version=client_version, capabilities=capabilities)
        self.remote_client_version = client_version

        log.info('connecting services', services=self.peermanager.wired_services)
        remote_services = dict((name, version) for name, version in capabilities)
        for service in sorted(self.peermanager.wired_services, key=operator.attrgetter('name')):
            proto = service.wire_protocol
            assert isinstance(service, WiredService)
            if proto.name in remote_services:
                if remote_services[proto.name] == proto.version:
                    if service != self.peermanager:  # p2p protcol already registered
                        self.connect_service(service)
                else:
                    log.info('wrong version', service=proto.name, local_version=proto.version,
                             remote_version=remote_services[proto.name])

    @property
    def capabilities(self):
        return [(s.wire_protocol.name, s.wire_protocol.version)
                for s in self.peermanager.wired_services]

    # sending p2p messages

    def send_packet(self, packet):
        # rewrite cmd id / future FIXME  to packet.protocol_id
        protocol = list(self.protocols.values())[packet.protocol_id]
        log.debug('send packet', cmd=protocol.cmd_by_id[packet.cmd_id], protcol=protocol.name,
                  peer=self)
        # rewrite cmd_id  # FIXME
        for i, protocol in enumerate(self.protocols.values()):
            if packet.protocol_id > i:
                packet.cmd_id += (0 if protocol.max_cmd_id == 0 else protocol.max_cmd_id + 1)
            if packet.protocol_id == protocol.protocol_id:
                break

        packet.protocol_id = 0
        # done rewrite
        self.mux.add_packet(packet)

    # receiving p2p messages

    def protocol_cmd_id_from_packet(self, packet):
        # packet.protocol_id not yet used. old adaptive cmd_ids instead
        # future FIXME  to packet.protocol_id

        # get protocol and protocol.cmd_id from packet.cmd_id
        max_id = 0
        assert packet.protocol_id == 0  # FIXME, should be used by other peers
        for protocol in self.protocols.values():
            if packet.cmd_id < max_id + protocol.max_cmd_id + 1:
                return protocol, packet.cmd_id - (0 if max_id == 0 else max_id + 1)
            max_id += protocol.max_cmd_id

        raise Exception('no protocol for id %s' % packet.cmd_id)

    def _handle_packet(self, packet):
        assert isinstance(packet, multiplexer.Packet)
        protocol, cmd_id = self.protocol_cmd_id_from_packet(packet)
        log.debug('recv packet', cmd=protocol.cmd_by_id[
                  cmd_id], protocol=protocol.name, orig_cmd_id=packet.cmd_id)
        packet.cmd_id = cmd_id  # rewrite
        protocol.receive_packet(packet)

    def send(self, data):
        if data:
            try:
                self.connection.sendall(data)  # check if gevent chunkes and switches contexts
            except gevent.socket.error as e:
                log.info('write error', errno=e.errno, reason=e.strerror)
                if e.errno == 32:  # Broken pipe
                    self.stop()
                else:
                    raise e

    def _run(self):
        """
        Loop through queues

        fixme: option to wait for any finished event
             gevent.wait(objects=None, timeout=None, count=None)
             and wrap connection.wait_ready in an event

        mux.evt
        and spawn a wait_read which triggers an event

        """
        while True:
            # handle decoded packets
            while not self.mux.packet_queue.empty():
                self._handle_packet(self.mux.get_packet())

            # read egress data from the multiplexer queue
            emsg = self.mux.get_message()
            if emsg:
                self.send(emsg)
                timeout = 0
            else:
                timeout = self.wait_read_timeout
            try:
                #log.debug('polling data', peer=self, timeout=timeout)
                gevent.socket.wait_read(self.connection.fileno(), timeout=timeout)
                imsg = self.connection.recv(4096)
            except gevent.socket.timeout:
                continue
            except gevent.socket.error as e:
                log.info('read error', errno=e.errno, reason=e.strerror)
                if e.errno in(54, 60):  # (Connection reset by peer, timeout)
                    self.stop()
                else:
                    raise e

            if imsg:
                self.mux.add_message(imsg)
            else:
                log.debug('loop_socket.not_data', peer=self)
                self.stop()
                break

    def stop(self):
        log.debug('stopped', thread=gevent.getcurrent())
        for p in self.protocols.values():
            p.stop()
        self.peermanager.peers.remove(self)
        self.kill()
