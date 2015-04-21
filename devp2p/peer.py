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
import rlpxcipher

log = slogging.get_logger('peer')


class Peer(gevent.Greenlet):

    remote_client_version = ''
    wait_read_timeout = 0.001

    def __init__(self, peermanager, connection, remote_pubkey=None):  # FIXME node vs remote_pubkey
        super(Peer, self).__init__()
        self.is_stopped = False
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

        # assure, we don't get messages while replies are not read
        self.safe_to_read = gevent.event.Event()
        self.safe_to_read.set()

    @property
    def remote_pubkey(self):
        "if peer is responder, then the remote_pubkey will not be available"
        "before the first packet is received"
        return self.mux.remote_pubkey

    def __repr__(self):
        try:
            pn = self.connection.getpeername()
        except gevent.socket.error:
            pn = ('not ready',)
        try:
            cv = '/'.join(self.remote_client_version.split('/')[:2])
        except:
            cv = self.remote_client_version
        return '<Peer%r %s>' % (pn, cv)
        # return '<Peer%r>' % repr(pn)

    def report_error(self, reason):
        try:
            ip_port = self.ip_port
        except:
            ip_port = 'ip_port not available fixme'
        self.peermanager.errors.add(ip_port, reason, self.remote_client_version)

    @property
    def ip_port(self):
        try:
            return self.connection.getpeername()
        except Exception as e:
            log.debug('ip_port failed')
            raise e

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
                    self.report_error('wrong version')

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
        if not data:
            return
        self.safe_to_read.clear()  # make sure we don't accept any data until message is sent
        try:
            self.connection.sendall(data)  # check if gevent chunkes and switches contexts
        except gevent.socket.error as e:
            log.info('write error', errno=e.errno, reason=e.strerror)
            self.report_error('write error')
            if e.errno == 32:  # Broken pipe
                self.report_error('broken pipe')
                self.stop()
            else:
                raise e
        except gevent.socket.timeout:
            log.info('write timeout')
            self.report_error('write timeout')
            self.stop()
        self.safe_to_read.set()

    def _run_egress_message(self):
        while not self.is_stopped:
            self.send(self.mux.message_queue.get())

    def _run_decoded_packets(self):
        # handle decoded packets
        while not self.is_stopped:
            self._handle_packet(self.mux.packet_queue.get())  # get_packet blocks

    def _run_ingress_message(self):
        gevent.spawn(self._run_decoded_packets)
        gevent.spawn(self._run_egress_message)

        while not self.is_stopped:
            self.safe_to_read.wait()
            gevent.socket.wait_read(self.connection.fileno())
            try:
                imsg = self.connection.recv(4096)
            except gevent.socket.error as e:
                log.info('read error', errno=e.errno, reason=e.strerror, peer=self)
                self.report_error('network error %s' % e.strerror)
                if e.errno in(54, 60):  # (Connection reset by peer, timeout)
                    self.stop()
                else:
                    raise e
                    break
            if imsg:
                try:
                    self.mux.add_message(imsg)
                except rlpxcipher.RLPxSessionError as e:
                    log.debug('rlpx session error', peer=self)
                    self.report_error('rlpx session error')
                    self.stop()
            else:
                log.debug('no data on socket', peer=self)
                self.report_error('no data on socket')
                self.stop()

    _run = _run_ingress_message

    def stop(self):
        if not self.is_stopped:
            self.is_stopped = True
            log.debug('stopped', peer=self)
            for p in self.protocols.values():
                p.stop()
            self.peermanager.peers.remove(self)
            self.kill()
