import gevent
from collections import OrderedDict
from protocol import BaseProtocol
from protocol import decode_packet_header, header_length
import slogging

log = slogging.get_logger('peer')


class QueueWorker(gevent.Greenlet):
    # FIXME we need to queue send messages
    def __init__(self, queue):
        self.queue = queue
        super(QueueWorker, self).__init__()

    def _run(self):
        self.running = True
        while self.running:
            msg = self.queue.get()    # block call
            print('queue:', msg)


class Peer(gevent.Greenlet):
    """
    After creation:
        register peer protocol
        send hello & encryption
        receive hello & derive session key
        register in common protocols

        receive data
            decrypt, check auth
            decode packet id
            lookup handling protocol
            pass packet to protocol

        send packet
            encrypt
    """

    def __init__(self, peermanager, connection):
        super(Peer, self).__init__()
        log.debug('peer init', peer=self)
        self.peermanager = peermanager
        self.connection = connection
        self.protocols = OrderedDict()
        self._buffer = ''
        # learned and set on handshake
        self.nodeid = None
        self.client_version = None
        self.listen_port = None

    def __repr__(self):
        return '<Peer(%r) thread=%r>' % (self.connection.getpeername(), id(gevent.getcurrent()))

    @property
    def ip_port(self):
        return self.connection.getpeername()

    # protocols
    def register_protocol(self, protocol):
        """
        registeres protocol with peer, which will be accessible as
        peer.<protocol.name> (e.g. peer.p2p or peer.eth)
        """
        assert isinstance(protocol, BaseProtocol)
        assert protocol.name not in self.protocols
        log.debug('registering protocol', protocol=protocol.name, peer=self)
        self.protocols[protocol.name] = protocol
        setattr(self.protocols, protocol.name, protocol)

    def deregister_protocol(self, protocol):
        assert isinstance(protocol, BaseProtocol)
        del self.protocols[protocol.name]
        delattr(self.protocols, protocol.name)

    def protocol_by_cmd_id(self, cmd_id):
        max_id = 0
        for p in self.protocols.values():
            max_id += len(p.cmd_map)
            if cmd_id < max_id:
                return p
        raise Exception('no protocol for id %s' % cmd_id)

    def has_protocol(self, name):
        assert isinstance(name, str)
        return hasattr(self.protocol, name)

    # receiving p2p mesages

    def _handle_packet(self, cmd_id, payload):
        log.debug('handling packet', cmd_id=cmd_id, peer=self)
        protocol = self.protocol_by_cmd_id(cmd_id)
        protocol.handle_message(cmd_id, payload)

    def _data_received(self, data):
        # use memoryview(string)[offset:] instead copying data
        self._buffer += data
        while len(self._buffer):
            # read packets from buffer
            payload_len, cmd_id = decode_packet_header(self._buffer)
            # check if we have a complete message
            if len(self._buffer) >= payload_len + header_length:
                payload = self._buffer[header_length:payload_len + header_length]
                self._buffer = self._buffer[payload_len + header_length:]
                self._handle_packet(cmd_id, payload)
            else:
                break

    def send(self, data):
        log.debug('send', size=len(data))
        self.connection.sendall(data)
        log.debug('send sent', size=len(data))

    def _run(self):
        while True:
            log.debug('loop_socket.wait', peer=self)
            data = self.connection.recv(4096)
            log.debug('loop_socket.received', size=len(data), peer=self)
            if not data:
                log.debug('loop_socket.not_data', peer=self)
                self.stop()
                break
            self._data_received(data)

    def stop(self):
        log.debug('stopped', thread=gevent.getcurrent())
        for p in self.protocols.values():
            p.stop()
        self.peermanager.peers.remove(self)
        self.kill()
