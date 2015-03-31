# https://github.com/ethereum/go-ethereum/wiki/Blockpool
import gevent
import rlp
from rlp import sedes
from multiplexer import Packet
from service import WiredService
import slogging
log = slogging.get_logger('protocol.p2p')


class BaseProtocol(gevent.Greenlet):

    """
    A protocol mediates between the network and the service.
    It implements a collection of commands.

    For each command X the following methods are created at initialization:
    -    packet = protocol.create_X(*args, **kargs)
    -   protocol.send_X(*args, **kargs) is a shortcut for:
            protocol.send_packet(protocol.create_X(*args, **kargs))
    - protocol._receive_X(data)


    on protocol.receive_packet, the packet is deserialized according to the command.structure
        and the command.receive method called with a dict containing the received data

    the default implementation of command.receive calls callbacks
    which can be registered in a list which is available as:
    protocol.receive_X_callbacks
    """
    protocol_id = 0
    name = ''
    version = 0
    max_cmd_id = 0  # reserved cmd space

    class command(object):

        """
        - set cmd_id
        - define structure for rlp de/endcoding by sedes
        optionally implement
        - create
        - receive

        default receive implementation, call callbacks with (proto_instance, data_dict)
        """
        cmd_id = 0
        structure = []  # [(arg_name, rlp.sedes.type), ...]

        def create(self, proto, *args, **kargs):
            "optionally implement create"
            assert isinstance(proto, BaseProtocol)
            return args or kargs

        def receive(self, proto, data):
            "optionally implement receive"
            for cb in self.receive_callbacks:
                cb(proto, **data)

        # no need to redefine the following ##################################

        def __init__(self):
            self.receive_callbacks = []

        @classmethod
        def encode_payload(cls, data):
            if isinstance(data, dict):  # convert dict to ordered list
                data = [data[x[0]] for x in cls.structure]
            assert len(data) == len(cls.structure)
            return rlp.encode(data, sedes=sedes.List([x[1] for x in cls.structure]))

        @classmethod
        def decode_payload(cls, rlp_data):
            try:
                data = rlp.decode(str(rlp_data), sedes=sedes.List([x[1] for x in cls.structure]))
                assert len(data) == len(cls.structure)
            except (AssertionError, rlp.RLPException, TypeError) as e:
                # print repr(rlp.decode(rlp_data))
                raise e
            # convert to dict
            return dict((cls.structure[i][0], v) for i, v in enumerate(data))

        # end command base ###################################################

    def __init__(self, peer, service):
        "hint: implement peer_started notifcation of associated protocol here"
        assert isinstance(service, WiredService)
        assert callable(peer.send_packet)
        self.peer = peer
        self.service = service
        self._setup()
        super(BaseProtocol, self).__init__()

    def _setup(self):

        # collect commands
        klasses = [k for k in self.__class__.__dict__.values()
                   if isinstance(k, type) and issubclass(k, self.command) and k != self.command]
        assert len(set(k.cmd_id for k in klasses)) == len(klasses)

        def create_methods(klass):
            instance = klass()

            def receive(packet):
                "decode rlp, create dict, call receive"
                assert isinstance(packet, Packet)
                instance.receive(proto=self, data=klass.decode_payload(packet.payload))

            def create(*args, **kargs):
                "get data, rlp encode, return packet"
                res = instance.create(self, *args, **kargs)
                payload = klass.encode_payload(res)
                return Packet(self.protocol_id, klass.cmd_id, payload=payload)

            def send(*args, **kargs):
                "create and send packet"
                packet = create(*args, **kargs)
                self.send_packet(packet)

            return receive, create, send, instance.receive_callbacks

        for klass in klasses:
            receive, create, send, receive_callbacks = create_methods(klass)
            setattr(self, '_receive_' + klass.__name__, receive)
            setattr(self, 'receive_' + klass.__name__ + '_callbacks', receive_callbacks)
            setattr(self, 'create_' + klass.__name__, create)
            setattr(self, 'send_' + klass.__name__, send)

        self.cmd_by_id = dict((klass.cmd_id, klass.__name__) for klass in klasses)

    def receive_packet(self, packet):
        cmd_name = self.cmd_by_id[packet.cmd_id]
        cmd = getattr(self, '_receive_' + cmd_name)
        cmd(packet)

    def send_packet(self, packet):
        self.peer.send_packet(packet)

    def stop(self):
        "hint: implement peer stopped notifcation of associated protocol here"
        pass


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
        BaseProtocol.__init__(self, peer, service)

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
