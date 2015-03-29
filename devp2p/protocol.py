# https://github.com/ethereum/go-ethereum/wiki/Blockpool
import rlp
from rlp import sedes
from multiplexer import Packet
import slogging
log = slogging.get_logger('protocol.p2p')


class BaseProtocol(object):

    """
    A protocol is collection of commands.

    For each command X the following methods are created at initialization:
    -    packet = protocol.create_X(*args, **kargs)
    -   protocol.send_X(*args, **kargs) is a shortcut for:
            protocol._send_packet(protocol.create_X(*args, **kargs))
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
                cb(proto, data)

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
            data = rlp.decode(rlp_data, sedes=sedes.List([x[1] for x in cls.structure]))
            # convert to dict
            return dict((cls.structure[i][0], v) for i, v in enumerate(data))

        # end command base ###################################################

    _send_packet = lambda packet: None  # override in implementation

    def __init__(self):
        self._setup()

    def _setup(self):
        assert callable(self._send_packet)

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
                print 'create called', klass
                res = instance.create(self, *args, **kargs)
                payload = klass.encode_payload(res)
                return Packet(self.protocol_id, klass.cmd_id, payload=payload)

            def send(*args, **kargs):
                "create and send packet"
                packet = create(*args, **kargs)
                self._send_packet(packet)

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


class P2PProtocol(BaseProtocol):
    protocol_id = 0
    name = 'p2p'
    version = 2

    def __init__(self, peer):
        # required by BaseProtocol
        self._send_packet = peer.send_packet
        # required by P2PProtocol
        self.config = peer.config
        assert peer.capabilities
        assert callable(peer.stop)
        assert callable(peer.receive_hello)
        self.peer = peer
        BaseProtocol.__init__(self)

    class ping(BaseProtocol.command):
        cmd_id = 1

        def receive(self, proto, data):
            proto.send_pong()

    class pong(BaseProtocol.command):
        cmd_id = 2

    class hello(BaseProtocol.command):
        cmd_id = 0
        max_protocols = 64
        _sedes_capabilites_tuple = sedes.List([sedes.binary, sedes.big_endian_int])
        structure = [
            ('version', sedes.big_endian_int),
            ('client_version', sedes.big_endian_int),
            ('capabilities', sedes.List([_sedes_capabilites_tuple] * max_protocols, strict=False)),
            ('listen_port', sedes.big_endian_int),
            ('nodeid', sedes.binary)
        ]

        def create(self, proto):
            return dict(version=proto.version,
                        client_version=proto.config['version'],
                        capabilities=proto.peer.capabilities,
                        listen_port=proto.config['p2p']['listen_port'],
                        nodeid=proto.config['p2p']['nodeid'],
                        )

        def receive(self, proto, data):
            log.debug('receive_hello', peer=proto.peer, version=data['version'])
            if data['nodeid'] == proto.config['p2p']['nodeid']:
                log.debug('connected myself')
                return proto.send_disconnect(
                    reason=proto.disconnect.reason.incompatible_network_protocols)
            if data['version'] != proto.version:
                log.debug('incompatible network protocols', peer=proto.peer,
                          expected=proto.version, received=data['version'])
                return proto.send_disconnect(
                    reason=proto.disconnect.reason.incompatible_network_protocols)

            proto.peer.receive_hello(**data)

    class disconnect(BaseProtocol.command):
        cmd_id = 3
        structure = [('reason', sedes.big_endian_int)]

        class reason(object):
            disconnect_requested = 0
            tcp_sub_system_error = 1
            bad_protocol = 2
            useless_peer = 3
            too_many_peers = 4
            already_connected = 5
            wrong_genesis_block = 6
            incompatible_network_protocols = 7
            client_quitting = 8

        def reason_name(self, id):
            return [k for k, v in self.reason.__dict__.items() if v == id][0]

        def create(self, proto, reason=reason.client_quitting):
            assert self.reason_name(reason)
            log.debug('send_disconnect', peer=proto.peer, reason=self.reason_name(reason))
            proto.peer.stop()
            return dict(reason=reason)

        def receive(self, proto, data):
            log.debug('receive_disconnect', peer=proto.peer,
                      reason=self.reason_name(data['reason']))
            proto.peer.stop()
