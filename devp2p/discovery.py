# -*- coding: utf-8 -*-
"""
https://github.com/ethereum/go-ethereum/wiki/RLPx-----Node-Discovery-Protocol

"""
import time
import gevent
import gevent.socket
from devp2p import crypto
import rlp
from devp2p import utils
from devp2p import kademlia
from service import BaseService
from gevent.server import DatagramServer
import slogging
import ipaddress

log = slogging.get_logger('discovery')


class DefectiveMessage(Exception):
    pass


class InvalidSignature(DefectiveMessage):
    pass


class PacketExpired(DefectiveMessage):
    pass


class Address(object):

    """
    Extend later, but make sure we deal with objects
    Multiaddress
    https://github.com/haypo/python-ipy
    """

    def __init__(self, ip, port, from_binary=False):
        if from_binary:
            assert len(ip) in (4, 16), repr(ip)
            self._ip = ipaddress.ip_address(ip)
            self.port = utils.idec(port)
        else:
            assert isinstance(port, (int, long))
            self._ip = ipaddress.ip_address(unicode(ip))
            self.port = port

    @property
    def ip(self):
        return str(self._ip)

    def __eq__(self, other):
        return self.to_dict() == other.to_dict()

    def __repr__(self):
        return 'Address(%s:%s)' % (self.ip, self.port)

    def to_dict(self):
        return dict(ip=self.ip, port=self.port)

    def to_binary(self):
        return list((self._ip.packed, utils.ienc(self.port)))

    @classmethod
    def from_binary(self, ip, port):
        return Address(ip, port, from_binary=True)

    def to_endpoint(self):
        """
        struct Endpoint
        {
            unsigned network; // ipv4:4, ipv6:6
            unsigned transport; // tcp:6, udp:17
            unsigned address; // BE encoded 32-bit or 128-bit unsigned (layer3 address)
            unsigned port; // BE encoded 16-bit unsigned (layer4 port)
        }
        """
        transport = 6
        r = [utils.ienc(self._ip.version), utils.ienc(transport)]
        r += [self._ip.packed, utils.ienc(self.port)]
        return r

    @classmethod
    def from_endpoint(self, data):
        assert isinstance(data, list) and len(data) == 4
        version = utils.idec(data[0])
        assert version in (4, 6)
        transport = utils.idec(data[1])
        assert transport == 6
        assert len(data[2]) == {4: 4, 6: 16}[version]
        return Address(data[2], data[3], from_binary=True)

    def to_wire_enc(self):
        # return [str(self.ip), struct.pack('>H', self.port)]
        return [str(self.ip), rlp.sedes.big_endian_int.serialize(self.port)]

    @classmethod
    def from_wire_enc(self, data):
        assert isinstance(data, (list, tuple)) and len(data) == 2
        assert isinstance(data[0], str)
        port = rlp.sedes.big_endian_int.deserialize(data[1])
        return Address(data[0], port)


class Node(kademlia.Node):

    def __init__(self, pubkey, address=None):
        kademlia.Node.__init__(self, pubkey)
        assert address is None or isinstance(address, Address)
        self.address = address
        self.reputation = 0
        self.rlpx_version = 0

    @classmethod
    def from_uri(cls, uri):
        ip, port, pubkey = utils.host_port_pubkey_from_uri(uri)
        return cls(pubkey, Address(ip, int(port)))

    def to_uri(self):
        return utils.host_port_pubkey_to_uri(self.address.ip, self.address.port, self.pubkey)


class DiscoveryProtocolTransport(object):

    def send(self, address, message):
        assert isinstance(address, Address)

    def receive(self, address, message):
        assert isinstance(address, Address)


class KademliaProtocolAdapter(kademlia.KademliaProtocol):
    pass

"""
# Node Discovery Protocol

**Node**: an entity on the network
**Node ID**: 512 bit public key of node

The Node Discovery protocol provides a way to find RLPx nodes
that can be connected to. It uses a Kademlia-like protocol to maintain a
distributed database of the IDs and endpoints of all listening nodes.

Each node keeps a node table as described in the Kademlia paper
[[Maymounkov, Mazières 2002][kad-paper]]. The node table is configured
with a bucket size of 16 (denoted `k` in Kademlia), concurrency of 3
(denoted `α` in Kademlia), and 8 bits per hop (denoted `b` in
Kademlia) for routing. The eviction check interval is 75 milliseconds,
and the idle bucket-refresh interval is
3600 seconds.

In order to maintain a well-formed network, RLPx nodes should try to connect
to an unspecified number of close nodes. To increase resilience against Sybil attacks,
nodes should also connect to randomly chosen, non-close nodes.

Each node runs the UDP-based RPC protocol defined below. The
`FIND_DATA` and `STORE` requests from the Kademlia paper are not part
of the protocol since the Node Discovery Protocol does not provide DHT
functionality.

[kad-paper]: http://www.cs.rice.edu/Conferences/IPTPS02/109.pdf

## Joining the network

When joining the network, fills its node table by perfoming a
recursive Find Node operation with its own ID as the `Target`. The
initial Find Node request is sent to one or more bootstrap nodes.

## RPC Protocol

RLPx nodes that want to accept incoming connections should listen on
the same port number for UDP packets (Node Discovery Protocol) and
TCP connections (RLPx protocol).

All requests time out after are 300ms. Requests are not re-sent.

"""


class DiscoveryProtocol(kademlia.WireInterface):

    """
    ## Packet Data
    All packets contain an `Expiration` date to guard against replay attacks.
    The date should be interpreted as a UNIX timestamp.
    The receiver should discard any packet whose `Expiration` value is in the past.
    """
    version = 3
    expiration = 60  # let messages expire after N secondes
    cmd_id_map = dict(ping=1, pong=2, find_node=3, neighbours=4)
    rev_cmd_id_map = dict((v, k) for k, v in cmd_id_map.items())

    encoders = dict(cmd_id=chr,
                    expiration=rlp.sedes.big_endian_int.serialize)

    decoders = dict(cmd_id=ord,
                    expiration=rlp.sedes.big_endian_int.deserialize)

    def __init__(self, app, transport):
        self.app = app
        self.transport = transport
        self.privkey = app.config['node']['privkey_hex'].decode('hex')
        self.pubkey = crypto.privtopub(self.privkey)
        self.nodes = dict()   # nodeid->Node,  fixme should be loaded
        self.this_node = Node(self.pubkey, self.transport.address)
        self.kademlia = KademliaProtocolAdapter(self.this_node, wire=self)

    def get_node(self, nodeid, address=None):
        "return node or create new, update address if supplied"
        assert isinstance(nodeid, str)
        assert len(nodeid) == 512 / 8
        assert address or (nodeid in self.nodes)
        if nodeid not in self.nodes:
            self.nodes[nodeid] = Node(nodeid, address)
        node = self.nodes[nodeid]
        if address:
            assert isinstance(address, Address)
            node.address = address
        assert node.address
        return node

    def sign(self, msg):
        """
        signature: sign(privkey, sha3(packet-type || packet-data))
        signature: sign(privkey, sha3(pubkey || packet-type || packet-data))
            // implementation w/MCD
        """
        msg = crypto.sha3(msg)
        return crypto.sign(msg, self.privkey)

    def pack(self, cmd_id, payload):
        """
        UDP packets are structured as follows:

        hash || signature || packet-type || packet-data
        packet-type: single byte < 2**7 // valid values are [1,4]
        packet-data: RLP encoded list. Packet properties are serialized in the order in
                    which they're defined. See packet-data below.

        Offset  |
        0       | MDC       | Ensures integrity of packet,
        65      | signature | Ensures authenticity of sender, `SIGN(sender-privkey, MDC)`
        97      | type      | Single byte in range [1, 4] that determines the structure of Data
        98      | data      | RLP encoded, see section Packet Data

        The packets are signed and authenticated. The sender's Node ID is determined by
        recovering the public key from the signature.

            sender-pubkey = ECRECOVER(Signature)

        The integrity of the packet can then be verified by computing the
        expected MDC of the packet as:

            MDC = SHA3(sender-pubkey || type || data)

        As an optimization, implementations may look up the public key by
        the UDP sending address and compute MDC before recovering the sender ID.
        If the MDC values do not match, the packet can be dropped.
        """
        assert cmd_id in self.cmd_id_map.values()
        assert isinstance(payload, list)

        cmd_id = self.encoders['cmd_id'](cmd_id)
        expiration = self.encoders['expiration'](int(time.time() + self.expiration))
        encoded_data = rlp.encode(payload + [expiration])
        # print rlp.decode(encoded_data)
        signed_data = crypto.sha3(cmd_id + encoded_data)
        signature = crypto.sign(signed_data, self.privkey)
        # assert crypto.verify(self.pubkey, signature, signed_data)
        # assert self.pubkey == crypto.ecdsa_recover(signed_data, signature)
        # assert crypto.verify(self.pubkey, signature, signed_data)
        assert len(signature) == 65
        mdc = crypto.sha3(signature + cmd_id + encoded_data)
        assert len(mdc) == 32
        # print dict(mdc=mdc.encode('hex'), signature=signature.encode('hex'),
        #            data=str(cmd_id + encoded_data).encode('hex'))
        return mdc + signature + cmd_id + encoded_data

    def unpack(self, message):
        """
        macSize  = 256 / 8 = 32
        sigSize  = 520 / 8 = 65
        headSize = macSize + sigSize = 97
        hash, sig, sigdata := buf[:macSize], buf[macSize:headSize], buf[headSize:]
        shouldhash := crypto.Sha3(buf[macSize:])
        """
        mdc = message[:32]
        assert mdc == crypto.sha3(message[32:])
        signature = message[32:97]
        assert len(signature) == 65
        signed_data = crypto.sha3(message[97:])
        remote_pubkey = crypto.ecdsa_recover(signed_data, signature)
        assert len(remote_pubkey) == 512 / 8
        if not crypto.verify(remote_pubkey, signature, signed_data):
            raise InvalidSignature()
        cmd_id = self.decoders['cmd_id'](message[97])
        assert cmd_id in self.cmd_id_map.values()
        payload = rlp.decode(message[98:])
        assert isinstance(payload, list)
        expiration = self.decoders['expiration'](payload.pop())
        if time.time() > expiration:
            raise PacketExpired()
        return remote_pubkey, cmd_id, payload, mdc

    def receive(self, address, message):
        log.debug('<<< message', address=address)
        assert isinstance(address, Address)
        try:
            remote_pubkey, cmd_id, payload, mdc = self.unpack(message)
        except PacketExpired:
            return
        cmd = getattr(self, 'recv_' + self.rev_cmd_id_map[cmd_id])
        nodeid = remote_pubkey
        if nodeid not in self.nodes:  # set intermediary address
            self.get_node(nodeid, address)
        cmd(nodeid, payload, mdc)

    def send(self, node, message):
        assert node.address
        log.debug('>>> message', address=node.address)
        self.transport.send(node.address, message)

    def send_ping(self, node):
        """
        ### Ping (type 0x01)

        Ping packets can be sent and received at any time. The receiver should
        reply with a Pong packet and update the IP/Port of the sender in its
        node table.

        PingNode packet-type: 0x01

        ping struct {
            Version    uint   // must match Version
            IP         string // our IP
            Port       uint16 // our port
            Expiration uint64
        }
        """
        assert node != self.this_node
        log.debug('>>> ping', remoteid=node)
        version = rlp.sedes.big_endian_int.serialize(self.version)
        ip = self.app.config['discovery']['listen_host']    # FIXME: P2P or discovery?
        port = self.app.config['discovery']['listen_port']
        payload = [version] + Address(ip, port).to_wire_enc()
        assert len(payload) == 3
        message = self.pack(self.cmd_id_map['ping'], payload)
        self.send(node, message)
        return message[:32]  # return the MDC to identify pongs

    def recv_ping(self, nodeid, payload, mdc):
        """
        update ip, port in node table
        Addresses can only be learned by ping messages
        """
        assert len(payload) == 3, (len(payload), repr(payload))
        node = self.get_node(nodeid)
        log.debug('<<< ping', node=node)
        version = rlp.sedes.big_endian_int.deserialize(payload[0])
        assert version == self.version
        address = Address.from_wire_enc(payload[1:])  # FIXME: how to use this?
        self.kademlia.recv_ping(node, echo=mdc)

    def send_pong(self, node, token):
        """
        ### Pong (type 0x02)

        Pong is the reply to a Ping packet.

        Pong packet-type: 0x02
        struct Pong  // response to PingNode
        {
            h256 echo; // hash of PingNode payload
            unsigned expiration;
        };
        """
        log.debug('>>> pong', remoteid=node)
        message = self.pack(self.cmd_id_map['pong'], [token])
        self.send(node, message)

    def recv_pong(self, nodeid,  payload, mdc):
        echoed = payload[0]
        if nodeid in self.nodes:
            node = self.get_node(nodeid)
            self.kademlia.recv_pong(node, echoed)
        else:
            log.debug('<<< unexpected pong from unkown node')

    def send_find_node(self, node, target_node_id):
        """
        ### Find Node (type 0x03)

        Find Node packets are sent to locate nodes close to a given target ID.
        The receiver should reply with a Neighbors packet containing the `k`
        nodes closest to target that it knows about.

        FindNode packet-type: 0x03
        struct FindNode
        {
            NodeId target;
            unsigned expiration;
        };
        """
        assert isinstance(target_node_id, long)
        target_node_id = utils.int_to_big_endian(target_node_id)
        assert len(target_node_id) == kademlia.k_id_size / 8
        log.debug('>>> find_node', remoteid=node)
        message = self.pack(self.cmd_id_map['find_node'], [target_node_id])
        self.send(node, message)

    def recv_find_node(self, nodeid, payload, mdc):
        node = self.get_node(nodeid)
        log.debug('<<< find_node', remoteid=node)
        assert len(payload[0]) == kademlia.k_id_size / 8
        target = utils.big_endian_to_int(payload[0])
        self.kademlia.recv_find_node(node, target)

    def send_neighbours(self, node, neighbours):
        """
        ### Neighbors (type 0x04)

        Neighbors is the reply to Find Node. It contains up to `k` nodes that
        the sender knows which are closest to the requested `Target`.

        Neighbors packet-type: 0x04
        struct Neighbors  // reponse to FindNode
        {
            struct Node
            {
                Endpoint endpoint;
                NodeId node;
            };

            std::list<Node> nodes;
            unsigned expiration;
        };
        """
        assert isinstance(neighbours, list)
        assert not neighbours or isinstance(neighbours[0], Node)
        nodes = []
        for n in neighbours:
            l = n.address.to_wire_enc() + [n.pubkey]
            nodes.append(l)
        log.debug('>>> neighbours', remoteid=node, count=len(nodes))
        message = self.pack(self.cmd_id_map['neighbours'], [nodes])
        self.send(node, message)

    def recv_neighbours(self, nodeid, payload, mdc):
        node = self.get_node(nodeid)
        assert len(payload) == 1
        neighbours_lst = payload[0]
        assert isinstance(neighbours_lst, list)
        log.debug('<<< neigbours', remoteid=node, count=len(neighbours_lst))
        neighbours = []
        neighbours_set = set(tuple(x) for x in neighbours_lst)
        if len(neighbours_set) < len(neighbours_lst):
            log.warn('received duplicates')

        for (ip, port, nodeid) in neighbours_set:
            address = Address.from_wire_enc((ip, port))
            node = self.get_node(nodeid, address)
            assert node.address
            neighbours.append(node)
        self.kademlia.recv_neighbours(node, neighbours)


class NodeDiscovery(BaseService, DiscoveryProtocolTransport):

    """
    Persist the list of known nodes with their reputation
    """

    cpp_bootstrap = 'enode://24f904a876975ab5c7acbedc8ec26e6f7559b527c073c6e822049fee4df78f2e9c74840587355a068f2cdb36942679f7a377a6d8c5713ccf40b1d4b99046bba0@5.1.83.226:30303'
    bootstrap_nodes = [cpp_bootstrap]

    name = 'discovery'
    server = None  # will be set to DatagramServer
    default_config = dict(discovery=dict(listen_port=30303,
                                         listen_host='0.0.0.0',
                                         bootstrap_nodes=bootstrap_nodes
                                         ),
                          node=dict(privkey_hex=''))

    def __init__(self, app):
        BaseService.__init__(self, app)
        log.info('NodeDiscovery init')
        # man setsockopt
        self.protocol = DiscoveryProtocol(app=self.app, transport=self)

    @property
    def address(self):
        ip = self.app.config['discovery']['listen_host']
        port = self.app.config['discovery']['listen_port']
        return Address(ip, port)

    # def _send(self, address, message):
    #     assert isinstance(address, Address)
    #     sock = gevent.socket.socket(type=gevent.socket.SOCK_DGRAM)
    # sock.bind(('0.0.0.0', self.address.port))  # send from our recv port
    #     sock.connect((address.ip, address.port))
    #     log.debug('sending', size=len(message), to=address)
    #     sock.send(message)

    def send(self, address, message):
        assert isinstance(address, Address)
        log.debug('sending', size=len(message), to=address)
        self.server.sendto(message, (address.ip, address.port))

    def receive(self, address, message):
        assert isinstance(address, Address)
        self.protocol.receive(address, message)

    def _handle_packet(self, message, ip_port):
        log.debug('handling packet', address=ip_port, size=len(message))
        assert len(ip_port) == 2
        address = Address(ip=ip_port[0], port=ip_port[1])
        self.receive(address, message)

    def start(self):
        log.info('starting discovery')
        # start a listening server
        ip = self.app.config['discovery']['listen_host']
        port = self.app.config['discovery']['listen_port']
        log.info('starting listener', port=port, host=ip)
        self.server = DatagramServer((ip, port), handle=self._handle_packet)
        self.server.start()
        super(NodeDiscovery, self).start()

        # bootstap
        nodes = [Node.from_uri(x) for x in self.app.config['discovery']['bootstrap_nodes']]
        if nodes:
            self.protocol.kademlia.bootstrap(nodes)

    def _run(self):
        log.debug('_run called')
        evt = gevent.event.Event()
        evt.wait()

    def stop(self):
        log.info('stopping discovery')
        self.server.stop()


if __name__ == '__main__':
    pass
